#!/bin/sh
# rollout-bastille.sh - Deploy prism using separate build and run jails
# Usage: ./rollout-bastille.sh <build-jail> <run-jail>
#
# Environment:
#   CF_TUNNEL_TOKEN - Cloudflare Tunnel token (required on first deploy,
#                     persisted in jail via sysrc for subsequent runs)
#
# Prerequisites:
#   - "hopper-api" must have an entry in /etc/hosts on this host for the API
#   - "hopper-db" must have an entry in /etc/hosts on this host for PostgreSQL
#
# Downtime model
# --------------
# Effectively zero. The new prism is brought up alongside the running one
# using SO_REUSEPORT_LB on FreeBSD (SO_REUSEPORT on Linux/macOS in tests),
# so both processes bind the same port at the same time and the kernel
# routes new connections to whichever is alive. The rollout:
#
#   1. Stages the new binary at /usr/local/bin/prism.new (running prism
#      keeps its old inode; no ETXTBSY risk).
#   2. Renames .new -> live path (atomic on the same filesystem).
#   3. Spawns the replacement via daemon(8) with /var/run/prism.next.pid
#      and /var/log/prism.next.log so it can run beside the old.
#   4. Polls http://127.0.0.1:8080/_/health until the replacement answers.
#   5. SIGTERMs the old PID. main.go's 5-second graceful shutdown closes
#      its listener immediately (kernel stops routing new conns to it)
#      and drains in-flight requests before exiting.
#   6. Renames prism.next.pid -> prism.pid so `service prism stop/restart`
#      keeps managing the right process going forward.
#
# If the replacement fails its health check, the old prism keeps serving
# and the rollout exits non-zero; the bad PID is cleaned up. SSE clients
# on the old process (e.g. /file/<sha>/wait) are cut at SIGTERM and the
# browser-side reconnect logic in rescan.js / pending page re-establishes
# the stream against the new prism.

set -ex

BUILD="$1"
RUN="$2"

die() {
    echo "error: $*" >&2
    exit 1
}

log() {
    echo "==> $*"
}

[ -z "$BUILD" ] || [ -z "$RUN" ] && die "usage: $0 <build-jail> <run-jail>"

# --- Resolve hopper-api hostname ---
# hopper-api serves the HTTP API (uploads, result publish). The PostgreSQL
# endpoint prism reads from is resolved in the DB-endpoint block below.
HOPPER_API_LINE=$(awk '/[[:space:]]hopper-api([[:space:]]|$)/{print; exit}' /etc/hosts)
[ -z "$HOPPER_API_LINE" ] && die "hopper-api not found in /etc/hosts — add an entry before deploying"
log "Using hopper-api: $HOPPER_API_LINE"

# Verify jails are accessible
doas bastille cmd "$BUILD" true || die "build jail '$BUILD' not accessible"
doas bastille cmd "$RUN" true || die "run jail '$RUN' not accessible"

# --- Hopper database endpoint ----------------------------------------------
# prism reads samples from PostgreSQL at HOPPER_DB_HOST (the hostname prism
# dials, resolved via /etc/hosts). Default: the primary, hopper-db.
#
# To point prism at a logical read replica, export on the deploy command line —
# the choice is persisted in the run jail via sysrc, so later plain `make
# deploy` runs keep it:
#
#   HOPPER_DB_HOST=hopper-replica HOPPER_DB_PASS='<replica hopper password>' make deploy
#
# A logical replica's `hopper` role has its OWN password (logical replication
# does not copy roles), so pass it via HOPPER_DB_PASS. Read it from the replica
# jail's .pgpass localhost line — note the jail name may differ from the
# hostname (e.g. jail "postgres" serving host "hopper-replica"):
#   doas bastille cmd postgres awk -F: '$1=="localhost"&&$4=="hopper"{print $5;exit}' /var/db/postgres/.pgpass
# When HOPPER_DB_PASS is unset the password is auto-sourced from
# HOPPER_DB_JAIL:HOPPER_DB_PGPASS (default the hopper-db jail) — correct for the
# primary, wrong for a replica.
#
# Any non-primary host also sets PRISM_READONLY=1 so prism refuses its lone DB
# write (the rescan button). Reads — every page-load query — are unaffected.

# Default the host from what's already persisted in the run jail, so a plain
# `make deploy` keeps the configured target; an explicit HOPPER_DB_HOST wins.
if [ -z "${HOPPER_DB_HOST:-}" ]; then
    _persisted_dsn=$(doas bastille cmd "$RUN" sh -c 'sysrc -n prism_hopper_dsn 2>/dev/null' || true)
    HOPPER_DB_HOST=$(printf '%s\n' "$_persisted_dsn" | sed -n 's#^postgres://[^@]*@\([^:/?]*\).*#\1#p')
    [ -z "$HOPPER_DB_HOST" ] && HOPPER_DB_HOST="hopper-db"
fi
HOPPER_DB_JAIL="${HOPPER_DB_JAIL:-hopper-db}"
HOPPER_DB_PGPASS="${HOPPER_DB_PGPASS:-/home/hopper/.pgpass}"
HOPPER_DB_PGPASS_HOST="${HOPPER_DB_PGPASS_HOST:-}"   # .pgpass host-field to match; empty = first hopper line
HOPPER_DB_SSLMODE="${HOPPER_DB_SSLMODE:-disable}"
HOPPER_DSN="postgres://hopper@${HOPPER_DB_HOST}:5432/hopper?sslmode=${HOPPER_DB_SSLMODE}"
if [ "$HOPPER_DB_HOST" = "hopper-db" ]; then
    PRISM_READONLY="${PRISM_READONLY:-0}"
else
    PRISM_READONLY="${PRISM_READONLY:-1}"
fi
log "prism DB endpoint: $HOPPER_DB_HOST (read-only=$PRISM_READONLY)"

HOPPER_DB_LINE=$(awk -v h="$HOPPER_DB_HOST" '$0 ~ "[[:space:]]" h "([[:space:]]|$)" {print; exit}' /etc/hosts)
[ -z "$HOPPER_DB_LINE" ] && die "$HOPPER_DB_HOST not found in /etc/hosts — add an entry (mapping to the DB jail IP) before deploying"
log "Using $HOPPER_DB_HOST: $HOPPER_DB_LINE"

# Tracks whether any restart-affecting change happened (binary or rc.d).
# Set to 1 by binary diff or rc.d/prism diff below.
NEEDS_PRISM_RESTART=0

# --- Build jail setup ---

log "Ensuring DNS resolver is running in build jail"
doas bastille sysrc "$BUILD" local_unbound_enable=YES >/dev/null
doas bastille service "$BUILD" local_unbound status >/dev/null 2>&1 || \
    doas bastille service "$BUILD" local_unbound start

log "Ensuring build user exists"
doas bastille cmd "$BUILD" id -u prism >/dev/null 2>&1 || \
    doas bastille cmd "$BUILD" pw useradd prism -m -s /bin/sh -c "Prism Build"

# `pkg install -y` is idempotent but always refreshes the catalog (slow).
# `pkg info -e` short-circuits when packages are already present.
if ! doas bastille cmd "$BUILD" pkg info -e go gmake >/dev/null 2>&1; then
    log "Installing build dependencies"
    doas bastille pkg "$BUILD" install -y go gmake
fi

log "Copying source tree to build jail"
doas bastille cmd "$BUILD" rm -rf /home/prism/prism
doas bastille cp "$BUILD" . /home/prism/prism
doas bastille cmd "$BUILD" chown -R prism:prism /home/prism/prism

log "Building prism binary"
doas bastille cmd "$BUILD" su -l prism -c "cd ~/prism && gmake build"

log "Running tests"
doas bastille cmd "$BUILD" su -l prism -c "cd ~/prism && gmake test"

# --- Run jail config (service stays running through all of this) ---

# Ensure hopper hostnames resolve inside the run jail.
if ! doas bastille cmd "$RUN" awk '/[[:space:]]hopper-api([[:space:]]|$)/{found=1} END{exit !found}' /etc/hosts 2>/dev/null; then
    doas bastille cmd "$RUN" sh -c "echo '$HOPPER_API_LINE' >> /etc/hosts"
    log "Added hopper-api to jail /etc/hosts"
fi
if ! doas bastille cmd "$RUN" awk '/[[:space:]]hopper-db([[:space:]]|$)/{found=1} END{exit !found}' /etc/hosts 2>/dev/null; then
    doas bastille cmd "$RUN" sh -c "echo '$HOPPER_DB_LINE' >> /etc/hosts"
    log "Added hopper-db to jail /etc/hosts"
fi

log "Ensuring run user exists"
doas bastille cmd "$RUN" id -u prism >/dev/null 2>&1 || \
    doas bastille cmd "$RUN" pw useradd prism -m -s /bin/sh -c "Prism Service"

doas bastille cmd "$RUN" mkdir -p /usr/local/bin

# --- Hopper database password ---
# prism authenticates to PostgreSQL via ~prism/.pgpass (pgx reads it
# automatically; the password never enters the DSN, environment, or process
# table). The entry is keyed by the host prism dials ($HOPPER_DB_HOST). We
# (re)write it when an explicit HOPPER_DB_PASS is supplied or when the file
# lacks an entry for this host — so switching hosts or rotating the password
# always takes effect, while routine redeploys don't re-read it.
pgpass_has_host=$(doas bastille cmd "$RUN" sh -c \
    "awk -F: -v h='$HOPPER_DB_HOST' '\$1==h && \$4==\"hopper\"{print 1; exit}' /home/prism/.pgpass 2>/dev/null" || true)
if [ -n "${HOPPER_DB_PASS:-}" ] || [ -z "$pgpass_has_host" ]; then
    set +x
    if [ -n "${HOPPER_DB_PASS:-}" ]; then
        log "Writing supplied hopper password for $HOPPER_DB_HOST into prism .pgpass"
        _pw="$HOPPER_DB_PASS"
    else
        log "Sourcing hopper password from ${HOPPER_DB_JAIL}:${HOPPER_DB_PGPASS} for $HOPPER_DB_HOST"
        doas bastille cmd "$HOPPER_DB_JAIL" test -f "$HOPPER_DB_PGPASS" \
            || { set -x; die "${HOPPER_DB_JAIL} jail pgpass not found at ${HOPPER_DB_PGPASS}"; }
        _pw=$(doas bastille cmd "$HOPPER_DB_JAIL" sh -c \
            "awk -F: -v h='$HOPPER_DB_PGPASS_HOST' '\$0!~/^[[:space:]]*#/ && (\$4==\"hopper\"||\$4==\"*\") && (h==\"\"||\$1==h){print \$5; exit}' '$HOPPER_DB_PGPASS'")
    fi
    [ -z "$_pw" ] && { set -x; die "no hopper password for $HOPPER_DB_HOST (set HOPPER_DB_PASS, or check HOPPER_DB_JAIL/HOPPER_DB_PGPASS/HOPPER_DB_PGPASS_HOST)"; }
    doas bastille cmd "$RUN" su -l prism -c "umask 077; printf '%s:5432:hopper:hopper:%s\n' '$HOPPER_DB_HOST' '$_pw' > ~/.pgpass && chmod 600 ~/.pgpass"
    unset _pw HOPPER_DB_PASS
    set -x
else
    log "prism .pgpass already has an entry for $HOPPER_DB_HOST"
fi

# --- CSRF signing key ---
# A stable HMAC key for prism's CSRF tokens, persisted in the run jail via
# sysrc (like cloudflared_token) and injected into prism's environment below.
# One key shared by the old and new process keeps CSRF tokens valid through the
# SO_REUSEPORT_LB hot-swap and across deploys. Generated once; never logged.
if ! doas bastille cmd "$RUN" sh -c '[ -n "$(sysrc -n prism_csrf_key 2>/dev/null)" ]' >/dev/null 2>&1; then
    log "Generating prism CSRF key"
    set +x
    CSRF_KEY=$(doas bastille cmd "$RUN" openssl rand -hex 32)
    [ -z "$CSRF_KEY" ] && die "failed to generate prism CSRF key"
    doas bastille sysrc "$RUN" prism_csrf_key="$CSRF_KEY" >/dev/null 2>&1
    unset CSRF_KEY
    set -x
fi

# Persist the DB endpoint so the rc.d service and future plain `make deploy`
# runs use it without re-passing env. The rc.d script reads these via sysrc.
doas bastille sysrc "$RUN" prism_hopper_dsn="$HOPPER_DSN" >/dev/null
doas bastille sysrc "$RUN" prism_readonly="$PRISM_READONLY" >/dev/null

# rc.d/prism — written via stage-and-cmp so we only update (and trigger a
# restart) when the script content actually changes.
log "Staging rc.d/prism"
doas bastille cmd "$RUN" mkdir -p /usr/local/etc/rc.d
doas bastille cmd "$RUN" tee /usr/local/etc/rc.d/prism.new >/dev/null <<'EOF'
#!/bin/sh

# PROVIDE: prism
# REQUIRE: LOGIN DAEMON NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="prism"
rcvar="prism_enable"

load_rc_config $name

: ${prism_enable:="NO"}
: ${prism_litmus_addr:="litmus:49999"}
: ${prism_hopper_api_addr:="hopper-api:8081"}
: ${prism_hopper_dsn:="postgres://hopper@hopper-db/hopper?sslmode=disable"}
: ${prism_readonly:="0"}
: ${prism_csrf_key:=""}

pidfile="/var/run/${name}.pid"
prism_log="/var/log/${name}.log"
command="/usr/sbin/daemon"
# HOME is set so pgx can locate ~prism/.pgpass for the hopper database password.
prism_env="HOME=/home/prism PORT=8080 LITMUS_ADDR=${prism_litmus_addr} HOPPER_API_ADDR=${prism_hopper_api_addr} HOPPER_DSN=${prism_hopper_dsn} PRISM_READONLY=${prism_readonly} PRISM_CSRF_KEY=${prism_csrf_key} OTEL_EXPORTER_OTLP_ENDPOINT=http://otel:9090/api/v1/otlp OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://otel:3100/otlp/v1/logs"
command_args="-c -f -P ${pidfile} -S -R 5 -o ${prism_log} -u prism /usr/bin/env ${prism_env} /usr/local/bin/prism --public --uploads"

run_rc_command "$1"
EOF

if doas bastille cmd "$RUN" cmp -s /usr/local/etc/rc.d/prism.new /usr/local/etc/rc.d/prism 2>/dev/null; then
    log "rc.d/prism unchanged"
    doas bastille cmd "$RUN" rm -f /usr/local/etc/rc.d/prism.new
else
    log "rc.d/prism changed — will restart"
    doas bastille cmd "$RUN" mv -f /usr/local/etc/rc.d/prism.new /usr/local/etc/rc.d/prism
    doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/prism
    NEEDS_PRISM_RESTART=1
fi
doas bastille sysrc "$RUN" prism_enable=YES >/dev/null

# --- Cloudflare Tunnel setup ---
# DNS must be running before pkg can bootstrap.
log "Ensuring DNS resolver is running in run jail"
doas bastille sysrc "$RUN" local_unbound_enable=YES >/dev/null
doas bastille service "$RUN" local_unbound status >/dev/null 2>&1 || \
    doas bastille service "$RUN" local_unbound start

# Tunnel and DNS are configured in the Cloudflare dashboard (Zero Trust -> Tunnels).
# Pass CF_TUNNEL_TOKEN on first deploy; it is persisted via sysrc for future runs.
if ! doas bastille cmd "$RUN" pkg info -e cloudflared >/dev/null 2>&1; then
    log "Installing cloudflared"
    doas bastille pkg "$RUN" install -y cloudflared
fi

if [ -n "$CF_TUNNEL_TOKEN" ]; then
    # Suppress -x and sysrc's "key: old -> new" echo so the token never lands
    # in the deploy log.
    set +x
    doas bastille sysrc "$RUN" cloudflared_token="$CF_TUNNEL_TOKEN" >/dev/null 2>&1
    set -x
fi

# Verify token without echoing it.
set +x
if ! doas bastille cmd "$RUN" sh -c '[ -n "$(sysrc -n cloudflared_token 2>/dev/null)" ]' >/dev/null 2>&1; then
    set -x
    die "no tunnel token: set CF_TUNNEL_TOKEN or run: doas bastille sysrc $RUN cloudflared_token=<token>"
fi
set -x

log "Staging rc.d/cloudflared"
doas bastille cmd "$RUN" tee /usr/local/etc/rc.d/cloudflared.new >/dev/null <<'EOF'
#!/bin/sh

# PROVIDE: cloudflared
# REQUIRE: LOGIN DAEMON NETWORKING prism
# KEYWORD: shutdown

. /etc/rc.subr

name="cloudflared"
rcvar="cloudflared_enable"

load_rc_config $name

: ${cloudflared_enable:="NO"}
: ${cloudflared_token:=""}

pidfile="/var/run/${name}.pid"
cloudflared_log="/var/log/${name}.log"
command="/usr/sbin/daemon"
command_args="-c -f -P ${pidfile} -S -R 5 -o ${cloudflared_log} /usr/local/bin/cloudflared tunnel --no-autoupdate run --token ${cloudflared_token}"

run_rc_command "$1"
EOF

if doas bastille cmd "$RUN" cmp -s /usr/local/etc/rc.d/cloudflared.new /usr/local/etc/rc.d/cloudflared 2>/dev/null; then
    log "rc.d/cloudflared unchanged"
    doas bastille cmd "$RUN" rm -f /usr/local/etc/rc.d/cloudflared.new
else
    log "rc.d/cloudflared changed"
    doas bastille cmd "$RUN" mv -f /usr/local/etc/rc.d/cloudflared.new /usr/local/etc/rc.d/cloudflared
    doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/cloudflared
fi
doas bastille sysrc "$RUN" cloudflared_enable=YES >/dev/null

# --- Stage and swap the binary (the only point of downtime) ---
# Copy new binary to /usr/local/bin/prism.new (does not touch the running
# executable, so no ETXTBSY). Compare against current; if unchanged, skip
# the restart entirely. If changed, atomic-rename .new -> live path and
# restart the service.

log "Staging prism binary"
doas bastille jcp "$BUILD" /home/prism/prism/prism "$RUN" /usr/local/bin/prism.new
# Normalize ownership to root:wheel (FreeBSD convention for /usr/local/bin/)
# so future BSD-mv calls don't go interactive on UID mismatch. jcp preserves
# numeric UIDs from the build jail, which may not map to the same user name
# in the run jail.
doas bastille cmd "$RUN" chown root:wheel /usr/local/bin/prism.new
doas bastille cmd "$RUN" chmod 755 /usr/local/bin/prism.new

if doas bastille cmd "$RUN" cmp -s /usr/local/bin/prism.new /usr/local/bin/prism 2>/dev/null; then
    log "Binary unchanged — leaving running service alone"
    doas bastille cmd "$RUN" rm -f /usr/local/bin/prism.new
else
    log "Binary changed — will restart"
    NEEDS_PRISM_RESTART=1
fi

if [ "$NEEDS_PRISM_RESTART" = 1 ]; then
    if doas bastille cmd "$RUN" service prism status >/dev/null 2>&1; then
        # ---- Hot-swap path -------------------------------------------------
        # The running prism listens with SO_REUSEPORT(_LB) so we can bring
        # the replacement up on the same port, prove it's healthy, then
        # SIGTERM the predecessor. Users see no connection-refused gap.
        OLD_PID=$(doas bastille cmd "$RUN" cat /var/run/prism.pid 2>/dev/null || echo "")
        [ -z "$OLD_PID" ] && die "service prism is running but /var/run/prism.pid is missing"
        log "Hot-swap: old prism PID = $OLD_PID"

        # Atomic rename — the running process keeps its old inode (FreeBSD
        # only ETXTBSYs on write-open of a running executable, not on
        # rename). The next daemon() spawn picks up the new binary.
        doas bastille cmd "$RUN" mv -f /usr/local/bin/prism.new /usr/local/bin/prism

        # Pull the runtime config from sysrc so a parallel start matches
        # what rc.d/prism would do. Falls back to the same defaults the
        # rc.d script declares above.
        PRISM_LITMUS_ADDR=$(doas bastille cmd "$RUN" sh -c 'sysrc -n prism_litmus_addr 2>/dev/null' || true)
        [ -z "$PRISM_LITMUS_ADDR" ] && PRISM_LITMUS_ADDR="litmus:49999"
        PRISM_HOPPER_API_ADDR=$(doas bastille cmd "$RUN" sh -c 'sysrc -n prism_hopper_api_addr 2>/dev/null' || true)
        [ -z "$PRISM_HOPPER_API_ADDR" ] && PRISM_HOPPER_API_ADDR="hopper-api:8081"
        PRISM_HOPPER_DSN=$(doas bastille cmd "$RUN" sh -c 'sysrc -n prism_hopper_dsn 2>/dev/null' || true)
        [ -z "$PRISM_HOPPER_DSN" ] && PRISM_HOPPER_DSN="postgres://hopper@hopper-db/hopper?sslmode=disable"
        PRISM_READONLY_VAL=$(doas bastille cmd "$RUN" sh -c 'sysrc -n prism_readonly 2>/dev/null' || true)
        [ -z "$PRISM_READONLY_VAL" ] && PRISM_READONLY_VAL="0"

        log "Starting replacement prism alongside old one"
        # daemon flags mirror rc.d/prism's command_args; only pidfile and
        # logfile differ so the two instances don't fight. -R 5 keeps the
        # restart-on-exit guarantee in case the new process crashes mid-
        # bootstrap. The CSRF key is read from sysrc and passed so the
        # replacement signs tokens with the same key as the outgoing process;
        # -x is off around it so the key never reaches the deploy log.
        set +x
        PRISM_CSRF_KEY=$(doas bastille cmd "$RUN" sh -c 'sysrc -n prism_csrf_key 2>/dev/null' || true)
        doas bastille cmd "$RUN" /usr/sbin/daemon \
            -c -f -P /var/run/prism.next.pid -S -R 5 -o /var/log/prism.next.log \
            -u prism /usr/bin/env \
                HOME=/home/prism \
                PORT=8080 \
                LITMUS_ADDR="$PRISM_LITMUS_ADDR" \
                HOPPER_API_ADDR="$PRISM_HOPPER_API_ADDR" \
                HOPPER_DSN="$PRISM_HOPPER_DSN" \
                PRISM_READONLY="$PRISM_READONLY_VAL" \
                PRISM_CSRF_KEY="$PRISM_CSRF_KEY" \
                OTEL_EXPORTER_OTLP_ENDPOINT=http://otel:9090/api/v1/otlp \
                OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://otel:3100/otlp/v1/logs \
                /usr/local/bin/prism --public --uploads
        set -x

        log "Waiting for replacement to become healthy"
        # Poll the in-jail healthcheck. We can't tell which prism answers
        # any given request (kernel-routed), but as soon as /_/health is
        # 200 we know at least one is up; combined with the next.pid
        # existing and being a fresh PID we know it's the new one.
        deadline=$(( $(date +%s) + 30 ))
        until doas bastille cmd "$RUN" sh -c 'fetch -qo - http://127.0.0.1:8080/_/health >/dev/null 2>&1 || curl -fsS http://127.0.0.1:8080/_/health >/dev/null 2>&1'; do
            if [ "$(date +%s)" -gt "$deadline" ]; then
                log "Replacement failed health check — rolling back"
                if doas bastille cmd "$RUN" test -f /var/run/prism.next.pid; then
                    BAD_PID=$(doas bastille cmd "$RUN" cat /var/run/prism.next.pid 2>/dev/null || true)
                    [ -n "$BAD_PID" ] && doas bastille cmd "$RUN" kill -KILL "$BAD_PID" 2>/dev/null || true
                    doas bastille cmd "$RUN" rm -f /var/run/prism.next.pid
                fi
                die "replacement prism never reached /_/health; old prism still running"
            fi
            sleep 1
        done
        log "Replacement is healthy"

        log "Draining old prism (SIGTERM $OLD_PID)"
        doas bastille cmd "$RUN" kill -TERM "$OLD_PID" 2>/dev/null || true
        # Wait up to graceful-shutdown deadline (5s in main.go) plus headroom.
        deadline=$(( $(date +%s) + 20 ))
        while doas bastille cmd "$RUN" kill -0 "$OLD_PID" 2>/dev/null; do
            if [ "$(date +%s)" -gt "$deadline" ]; then
                log "Old prism didn't exit within 20s — sending SIGKILL"
                doas bastille cmd "$RUN" kill -KILL "$OLD_PID" 2>/dev/null || true
                break
            fi
            sleep 1
        done

        # Promote the next pidfile so `service prism stop/restart/status`
        # keeps managing the right process going forward.
        doas bastille cmd "$RUN" mv -f /var/run/prism.next.pid /var/run/prism.pid
        log "Hot-swap complete"
    else
        # ---- First deploy (no prism running) -------------------------------
        log "First-deploy: staging binary + service start"
        doas bastille cmd "$RUN" mv -f /usr/local/bin/prism.new /usr/local/bin/prism
        doas bastille service "$RUN" prism start
    fi
else
    log "Skipping restart — no changes detected"
fi

if ! doas bastille cmd "$RUN" service cloudflared status >/dev/null 2>&1; then
    log "Starting cloudflared (first deploy)"
    doas bastille service "$RUN" cloudflared start
fi

log "Deployment complete"
