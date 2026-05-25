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
# Service stays running across all config and binary-staging steps. The only
# moment of downtime is the final `service prism restart`, gated behind a
# diff: if neither the binary nor rc.d/prism changed, no restart happens.
# Binary is staged into /usr/local/bin/prism.new and atomically renamed into
# place just before restart, so we never overwrite a running executable
# (FreeBSD ETXTBSY) and never have a window with no binary present.

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

# --- Resolve hopper hostnames ---
# hopper-api serves the API; hopper-db serves PostgreSQL.

HOPPER_API_LINE=$(awk '/[[:space:]]hopper-api([[:space:]]|$)/{print; exit}' /etc/hosts)
[ -z "$HOPPER_API_LINE" ] && die "hopper-api not found in /etc/hosts — add an entry before deploying"
log "Using hopper-api: $HOPPER_API_LINE"

HOPPER_DB_LINE=$(awk '/[[:space:]]hopper-db([[:space:]]|$)/{print; exit}' /etc/hosts)
[ -z "$HOPPER_DB_LINE" ] && die "hopper-db not found in /etc/hosts — add an entry before deploying"
log "Using hopper-db: $HOPPER_DB_LINE"

# Verify jails are accessible
doas bastille cmd "$BUILD" true || die "build jail '$BUILD' not accessible"
doas bastille cmd "$RUN" true || die "run jail '$RUN' not accessible"

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
# Stored in ~prism/.pgpass in the run jail (PostgreSQL standard; pgx reads it
# automatically). The password is never placed in the DSN, environment, or
# process table. Copied from the hopper jail where it is already provisioned.

if doas bastille cmd "$RUN" sh -c "test -f /home/prism/.pgpass" 2>/dev/null; then
    log "Hopper credentials already present in prism jail, skipping copy"
else
    log "Copying hopper credentials from hopper-db jail"
    doas bastille cmd hopper-db test -f /home/hopper/.pgpass || die "hopper-db jail pgpass not found at /home/hopper/.pgpass"
    set +x
    HOPPER_PASS=$(doas bastille cmd hopper-db sh -c "cut -d: -f5 /home/hopper/.pgpass")
    [ -z "$HOPPER_PASS" ] && die "could not read password from hopper-db jail pgpass"
    doas bastille cmd "$RUN" su -l prism -c "printf 'hopper-db:5432:hopper:hopper:%s\n' '$HOPPER_PASS' > ~/.pgpass && chmod 600 ~/.pgpass"
    unset HOPPER_PASS
    set -x
fi

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

pidfile="/var/run/${name}.pid"
prism_log="/var/log/${name}.log"
command="/usr/sbin/daemon"
# HOME is set so pgx can locate ~prism/.pgpass for the hopper database password.
prism_env="HOME=/home/prism PORT=8080 LITMUS_ADDR=${prism_litmus_addr} HOPPER_API_ADDR=${prism_hopper_api_addr} HOPPER_DSN=postgres://hopper@hopper-db/hopper"
command_args="-c -f -P ${pidfile} -S -R 5 -o ${prism_log} -u prism /usr/bin/env ${prism_env} /usr/local/bin/prism --public"

run_rc_command "$1"
EOF

if doas bastille cmd "$RUN" cmp -s /usr/local/etc/rc.d/prism.new /usr/local/etc/rc.d/prism 2>/dev/null; then
    log "rc.d/prism unchanged"
    doas bastille cmd "$RUN" rm -f /usr/local/etc/rc.d/prism.new
else
    log "rc.d/prism changed — will restart"
    doas bastille cmd "$RUN" mv /usr/local/etc/rc.d/prism.new /usr/local/etc/rc.d/prism
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
    doas bastille cmd "$RUN" mv /usr/local/etc/rc.d/cloudflared.new /usr/local/etc/rc.d/cloudflared
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
doas bastille cmd "$RUN" chmod 755 /usr/local/bin/prism.new

if doas bastille cmd "$RUN" cmp -s /usr/local/bin/prism.new /usr/local/bin/prism 2>/dev/null; then
    log "Binary unchanged — leaving running service alone"
    doas bastille cmd "$RUN" rm -f /usr/local/bin/prism.new
else
    log "Binary changed — will restart"
    NEEDS_PRISM_RESTART=1
fi

if [ "$NEEDS_PRISM_RESTART" = 1 ]; then
    # Atomic on the same filesystem; the running prism keeps its old inode
    # until restart. Done immediately before the restart to keep the window
    # between "binary changed on disk" and "service restarted" minimal.
    if doas bastille cmd "$RUN" test -f /usr/local/bin/prism.new; then
        doas bastille cmd "$RUN" mv /usr/local/bin/prism.new /usr/local/bin/prism
    fi
    if doas bastille cmd "$RUN" service prism status >/dev/null 2>&1; then
        log "Restarting prism service"
        doas bastille service "$RUN" prism restart
    else
        log "Starting prism service"
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
