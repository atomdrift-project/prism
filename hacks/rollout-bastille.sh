#!/bin/sh
# rollout-bastille.sh - Deploy prism using separate build and run jails
# Usage: ./rollout-bastille.sh <build-jail> <run-jail>
#
# Environment:
#   CF_TUNNEL_TOKEN - Cloudflare Tunnel token (required on first deploy,
#                     persisted in jail via sysrc for subsequent runs)
#
# Prerequisites:
#   - "hopper" must have an entry in /etc/hosts on this host
#   - The hopper PostgreSQL database must be reachable from the run jail

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

# --- Resolve hopper hostname ---
# Look up the hopper entry in /etc/hosts so the run jail can reach the database.

HOPPER_LINE=$(awk '/[[:space:]]hopper([[:space:]]|$)/{print; exit}' /etc/hosts)
[ -z "$HOPPER_LINE" ] && die "hopper not found in /etc/hosts — add an entry before deploying"
log "Using hopper: $HOPPER_LINE"

# Verify jails are accessible
doas bastille cmd "$BUILD" true || die "build jail '$BUILD' not accessible"
doas bastille cmd "$RUN" true || die "run jail '$RUN' not accessible"

# --- Build jail setup ---

log "Ensuring DNS resolver is running in build jail"
doas bastille sysrc "$BUILD" local_unbound_enable=YES
doas bastille service "$BUILD" local_unbound status >/dev/null 2>&1 || \
    doas bastille service "$BUILD" local_unbound start

log "Ensuring build user exists"
doas bastille cmd "$BUILD" id -u prism >/dev/null 2>&1 || \
    doas bastille cmd "$BUILD" pw useradd prism -m -s /bin/sh -c "Prism Build"

log "Installing build dependencies"
doas bastille pkg "$BUILD" install -y go gmake

log "Copying source tree to build jail"
doas bastille cmd "$BUILD" rm -rf /home/prism/prism
doas bastille cp "$BUILD" . /home/prism/prism
doas bastille cmd "$BUILD" chown -R prism:prism /home/prism/prism

log "Building prism binary"
doas bastille cmd "$BUILD" su -l prism -c "cd ~/prism && gmake build"

log "Running tests"
doas bastille cmd "$BUILD" su -l prism -c "cd ~/prism && gmake test"

# --- Run jail setup (all config before any restarts) ---

# Ensure hopper hostname resolves inside the run jail.
if ! doas bastille cmd "$RUN" grep -q 'hopper' /etc/hosts 2>/dev/null; then
    doas bastille cmd "$RUN" sh -c "echo '$HOPPER_LINE' >> /etc/hosts"
    log "Added hopper to jail /etc/hosts"
fi

log "Ensuring run user exists"
doas bastille cmd "$RUN" id -u prism >/dev/null 2>&1 || \
    doas bastille cmd "$RUN" pw useradd prism -m -s /bin/sh -c "Prism Service"

log "Stopping prism service (if running)"
doas bastille cmd "$RUN" service prism stop 2>/dev/null || true

log "Installing prism binary"
doas bastille cmd "$RUN" mkdir -p /usr/local/bin
doas bastille jcp "$BUILD" /home/prism/prism/prism "$RUN" /usr/local/bin/prism
doas bastille cmd "$RUN" chmod 755 /usr/local/bin/prism

# --- Hopper database password ---
# Stored in ~prism/.pgpass (PostgreSQL standard; pgx reads it automatically).
# The password is never placed in the DSN, environment, or process table.
# Copied from the hopper jail where it is already provisioned.

# --- Hopper database password ---
# Stored in ~prism/.pgpass in the run jail (PostgreSQL standard; pgx reads it automatically).
# The password is never placed in the DSN, environment, or process table.

if doas bastille cmd "$RUN" sh -c "test -f /home/prism/.pgpass" 2>/dev/null; then
    log "Hopper credentials already present in prism jail, skipping copy"
else
    log "Copying hopper credentials from hopper jail"
    doas bastille cmd hopper test -f /home/hopper/.pgpass || die "hopper jail pgpass not found at /home/hopper/.pgpass"
    # Hoist the password from the hopper jail's pgpass (localhost entry) and write a
    # remote entry for prism to use (connecting to the hopper host, not localhost).
    set +x
    HOPPER_PASS=$(doas bastille cmd hopper sh -c "cut -d: -f5 /home/hopper/.pgpass")
    [ -z "$HOPPER_PASS" ] && die "could not read password from hopper jail pgpass"
    doas bastille cmd "$RUN" su -l prism -c "printf 'hopper:5432:hopper:hopper:%s\n' '$HOPPER_PASS' > ~/.pgpass && chmod 600 ~/.pgpass"
    unset HOPPER_PASS
    set -x
fi

log "Creating rc.d service for prism"
doas bastille cmd "$RUN" mkdir -p /usr/local/etc/rc.d
doas bastille cmd "$RUN" tee /usr/local/etc/rc.d/prism >/dev/null <<'EOF'
#!/bin/sh

# PROVIDE: prism
# REQUIRE: LOGIN DAEMON NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="prism"
rcvar="prism_enable"

load_rc_config $name

: ${prism_enable:="NO"}
: ${prism_litmus_addr:="10.9.8.63:8880"}

pidfile="/var/run/${name}.pid"
prism_log="/var/log/${name}.log"
command="/usr/sbin/daemon"
# HOME is set so pgx can locate ~prism/.pgpass for the hopper database password.
prism_env="HOME=/home/prism PORT=8080 LITMUS_ADDR=${prism_litmus_addr} HOPPER_DSN=postgres://hopper@hopper/hopper"
command_args="-c -f -P ${pidfile} -S -R 5 -o ${prism_log} -u prism /usr/bin/env ${prism_env} /usr/local/bin/prism --public"

run_rc_command "$1"
EOF

doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/prism
doas bastille sysrc "$RUN" prism_enable=YES

# --- Cloudflare Tunnel setup ---
# DNS must be running before pkg can bootstrap.
log "Ensuring DNS resolver is running in run jail"
doas bastille sysrc "$RUN" local_unbound_enable=YES
doas bastille service "$RUN" local_unbound status >/dev/null 2>&1 || \
    doas bastille service "$RUN" local_unbound start


# Tunnel and DNS are configured in the Cloudflare dashboard (Zero Trust -> Tunnels).
# Pass CF_TUNNEL_TOKEN on first deploy; it is persisted via sysrc for future runs.

log "Installing cloudflared"
doas bastille pkg "$RUN" install -y cloudflared

if [ -n "$CF_TUNNEL_TOKEN" ]; then
    doas bastille sysrc "$RUN" cloudflared_token="$CF_TUNNEL_TOKEN"
fi

CONFIGURED_TOKEN=$(doas bastille cmd "$RUN" sysrc -n cloudflared_token 2>/dev/null || true)
[ -z "$CONFIGURED_TOKEN" ] && die "no tunnel token: set CF_TUNNEL_TOKEN or run: doas bastille sysrc $RUN cloudflared_token=<token>"

log "Creating rc.d service for cloudflared"
doas bastille cmd "$RUN" tee /usr/local/etc/rc.d/cloudflared >/dev/null <<'EOF'
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

doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/cloudflared
doas bastille sysrc "$RUN" cloudflared_enable=YES

# --- Restart prism; start cloudflared only if not already running ---

if doas bastille cmd "$RUN" service prism status >/dev/null 2>&1; then
    log "Restarting prism service"
    doas bastille service "$RUN" prism restart
else
    log "Starting prism service (first deploy)"
    doas bastille service "$RUN" prism start
fi

if ! doas bastille cmd "$RUN" service cloudflared status >/dev/null 2>&1; then
    log "Starting cloudflared (first deploy)"
    doas bastille service "$RUN" cloudflared start
fi

log "Deployment complete"
