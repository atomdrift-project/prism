#!/bin/sh
# rollout-bastille.sh - Deploy prism using separate build and run jails
# Usage: ./rollout-bastille.sh <build-jail> <run-jail>
#
# Environment:
#   CF_TUNNEL_TOKEN - Cloudflare Tunnel token (required on first deploy,
#                     persisted in jail via sysrc for subsequent runs)

set -e

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

# Verify jails are accessible
doas bastille cmd "$BUILD" true || die "build jail '$BUILD' not accessible"
doas bastille cmd "$RUN" true || die "run jail '$RUN' not accessible"

# --- Build jail setup ---

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

# --- Transfer binary via jail filesystem ---

BASTILLE_DIR="/usr/local/bastille/jails"

log "Transferring binary to run jail"
doas cp "$BASTILLE_DIR/$BUILD/root/home/prism/prism/prism" \
       "$BASTILLE_DIR/$RUN/root/tmp/prism"

# --- Run jail setup ---

log "Ensuring run user exists"
doas bastille cmd "$RUN" id -u prism >/dev/null 2>&1 || \
    doas bastille cmd "$RUN" pw useradd prism -m -s /bin/sh -c "Prism Service"

log "Installing prism binary"
doas bastille cmd "$RUN" mkdir -p /usr/local/bin
doas bastille cmd "$RUN" install -o root -g wheel -m 755 /tmp/prism /usr/local/bin/prism
doas bastille cmd "$RUN" rm -f /tmp/prism

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
prism_env="PORT=8080 LITMUS_ADDR=${prism_litmus_addr}"
command_args="-c -f -P ${pidfile} -S -R 5 -o ${prism_log} -u prism /usr/bin/env ${prism_env} /usr/local/bin/prism --public"

run_rc_command "$1"
EOF

doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/prism

log "Enabling and restarting prism service"
doas bastille sysrc "$RUN" prism_enable=YES
doas bastille service "$RUN" prism stop 2>/dev/null || true
doas bastille service "$RUN" prism start

# --- Cloudflare Tunnel setup ---
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

log "Enabling and restarting cloudflared"
doas bastille sysrc "$RUN" cloudflared_enable=YES
doas bastille service "$RUN" cloudflared stop 2>/dev/null || true
doas bastille service "$RUN" cloudflared start

log "Deployment complete"
