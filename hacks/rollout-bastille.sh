#!/bin/sh
# rollout-bastille.sh - Deploy prism using separate build and run jails
# Usage: ./rollout-bastille.sh <build-jail> <run-jail>
#
# Environment:
#   CF_TUNNEL_NAME     - Tunnel name (default: "prism")
#   CF_TUNNEL_HOSTNAME - Public hostname for the tunnel (default: "prism.example.com")
#
# On first run, cloudflared prints a URL to authenticate with Cloudflare.
# The resulting cert.pem is persisted in the jail for subsequent runs.

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

CF_TUNNEL_NAME="${CF_TUNNEL_NAME:-prism}"
CF_TUNNEL_HOSTNAME="${CF_TUNNEL_HOSTNAME:-prism.atomdrift.org}"

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
command_args="-c -f -P ${pidfile} -S -R 5 -o ${prism_log} -u prism /usr/bin/env ${prism_env} /usr/local/bin/prism"

run_rc_command "$1"
EOF

doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/prism

log "Enabling and restarting prism service"
doas bastille sysrc "$RUN" prism_enable=YES
doas bastille service "$RUN" prism stop 2>/dev/null || true
doas bastille service "$RUN" prism start

# --- Cloudflare Tunnel setup ---

CF_HOME="/usr/local/etc/cloudflared"

log "Installing cloudflared"
doas bastille pkg "$RUN" install -y cloudflared

log "Creating cloudflared user"
doas bastille cmd "$RUN" id -u cloudflared >/dev/null 2>&1 || \
    doas bastille cmd "$RUN" pw useradd cloudflared -d /nonexistent -s /usr/sbin/nologin -c "Cloudflare Tunnel"

doas bastille cmd "$RUN" mkdir -p "$CF_HOME"

# Authenticate with Cloudflare if not already done.
# On first run this prints a URL to open in a browser; cert.pem is persisted for future runs.
# cloudflared always writes cert.pem to ~/.cloudflared/, so we move it afterward.
if ! doas bastille cmd "$RUN" test -f "$CF_HOME/cert.pem"; then
    log "Authenticating with Cloudflare (open the URL printed below in a browser)"
    doas bastille cmd "$RUN" cloudflared tunnel login
    doas bastille cmd "$RUN" mv /root/.cloudflared/cert.pem "$CF_HOME/cert.pem"
fi

# Create the tunnel if it doesn't already exist.
if ! doas bastille cmd "$RUN" cloudflared tunnel --origincert "$CF_HOME/cert.pem" --cred-file "$CF_HOME" list -n "$CF_TUNNEL_NAME" 2>/dev/null | grep -q "$CF_TUNNEL_NAME"; then
    log "Creating tunnel '$CF_TUNNEL_NAME'"
    doas bastille cmd "$RUN" cloudflared tunnel --origincert "$CF_HOME/cert.pem" --cred-file "$CF_HOME" create "$CF_TUNNEL_NAME"
else
    log "Tunnel '$CF_TUNNEL_NAME' already exists"
fi

# Resolve the tunnel UUID from the credentials file.
CF_TUNNEL_UUID=$(doas bastille cmd "$RUN" ls "$CF_HOME" | grep '\.json$' | head -1 | sed 's/\.json$//')
[ -z "$CF_TUNNEL_UUID" ] && die "could not determine tunnel UUID"
log "Tunnel UUID: $CF_TUNNEL_UUID"

# Write the tunnel config file.
log "Writing cloudflared config"
doas bastille cmd "$RUN" tee "$CF_HOME/config.yml" >/dev/null <<CFEOF
tunnel: ${CF_TUNNEL_UUID}
credentials-file: ${CF_HOME}/${CF_TUNNEL_UUID}.json
origincert: ${CF_HOME}/cert.pem

ingress:
  - hostname: ${CF_TUNNEL_HOSTNAME}
    service: http://localhost:8080
  - service: http_status:404
CFEOF

# Route DNS (idempotent — updates the CNAME if it already exists).
log "Routing DNS for $CF_TUNNEL_HOSTNAME"
doas bastille cmd "$RUN" cloudflared tunnel --origincert "$CF_HOME/cert.pem" route dns "$CF_TUNNEL_NAME" "$CF_TUNNEL_HOSTNAME" || true

# Fix ownership so the unprivileged user can read credentials.
doas bastille cmd "$RUN" chown -R cloudflared:cloudflared "$CF_HOME"
doas bastille cmd "$RUN" chmod 700 "$CF_HOME"
doas bastille cmd "$RUN" chmod 600 "$CF_HOME"/*.json "$CF_HOME"/cert.pem

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

pidfile="/var/run/${name}.pid"
cloudflared_log="/var/log/${name}.log"
command="/usr/sbin/daemon"
command_args="-c -f -P ${pidfile} -S -R 5 -o ${cloudflared_log} -u cloudflared /usr/local/bin/cloudflared tunnel --no-autoupdate --config /usr/local/etc/cloudflared/config.yml run"

run_rc_command "$1"
EOF

doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/cloudflared

log "Enabling and restarting cloudflared"
doas bastille sysrc "$RUN" cloudflared_enable=YES
doas bastille service "$RUN" cloudflared stop 2>/dev/null || true
doas bastille service "$RUN" cloudflared start

log "Deployment complete"
