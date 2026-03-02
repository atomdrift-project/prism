#!/bin/sh
# rollout-bastille.sh - Deploy prism using separate build and run jails
# Usage: ./rollout-bastille.sh <build-jail> <run-jail>

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

log "Building binary"
doas bastille cmd "$BUILD" su -l prism -c "cd ~/prism && gmake build"

# --- Transfer binary via jail filesystem ---

log "Transferring binary to run jail"
BASTILLE_DIR="/usr/local/bastille/jails"
doas cp "$BASTILLE_DIR/$BUILD/root/home/prism/prism/prism" \
       "$BASTILLE_DIR/$RUN/root/tmp/prism"

# --- Run jail setup ---

log "Ensuring run user exists"
doas bastille cmd "$RUN" id -u prism >/dev/null 2>&1 || \
    doas bastille cmd "$RUN" pw useradd prism -m -s /bin/sh -c "Prism Service"

log "Installing binary"
doas bastille cmd "$RUN" mkdir -p /usr/local/bin
doas bastille cmd "$RUN" install -o root -g wheel -m 755 /tmp/prism /usr/local/bin/prism
doas bastille cmd "$RUN" rm -f /tmp/prism

log "Creating rc.d service"
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
: ${prism_cleave_url:="http://10.9.8.62:8000"}

pidfile="/var/run/${name}.pid"
command="/usr/sbin/daemon"
prism_env="PORT=8080 CLEAVE_URL=${prism_cleave_url}"
command_args="-c -f -P ${pidfile} -S -r -u prism /usr/bin/env ${prism_env} /usr/local/bin/prism"

run_rc_command "$1"
EOF

doas bastille cmd "$RUN" chmod 755 /usr/local/etc/rc.d/prism

log "Enabling and restarting prism service"
doas bastille sysrc "$RUN" prism_enable=YES
doas bastille service "$RUN" prism stop 2>/dev/null || true
doas bastille service "$RUN" prism start

log "Deployment complete"
