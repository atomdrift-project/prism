#!/bin/sh
# rollout-systemd.sh - Build, test, and install prism as a hardened systemd service.
#
# First deployment:
#   CF_TUNNEL_TOKEN='...' HOPPER_DB_HOST=hopper-db HOPPER_DB_PASS='...' make deploy
#
# HOPPER_DB_HOST defaults to hopper-db. HOPPER_DB_PASS is only needed when
# /etc/prism/pgpass does not already contain an entry for the selected host.
# The PostgreSQL password, CSRF key, and Tunnel token are not placed in a unit,
# environment file, process environment, or command line; systemd supplies
# them from its per-service credential directories.

set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
UNIT_SOURCE="$SCRIPT_DIR/prism.service"
UNIT_TARGET=/etc/systemd/system/prism.service
CLOUDFLARED_UNIT_SOURCE="$SCRIPT_DIR/cloudflared.service"
CLOUDFLARED_UNIT_TARGET=/etc/systemd/system/cloudflared.service
ENV_FILE=/etc/prism/prism.env
PGPASS_FILE=/etc/prism/pgpass
CSRF_FILE=/etc/prism/csrf-key
TUNNEL_TOKEN_FILE=/etc/prism/cloudflared-token
BINARY_TARGET=/usr/local/bin/prism
BACKUP_DIR=/usr/local/lib/prism
ROOT_CMD=
HOST_WAS_SET=0
[ "${HOPPER_DB_HOST+x}" = x ] && HOST_WAS_SET=1
HOPPER_DB_HOST=${HOPPER_DB_HOST:-hopper-db}
HOPPER_DB_SSLMODE=${HOPPER_DB_SSLMODE:-disable}
DB_PASS=${HOPPER_DB_PASS:-}
unset HOPPER_DB_PASS
TUNNEL_TOKEN=${CF_TUNNEL_TOKEN:-}
unset CF_TUNNEL_TOKEN
USER_PGPASS=
if [ -n "${PGPASSFILE:-}" ]; then
    USER_PGPASS=$PGPASSFILE
elif [ -n "${HOME:-}" ]; then
    USER_PGPASS=$HOME/.pgpass
fi

TMP_ENV=
TMP_SECRET=
TMP_CLOUDFLARED_UNIT=
cleanup() {
    [ -z "$TMP_ENV" ] || rm -f "$TMP_ENV"
    [ -z "$TMP_SECRET" ] || rm -f "$TMP_SECRET"
    [ -z "$TMP_CLOUDFLARED_UNIT" ] || rm -f "$TMP_CLOUDFLARED_UNIT"
}
trap cleanup EXIT HUP INT TERM

die() {
    echo "error: $*" >&2
    exit 1
}

log() {
    echo "==> $*"
}

as_root() {
    if [ -z "$ROOT_CMD" ]; then
        "$@"
    else
        "$ROOT_CMD" "$@"
    fi
}

case "$HOPPER_DB_HOST" in
    *[!A-Za-z0-9._-]* | "") die "invalid HOPPER_DB_HOST: $HOPPER_DB_HOST" ;;
esac
case "$HOPPER_DB_SSLMODE" in
    disable | allow | prefer | require | verify-ca | verify-full) ;;
    *) die "invalid HOPPER_DB_SSLMODE: $HOPPER_DB_SSLMODE" ;;
esac
if printf '%s' "$DB_PASS" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    die "HOPPER_DB_PASS must not contain control characters"
fi
if printf '%s' "$TUNNEL_TOKEN" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    die "CF_TUNNEL_TOKEN must not contain control characters"
fi

[ "$(uname -s)" = Linux ] || die "this rollout requires Linux"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
command -v go >/dev/null 2>&1 || die "Go is required to build prism"
SYSTEMD_VERSION=$(systemctl --version | awk 'NR == 1 {print $2}')
case "$SYSTEMD_VERSION" in
    '' | *[!0-9]*) die "could not determine the systemd version" ;;
esac
[ "$SYSTEMD_VERSION" -ge 249 ] \
    || die "systemd 249 or newer is required for service credentials and bind restrictions"
if command -v getent >/dev/null 2>&1 \
    && ! getent hosts "$HOPPER_DB_HOST" >/dev/null 2>&1; then
    die "$HOPPER_DB_HOST does not resolve on this host; fix DNS or /etc/hosts first"
fi
if [ "$(id -u)" -ne 0 ]; then
    if command -v doas >/dev/null 2>&1; then
        doas true
        ROOT_CMD=doas
    elif command -v sudo >/dev/null 2>&1; then
        sudo -v
        ROOT_CMD=sudo
    else
        die "run as root or install doas/sudo"
    fi
fi

log "Building prism"
(cd "$REPO_DIR" && make build)
log "Running tests"
(cd "$REPO_DIR" && make test)
[ -x "$REPO_DIR/prism" ] || die "build did not produce $REPO_DIR/prism"

as_root install -d -o root -g root -m 0700 /etc/prism
as_root install -d -o root -g root -m 0755 /usr/local/bin "$BACKUP_DIR"

PGPASS_PREFIX="${HOPPER_DB_HOST}:5432:hopper:hopper:"
if [ -n "$DB_PASS" ]; then
    log "Installing the supplied PostgreSQL credential for $HOPPER_DB_HOST"
    TMP_SECRET=$(mktemp)
    chmod 600 "$TMP_SECRET"
    ESCAPED_PASS=$(printf '%s' "$DB_PASS" | sed 's/\\/\\\\/g; s/:/\\:/g')
    printf '%s%s\n' "$PGPASS_PREFIX" "$ESCAPED_PASS" >"$TMP_SECRET"
    unset DB_PASS ESCAPED_PASS
    as_root install -o root -g root -m 0600 "$TMP_SECRET" "$PGPASS_FILE"
    rm -f "$TMP_SECRET"
    TMP_SECRET=
elif as_root grep -Fq "$PGPASS_PREFIX" "$PGPASS_FILE" 2>/dev/null; then
    log "Keeping the existing PostgreSQL credential for $HOPPER_DB_HOST"
elif [ -n "$USER_PGPASS" ] && [ -f "$USER_PGPASS" ] \
    && awk -F: -v host="$HOPPER_DB_HOST" \
        '$1 == host && $2 == "5432" && $3 == "hopper" && $4 == "hopper" {found=1} END {exit !found}' \
        "$USER_PGPASS"; then
    log "Importing the $HOPPER_DB_HOST credential from $USER_PGPASS"
    chmod 600 "$USER_PGPASS"
    TMP_SECRET=$(mktemp)
    chmod 600 "$TMP_SECRET"
    awk -F: -v host="$HOPPER_DB_HOST" \
        '$1 == host && $2 == "5432" && $3 == "hopper" && $4 == "hopper" {print; exit}' \
        "$USER_PGPASS" >"$TMP_SECRET"
    as_root install -o root -g root -m 0600 "$TMP_SECRET" "$PGPASS_FILE"
    rm -f "$TMP_SECRET"
    TMP_SECRET=
else
    die "no PostgreSQL credential for $HOPPER_DB_HOST; rerun with HOPPER_DB_PASS set"
fi

if ! command -v cloudflared >/dev/null 2>&1; then
    log "Installing cloudflared"
    if command -v apt-get >/dev/null 2>&1; then
        as_root apt-get update
        as_root apt-get install -y cloudflared
    elif command -v dnf >/dev/null 2>&1; then
        as_root dnf install -y cloudflared
    elif command -v yum >/dev/null 2>&1; then
        as_root yum install -y cloudflared
    elif command -v zypper >/dev/null 2>&1; then
        as_root zypper --non-interactive install cloudflared
    elif command -v pacman >/dev/null 2>&1; then
        as_root pacman -S --needed --noconfirm cloudflared
    else
        die "cloudflared is not installed and no supported package manager was found"
    fi
fi
command -v cloudflared >/dev/null 2>&1 \
    || die "cloudflared installation failed; configure Cloudflare's package repository and retry"
CLOUDFLARED_BIN=$(command -v cloudflared)
case "$CLOUDFLARED_BIN" in
    /usr/bin/cloudflared | /usr/local/bin/cloudflared) ;;
    *) die "cloudflared must be installed at /usr/bin/cloudflared or /usr/local/bin/cloudflared" ;;
esac
CLOUDFLARED_VERSION=$("$CLOUDFLARED_BIN" --version | awk '$1 == "cloudflared" && $2 == "version" {print $3; exit}')
CLOUDFLARED_YEAR=${CLOUDFLARED_VERSION%%.*}
CLOUDFLARED_REST=${CLOUDFLARED_VERSION#*.}
CLOUDFLARED_MONTH=${CLOUDFLARED_REST%%.*}
case "$CLOUDFLARED_YEAR:$CLOUDFLARED_MONTH" in
    *[!0-9:]* | :* | *:) die "could not parse cloudflared version: $CLOUDFLARED_VERSION" ;;
esac
if [ "$CLOUDFLARED_YEAR" -lt 2025 ] \
    || { [ "$CLOUDFLARED_YEAR" -eq 2025 ] && [ "$CLOUDFLARED_MONTH" -lt 4 ]; }; then
    die "cloudflared 2025.4.0 or newer is required for secure token-file support"
fi
CLOUDFLARED_EXEC_PATHS=$CLOUDFLARED_BIN
for libdir in /usr/lib /usr/lib64 /lib /lib64; do
    [ -e "$libdir" ] || continue
    CLOUDFLARED_EXEC_PATHS="$CLOUDFLARED_EXEC_PATHS $libdir"
done

if [ -n "$TUNNEL_TOKEN" ]; then
    log "Installing the supplied Cloudflare Tunnel token"
    if as_root test -s "$TUNNEL_TOKEN_FILE"; then
        as_root cp -p "$TUNNEL_TOKEN_FILE" "${TUNNEL_TOKEN_FILE}.previous"
    fi
    TMP_SECRET=$(mktemp)
    chmod 600 "$TMP_SECRET"
    printf '%s\n' "$TUNNEL_TOKEN" >"$TMP_SECRET"
    unset TUNNEL_TOKEN
    as_root install -o root -g root -m 0600 "$TMP_SECRET" "$TUNNEL_TOKEN_FILE"
    rm -f "$TMP_SECRET"
    TMP_SECRET=
elif ! as_root test -s "$TUNNEL_TOKEN_FILE"; then
    die "no Cloudflare Tunnel token; rerun with CF_TUNNEL_TOKEN set"
else
    log "Keeping the existing Cloudflare Tunnel token"
fi

if ! as_root test -e "$ENV_FILE"; then
    log "Creating $ENV_FILE for PostgreSQL host $HOPPER_DB_HOST"
    TMP_ENV=$(mktemp)
    chmod 600 "$TMP_ENV"
    {
        printf '%s\n' \
            'LISTEN_ADDR=127.0.0.1' \
            'PORT=8080' \
            'CACHE_DIR=/var/cache/prism' \
            "HOPPER_DSN=postgres://hopper@${HOPPER_DB_HOST}:5432/hopper?sslmode=${HOPPER_DB_SSLMODE}&application_name=prism&default_transaction_read_only=on" \
            'HOPPER_API_ADDR=hopper-api:8081' \
            'LITMUS_ADDR=scan:49999' \
            'PRISM_UPLOADS=true'
    } >"$TMP_ENV"
    as_root install -o root -g root -m 0600 "$TMP_ENV" "$ENV_FILE"
elif [ "$HOST_WAS_SET" -eq 1 ]; then
    log "Updating the persisted PostgreSQL endpoint to $HOPPER_DB_HOST"
    DSN="postgres://hopper@${HOPPER_DB_HOST}:5432/hopper?sslmode=${HOPPER_DB_SSLMODE}&application_name=prism&default_transaction_read_only=on"
    SED_DSN=$(printf '%s' "$DSN" | sed 's/[&|\\]/\\&/g')
    as_root grep -q '^HOPPER_DSN=' "$ENV_FILE" \
        || die "$ENV_FILE has no HOPPER_DSN entry; add one before deploying"
    as_root sed -i "s|^HOPPER_DSN=.*|HOPPER_DSN=$SED_DSN|" "$ENV_FILE"
else
    log "Keeping the PostgreSQL endpoint persisted in $ENV_FILE"
fi

if ! as_root test -s "$CSRF_FILE"; then
    log "Generating a persistent CSRF signing key"
    TMP_SECRET=$(mktemp)
    chmod 600 "$TMP_SECRET"
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"$TMP_SECRET"
    printf '\n' >>"$TMP_SECRET"
    [ "$(wc -c <"$TMP_SECRET")" -eq 65 ] || die "failed to generate CSRF key"
    as_root install -o root -g root -m 0600 "$TMP_SECRET" "$CSRF_FILE"
    rm -f "$TMP_SECRET"
    TMP_SECRET=
fi

log "Installing the unit and binary atomically"
if [ -e "$UNIT_TARGET" ]; then
    as_root cp -p "$UNIT_TARGET" "$BACKUP_DIR/prism.service.previous"
fi
if [ -e "$BINARY_TARGET" ]; then
    as_root cp -p "$BINARY_TARGET" "$BACKUP_DIR/prism.previous"
fi
if [ -e "$CLOUDFLARED_UNIT_TARGET" ]; then
    as_root cp -p "$CLOUDFLARED_UNIT_TARGET" "$BACKUP_DIR/cloudflared.service.previous"
fi
TMP_CLOUDFLARED_UNIT=$(mktemp)
sed "s|@CLOUDFLARED_BIN@|$CLOUDFLARED_BIN|g" \
    "$CLOUDFLARED_UNIT_SOURCE" \
    | sed "s|@CLOUDFLARED_EXEC_PATHS@|$CLOUDFLARED_EXEC_PATHS|g" \
        >"$TMP_CLOUDFLARED_UNIT"
as_root install -o root -g root -m 0644 "$UNIT_SOURCE" "${UNIT_TARGET}.new"
as_root mv -f "${UNIT_TARGET}.new" "$UNIT_TARGET"
as_root install -o root -g root -m 0644 \
    "$TMP_CLOUDFLARED_UNIT" "${CLOUDFLARED_UNIT_TARGET}.new"
as_root mv -f "${CLOUDFLARED_UNIT_TARGET}.new" "$CLOUDFLARED_UNIT_TARGET"
rm -f "$TMP_CLOUDFLARED_UNIT"
TMP_CLOUDFLARED_UNIT=
as_root install -o root -g root -m 0755 "$REPO_DIR/prism" "${BINARY_TARGET}.new"
as_root mv -f "${BINARY_TARGET}.new" "$BINARY_TARGET"

if command -v systemd-analyze >/dev/null 2>&1; then
    as_root systemd-analyze verify "$UNIT_TARGET" "$CLOUDFLARED_UNIT_TARGET"
fi
as_root systemctl daemon-reload
as_root systemctl enable prism.service >/dev/null
as_root systemctl enable cloudflared.service >/dev/null
as_root systemctl restart prism.service

log "Waiting for prism to become healthy"
deadline=$(( $(date +%s) + 30 ))
while :; do
    if command -v curl >/dev/null 2>&1; then
        curl -fsS http://127.0.0.1:8080/_/health >/dev/null 2>&1 && break
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- http://127.0.0.1:8080/_/health >/dev/null 2>&1 && break
    else
        die "curl or wget is required for the deployment health check"
    fi
    if [ "$(date +%s)" -gt "$deadline" ]; then
        as_root systemctl status prism.service --no-pager || true
        as_root journalctl -u prism.service -n 50 --no-pager || true
        if [ -e "$BACKUP_DIR/prism.previous" ]; then
            log "Health check failed; restoring the previous binary"
            as_root install -o root -g root -m 0755 \
                "$BACKUP_DIR/prism.previous" "${BINARY_TARGET}.rollback"
            as_root mv -f "${BINARY_TARGET}.rollback" "$BINARY_TARGET"
            if [ -e "$BACKUP_DIR/prism.service.previous" ]; then
                as_root install -o root -g root -m 0644 \
                    "$BACKUP_DIR/prism.service.previous" "${UNIT_TARGET}.rollback"
                as_root mv -f "${UNIT_TARGET}.rollback" "$UNIT_TARGET"
                as_root systemctl daemon-reload
            fi
            as_root systemctl restart prism.service || true
        fi
        die "prism did not become healthy within 30 seconds"
    fi
    sleep 1
done

log "Starting Cloudflare Tunnel"
if ! as_root systemctl restart cloudflared.service; then
    as_root systemctl status cloudflared.service --no-pager || true
    as_root journalctl -u cloudflared.service -n 50 --no-pager || true
    if [ -e "$BACKUP_DIR/cloudflared.service.previous" ]; then
        log "Tunnel failed to start; restoring its previous unit and token"
        as_root install -o root -g root -m 0644 \
            "$BACKUP_DIR/cloudflared.service.previous" "${CLOUDFLARED_UNIT_TARGET}.rollback"
        as_root mv -f "${CLOUDFLARED_UNIT_TARGET}.rollback" "$CLOUDFLARED_UNIT_TARGET"
        if as_root test -s "${TUNNEL_TOKEN_FILE}.previous"; then
            as_root install -o root -g root -m 0600 \
                "${TUNNEL_TOKEN_FILE}.previous" "${TUNNEL_TOKEN_FILE}.rollback"
            as_root mv -f "${TUNNEL_TOKEN_FILE}.rollback" "$TUNNEL_TOKEN_FILE"
        fi
        as_root systemctl daemon-reload
        as_root systemctl restart cloudflared.service || true
    fi
    die "Cloudflare Tunnel failed to start"
fi
as_root systemctl is-active --quiet cloudflared.service \
    || die "cloudflared.service did not remain active"

log "Deployment complete: prism is active on 127.0.0.1:8080 and the tunnel is connected"
