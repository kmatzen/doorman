#!/usr/bin/env bash
#
# Install doorman on macOS. Idempotent — re-running fixes drift instead of
# creating duplicates.
#
# Run as root: `sudo bash scripts/install-darwin.sh`.
#
# Does not start the daemon. After the script finishes you still need to:
#   1. Write /etc/doorman/doorman.yaml with real credentials (mode 0400).
#   2. Bootstrap launchd:
#        sudo launchctl bootstrap system /Library/LaunchDaemons/com.doorman.doormand.plist
#
# Uninstall:
#   sudo launchctl bootout system/com.doorman.doormand 2>/dev/null || true
#   sudo rm -f /Library/LaunchDaemons/com.doorman.doormand.plist
#   sudo rm -f /usr/local/bin/doormand
#   sudo rm -rf /etc/doorman /var/log/doorman
#   sudo dscl . -delete /Users/_doorman 2>/dev/null || true
#   sudo dscl . -delete /Groups/_doorman 2>/dev/null || true

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "this script targets macOS; on Linux use the systemd unit emitted by 'doormand install-service'" >&2
    exit 1
fi
if [[ "$(id -u)" -ne 0 ]]; then
    echo "must run as root: sudo bash $0" >&2
    exit 1
fi

# Resolve the source binary. Look at the standard build output first.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_BIN="${REPO_ROOT}/target/release/doormand"
if [[ ! -x "${SOURCE_BIN}" ]]; then
    echo "no release binary at ${SOURCE_BIN}" >&2
    echo "run 'make release' (or 'cargo build --release') first" >&2
    exit 1
fi

INSTALL_BIN="/usr/local/bin/doormand"
ETC_DIR="/etc/doorman"
LOG_DIR="/var/log/doorman"
PLIST="/Library/LaunchDaemons/com.doorman.doormand.plist"
USER_NAME="_doorman"
GROUP_NAME="_doorman"

echo "==> installing binary to ${INSTALL_BIN}"
install -m 0755 -o root -g wheel "${SOURCE_BIN}" "${INSTALL_BIN}"

# Read existing UID/GID if either record already exists. We may be picking
# up a half-finished previous run.
EXISTING_UID=""
EXISTING_GID=""
if dscl . -read "/Users/${USER_NAME}" >/dev/null 2>&1; then
    EXISTING_UID="$(dscl . -read "/Users/${USER_NAME}" UniqueID 2>/dev/null | awk '{print $2}')"
fi
if dscl . -read "/Groups/${GROUP_NAME}" >/dev/null 2>&1; then
    EXISTING_GID="$(dscl . -read "/Groups/${GROUP_NAME}" PrimaryGroupID 2>/dev/null | awk '{print $2}')"
fi

if [[ -n "${EXISTING_UID}" ]]; then
    UID_USE="${EXISTING_UID}"
elif [[ -n "${EXISTING_GID}" ]]; then
    UID_USE="${EXISTING_GID}"
else
    # Pick the lowest unused id >= 400, considering both /Users and /Groups
    # so user and group can share the number.
    UID_USE=400
    USED="$( { dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } | awk '{print $2}')"
    while echo "${USED}" | grep -qx "${UID_USE}"; do
        UID_USE=$((UID_USE + 1))
    done
fi

if [[ -z "${EXISTING_GID}" ]]; then
    echo "==> creating group ${GROUP_NAME} (gid ${UID_USE})"
    dscl . -create "/Groups/${GROUP_NAME}"
    dscl . -create "/Groups/${GROUP_NAME}" PrimaryGroupID "${UID_USE}"
    dscl . -create "/Groups/${GROUP_NAME}" RealName "doorman daemon"
else
    echo "==> group ${GROUP_NAME} already exists (gid ${EXISTING_GID}), skipping"
fi

if [[ -z "${EXISTING_UID}" ]]; then
    echo "==> creating user ${USER_NAME} (uid ${UID_USE})"
    dscl . -create "/Users/${USER_NAME}"
    dscl . -create "/Users/${USER_NAME}" UserShell /usr/bin/false
    dscl . -create "/Users/${USER_NAME}" UniqueID "${UID_USE}"
    dscl . -create "/Users/${USER_NAME}" PrimaryGroupID "${UID_USE}"
    dscl . -create "/Users/${USER_NAME}" NFSHomeDirectory /var/empty
    dscl . -create "/Users/${USER_NAME}" RealName "doorman daemon"
else
    echo "==> user ${USER_NAME} already exists (uid ${EXISTING_UID}), skipping"
fi

echo "==> creating ${ETC_DIR} (mode 0750, owned by ${USER_NAME})"
mkdir -p "${ETC_DIR}"
chown "${USER_NAME}:${GROUP_NAME}" "${ETC_DIR}"
chmod 0750 "${ETC_DIR}"

echo "==> creating ${LOG_DIR} (mode 0750, owned by ${USER_NAME})"
mkdir -p "${LOG_DIR}"
chown "${USER_NAME}:${GROUP_NAME}" "${LOG_DIR}"
chmod 0750 "${LOG_DIR}"

echo "==> writing launchd plist to ${PLIST}"
"${INSTALL_BIN}" install-service --bin-path "${INSTALL_BIN}" > "${PLIST}.tmp"
chown root:wheel "${PLIST}.tmp"
chmod 0644 "${PLIST}.tmp"
mv "${PLIST}.tmp" "${PLIST}"

cat <<DONE

Installed.

Next steps:
  1. Write your config:
       sudo -u ${USER_NAME} touch ${ETC_DIR}/doorman.yaml
       sudo chmod 0400 ${ETC_DIR}/doorman.yaml
       sudoedit ${ETC_DIR}/doorman.yaml

  2. Start the daemon:
       sudo launchctl bootstrap system ${PLIST}

  3. Verify it's listening:
       lsof -nP -iTCP:8443 -sTCP:LISTEN

  4. Tail the audit log:
       sudo tail -f ${LOG_DIR}/audit.log

To uninstall, see the comment at the top of this script.
DONE
