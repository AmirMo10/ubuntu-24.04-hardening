#!/usr/bin/env bash
# Ubuntu Server 24.04 LTS hardening and posture-audit utility
# Version: 1.1.0 (2026-07-28)
#
# Design goals:
#   - conservative, server-safe defaults
#   - idempotent managed drop-ins instead of destructive rewrites
#   - transactional backups and an explicit rollback path
#   - SSH/UFW lockout checks before enforcement
#   - no obsolete crypto pinning, blanket service removal, or fragile CIS cargo-culting
#
# Review this file and test it on a disposable clone before production rollout.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_NAME="${0##*/}"
readonly SCRIPT_VERSION="1.1.0"
readonly BACKUP_ROOT="/var/backups/ubuntu-hardening"
readonly DEFAULT_LOG_FILE="/var/log/ubuntu-hardening.log"

MODE="audit"
MODE_SET=0
ROLLBACK_TARGET=""
FORCE=0
UPGRADE_SYSTEM=0
ADMIN_USER=""
PASSWORD_POLICY="auto"       # auto | disable | preserve
ENABLE_SSH_HARDENING=1
ENABLE_UFW=1
ENABLE_FAIL2BAN=1
ENABLE_AUDITD=1
ENABLE_UNATTENDED=1
ENABLE_APPARMOR=1
ENABLE_PWQUALITY=1
DISABLE_COREDUMPS=1
WITH_AIDE=0
STRICT_RPF=0
DISABLE_SSH_FORWARDING=0
STRICT_MODULES=0
AUDIT_IMMUTABLE=0
AUTO_REBOOT=0
AUTO_REBOOT_TIME="03:30"

CURRENT_STAGE="initialization"
LOG_FILE=""
BACKUP_DIR=""
VIRT_TYPE="unknown"
IS_WSL=0
IS_DESKTOP=0
SSH_SERVER_PRESENT=0
ADMIN_KEY_SAFE=0
SESSION_PUBLICKEY_CONFIRMED=0
WILL_DISABLE_PASSWORD_AUTH=0
WILL_DISABLE_ROOT_LOGIN=0
ADMIN_HOME=""
CURRENT_SSH_SOURCE_IP=""
CURRENT_SSH_SOURCE_PORT=""

SSH_ALLOW_CIDRS=()
ALLOW_TCP_PORTS=()
ALLOW_UDP_PORTS=()
SSH_PORTS=()
ADMIN_AUTHORIZED_KEYS_FILES=()

MANAGED_FILES=(
  "/etc/ssh/sshd_config.d/00-hardening.conf"
  "/etc/apt/apt.conf.d/52-hardening-local"
  "/etc/security/pwquality.conf.d/99-hardening.conf"
  "/etc/profile.d/99-hardening-umask.sh"
  "/etc/security/limits.d/99-hardening.conf"
  "/etc/sudoers.d/99-hardening"
  "/etc/logrotate.d/ubuntu-hardening-sudo"
  "/etc/sysctl.d/99-hardening.conf"
  "/etc/systemd/journald.conf.d/99-hardening.conf"
  "/etc/systemd/coredump.conf.d/99-hardening.conf"
  "/etc/rsyslog.d/99-hardening.conf"
  "/etc/audit/rules.d/99-hardening.rules"
  "/etc/fail2ban/jail.d/99-hardening.local"
  "/etc/modprobe.d/99-hardening-blacklist.conf"
)

BACKUP_PATHS=(
  "/etc/ssh/sshd_config"
  "/etc/ssh/sshd_config.d"
  "/etc/apt/apt.conf.d"
  "/etc/default/ufw"
  "/etc/ufw"
  "/etc/security"
  "/etc/pam.d"
  "/etc/login.defs"
  "/etc/sudoers"
  "/etc/sudoers.d"
  "/etc/logrotate.d"
  "/etc/sysctl.conf"
  "/etc/sysctl.d"
  "/etc/systemd/journald.conf"
  "/etc/systemd/journald.conf.d"
  "/etc/systemd/coredump.conf"
  "/etc/systemd/coredump.conf.d"
  "/etc/rsyslog.conf"
  "/etc/rsyslog.d"
  "/etc/audit"
  "/etc/fail2ban"
  "/etc/modprobe.d"
  "/etc/passwd"
  "/etc/passwd-"
  "/etc/group"
  "/etc/group-"
  "/etc/shadow"
  "/etc/shadow-"
  "/etc/gshadow"
  "/etc/gshadow-"
  "/boot/grub/grub.cfg"
)

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_BOLD=$'\033[1m'
  C_RESET=$'\033[0m'
else
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi

log()  { printf '%s[%s]%s %s\n' "$C_BLUE" "INFO" "$C_RESET" "$*"; }
pass() { printf '%s[%s]%s %s\n' "$C_GREEN" "PASS" "$C_RESET" "$*"; }
warn() { printf '%s[%s]%s %s\n' "$C_YELLOW" "WARN" "$C_RESET" "$*" >&2; }
fail() { printf '%s[%s]%s %s\n' "$C_RED" "FAIL" "$C_RESET" "$*" >&2; }
die()  { fail "$*"; exit 1; }

on_error() {
  local line="$1" command="$2" status="$3"
  fail "Stage '${CURRENT_STAGE}' failed at line ${line} (exit ${status}): ${command}"
  if [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]; then
    warn "A pre-change backup exists at: $BACKUP_DIR"
    warn "After diagnosing the failure, rollback with: sudo $SCRIPT_NAME --rollback '$BACKUP_DIR'"
  fi
  exit "$status"
}
trap 'status=$?; on_error "$LINENO" "$BASH_COMMAND" "$status"' ERR

usage() {
  cat <<USAGE
${C_BOLD}Ubuntu Server 24.04 LTS hardening utility v${SCRIPT_VERSION}${C_RESET}

Usage:
  sudo ./${SCRIPT_NAME} --audit
  sudo ./${SCRIPT_NAME} --dry-run [options]
  sudo ./${SCRIPT_NAME} --apply [options]
  sudo ./${SCRIPT_NAME} --rollback latest|/var/backups/ubuntu-hardening/TIMESTAMP

Modes (choose exactly one):
  --audit                         Inspect the current posture; make no changes (default).
  --dry-run                       Validate inputs and show the intended changes.
  --apply                         Back up the system and apply selected controls.
  --rollback PATH                 Restore backed-up configuration and prior service states.

SSH safety:
  --admin-user USER               Non-root sudo user used for lockout checks.
  --disable-password-auth         Require a valid local SSH key for USER, then disable
                                  SSH password and keyboard-interactive authentication.
  --preserve-password-auth        Never change the effective SSH password-auth policy.
  --disable-ssh-forwarding        Set DisableForwarding=yes (can break tunnels/agent use).
  --no-ssh-hardening              Do not install the managed OpenSSH drop-in.

Firewall exposure:
  --ssh-allow-cidr CIDR           Restrict SSH to this source CIDR; repeat as needed.
  --allow-tcp PORTS               Comma-separated inbound TCP ports, e.g. 80,443.
  --allow-udp PORTS               Comma-separated inbound UDP ports, e.g. 51820.
  --no-ufw                        Do not configure or enable UFW.

Modules and maintenance:
  --upgrade                       Apply currently available package upgrades now.
  --no-unattended-upgrades        Do not enable daily unattended security updates.
  --auto-reboot HH:MM             Permit unattended-upgrades to reboot at this local time.
  --no-fail2ban                   Do not configure Fail2ban for SSH.
  --no-auditd                     Do not configure Linux Audit.
  --audit-immutable               End audit rules with -e 2 (cannot change until reboot).
  --no-apparmor                   Do not enable/reload AppArmor.
  --no-pwquality                  Do not configure PAM password-quality checks.
  --keep-coredumps                Preserve systemd coredump collection.
  --with-aide                     Initialize AIDE and enable its daily timer.
  --strict-rpf                    Use strict rp_filter=1 instead of compatible loose mode=2.
  --strict-modules                Block uncommon filesystems/protocol modules on next load.
  --force                         Override environment/conflict guards; never overrides
                                  invalid ports, invalid CIDRs, or missing SSH-key safety.
  -h, --help                      Show this help.

Safe first run:
  sudo ./${SCRIPT_NAME} --audit
  sudo ./${SCRIPT_NAME} --dry-run --admin-user deploy --allow-tcp 80,443
  sudo ./${SCRIPT_NAME} --apply --admin-user deploy --allow-tcp 80,443

Key-only SSH after confirming a second key-based session works:
  sudo ./${SCRIPT_NAME} --apply --admin-user deploy \\
    --disable-password-auth --ssh-allow-cidr 203.0.113.4/32 --allow-tcp 80,443
USAGE
}

set_mode() {
  local requested="$1"
  if (( MODE_SET )) && [[ "$MODE" != "$requested" ]]; then
    die "Choose only one mode: --audit, --dry-run, --apply, or --rollback."
  fi
  MODE="$requested"
  MODE_SET=1
}

append_csv_ports() {
  local csv="$1" array_name="$2" item
  local -a items=()
  IFS=',' read -r -a items <<< "$csv"
  for item in "${items[@]}"; do
    item="${item//[[:space:]]/}"
    [[ -n "$item" ]] || die "An empty port was supplied in '$csv'."
    [[ "$item" =~ ^[0-9]+$ ]] || die "Invalid port '$item'."
    local numeric_port
    numeric_port=$((10#$item))
    (( numeric_port >= 1 && numeric_port <= 65535 )) || die "Port '$item' is outside 1-65535."
    if [[ "$array_name" == "tcp" ]]; then
      ALLOW_TCP_PORTS+=("$numeric_port")
    else
      ALLOW_UDP_PORTS+=("$numeric_port")
    fi
  done
}

while (( $# > 0 )); do
  case "$1" in
    --audit) set_mode audit ;;
    --dry-run) set_mode dry-run ;;
    --apply) set_mode apply ;;
    --rollback)
      set_mode rollback
      shift
      (( $# > 0 )) || die "--rollback requires 'latest' or a backup directory."
      ROLLBACK_TARGET="$1"
      ;;
    --admin-user)
      shift; (( $# > 0 )) || die "--admin-user requires a username."
      ADMIN_USER="$1"
      ;;
    --disable-password-auth) PASSWORD_POLICY="disable" ;;
    --preserve-password-auth) PASSWORD_POLICY="preserve" ;;
    --disable-ssh-forwarding) DISABLE_SSH_FORWARDING=1 ;;
    --no-ssh-hardening) ENABLE_SSH_HARDENING=0 ;;
    --ssh-allow-cidr)
      shift; (( $# > 0 )) || die "--ssh-allow-cidr requires a CIDR."
      SSH_ALLOW_CIDRS+=("$1")
      ;;
    --allow-tcp)
      shift; (( $# > 0 )) || die "--allow-tcp requires comma-separated ports."
      append_csv_ports "$1" tcp
      ;;
    --allow-udp)
      shift; (( $# > 0 )) || die "--allow-udp requires comma-separated ports."
      append_csv_ports "$1" udp
      ;;
    --upgrade) UPGRADE_SYSTEM=1 ;;
    --skip-upgrade) UPGRADE_SYSTEM=0 ;;
    --no-unattended-upgrades) ENABLE_UNATTENDED=0 ;;
    --auto-reboot)
      shift; (( $# > 0 )) || die "--auto-reboot requires HH:MM."
      AUTO_REBOOT=1
      AUTO_REBOOT_TIME="$1"
      ;;
    --no-ufw) ENABLE_UFW=0 ;;
    --no-fail2ban) ENABLE_FAIL2BAN=0 ;;
    --no-auditd) ENABLE_AUDITD=0 ;;
    --audit-immutable) AUDIT_IMMUTABLE=1 ;;
    --no-apparmor) ENABLE_APPARMOR=0 ;;
    --no-pwquality) ENABLE_PWQUALITY=0 ;;
    --keep-coredumps) DISABLE_COREDUMPS=0 ;;
    --with-aide) WITH_AIDE=1 ;;
    --strict-rpf) STRICT_RPF=1 ;;
    --strict-modules) STRICT_MODULES=1 ;;
    --force) FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

setup_logging() {
  # Audit and dry-run are strictly read-only, including their logging behavior.
  if (( EUID == 0 )) && [[ "$MODE" == "apply" || "$MODE" == "rollback" ]]; then
    LOG_FILE="$DEFAULT_LOG_FILE"
    [[ -d "$(dirname "$LOG_FILE")" ]] || install -d -m 0755 -o root -g root "$(dirname "$LOG_FILE")"
    [[ ! -L "$LOG_FILE" ]] || die "Refusing symlinked log file: $LOG_FILE"
    touch "$LOG_FILE"
    chown root:adm "$LOG_FILE"
    chmod 0640 "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
  fi
}

require_root() {
  (( EUID == 0 )) || die "Run this mode as root (for example with sudo)."
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

package_installed() {
  dpkg-query -W -f='${db:Status-Abbrev}' "$1" 2>/dev/null | grep -q '^ii '
}

service_active() {
  systemctl is-active --quiet "$1" 2>/dev/null
}

service_enabled_value() {
  local value
  value="$(systemctl is-enabled "$1" 2>/dev/null || true)"
  [[ -n "$value" ]] || value="disabled"
  printf '%s' "$value"
}

bool_word() {
  if "$@"; then printf 'yes'; else printf 'no'; fi
}

dedupe_array() {
  local array_name="$1" item
  local -n array_ref="$array_name"
  local -a output=()
  local -A seen=()
  for item in "${array_ref[@]}"; do
    if [[ -z "${seen[$item]+x}" ]]; then
      output+=("$item")
      seen["$item"]=1
    fi
  done
  array_ref=("${output[@]}")
}

remove_ssh_ports_from_additional_tcp() {
  (( SSH_SERVER_PRESENT )) || return 0
  local candidate ssh_port matched
  local -a filtered=()
  for candidate in "${ALLOW_TCP_PORTS[@]}"; do
    matched=0
    for ssh_port in "${SSH_PORTS[@]}"; do
      if [[ "$candidate" == "$ssh_port" ]]; then
        matched=1
        warn "TCP port $candidate was also supplied via --allow-tcp; it is ignored there because SSH exposure is managed by the lockout-safe SSH rule."
        break
      fi
    done
    (( matched )) || filtered+=("$candidate")
  done
  ALLOW_TCP_PORTS=("${filtered[@]}")
}

validate_reboot_time() {
  [[ "$AUTO_REBOOT_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || \
    die "Invalid reboot time '$AUTO_REBOOT_TIME'; use 24-hour HH:MM."
}

normalize_cidr() {
  local cidr="$1"
  command_exists python3 || die "python3 is required to validate CIDRs."
  python3 - "$cidr" <<'PY'
import ipaddress
import sys
try:
    print(ipaddress.ip_network(sys.argv[1], strict=False))
except ValueError as exc:
    print(exc, file=sys.stderr)
    raise SystemExit(1)
PY
}

ip_in_any_cidr() {
  local ip="$1"
  shift
  python3 - "$ip" "$@" <<'PY'
import ipaddress
import sys
try:
    address = ipaddress.ip_address(sys.argv[1])
    networks = [ipaddress.ip_network(value, strict=False) for value in sys.argv[2:]]
except ValueError:
    raise SystemExit(2)
raise SystemExit(0 if any(address in network for network in networks) else 1)
PY
}

validate_options() {
  local index normalized
  for index in "${!SSH_ALLOW_CIDRS[@]}"; do
    if ! normalized="$(normalize_cidr "${SSH_ALLOW_CIDRS[$index]}")"; then
      die "Invalid CIDR: ${SSH_ALLOW_CIDRS[$index]}"
    fi
    SSH_ALLOW_CIDRS[$index]="$normalized"
  done
  dedupe_array SSH_ALLOW_CIDRS
  dedupe_array ALLOW_TCP_PORTS
  dedupe_array ALLOW_UDP_PORTS
  validate_reboot_time

  if [[ "$PASSWORD_POLICY" == "disable" ]] && (( ! ENABLE_SSH_HARDENING )); then
    die "--disable-password-auth cannot be combined with --no-ssh-hardening."
  fi
  if (( AUTO_REBOOT && ! ENABLE_UNATTENDED )); then
    die "--auto-reboot requires unattended-upgrades to remain enabled."
  fi
  if (( AUDIT_IMMUTABLE && ! ENABLE_AUDITD )); then
    die "--audit-immutable requires auditd to remain enabled."
  fi
  if (( ${#SSH_ALLOW_CIDRS[@]} > 0 && ! ENABLE_UFW )); then
    warn "SSH CIDRs were supplied, but UFW is disabled; the CIDRs will not be enforced."
  fi
}

detect_environment() {
  CURRENT_STAGE="environment detection"
  [[ -r /etc/os-release ]] || die "/etc/os-release is missing."
  # shellcheck disable=SC1091
  source /etc/os-release

  local os_ok=0
  if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == 24.04* ]]; then os_ok=1; fi
  if (( ! os_ok )); then
    if (( FORCE )); then
      warn "This is designed for Ubuntu 24.04 LTS; detected ${PRETTY_NAME:-unknown}. Continuing because --force was used."
    else
      die "This script supports Ubuntu Server 24.04 LTS only; detected ${PRETTY_NAME:-unknown}."
    fi
  fi

  if grep -qiE '(microsoft|wsl)' /proc/version /proc/sys/kernel/osrelease 2>/dev/null; then IS_WSL=1; fi
  VIRT_TYPE="$(systemd-detect-virt 2>/dev/null || true)"
  [[ -n "$VIRT_TYPE" ]] || VIRT_TYPE="none"

  case "$VIRT_TYPE" in
    docker|lxc|lxc-libvirt|openvz|podman|systemd-nspawn|container-other)
      if (( ! FORCE )); then
        die "Container environment '$VIRT_TYPE' detected. Harden the host/image instead, or review and rerun with --force."
      fi
      warn "Container environment '$VIRT_TYPE' detected; several kernel, audit, firewall, and systemd controls may be unavailable."
      ;;
  esac

  if (( IS_WSL )); then
    if (( ! FORCE )); then die "WSL detected. This server hardening profile is not appropriate for WSL; use --force only after review."; fi
    warn "WSL detected; firewall, kernel, audit, and service behavior differs from a normal Ubuntu server."
  fi

  if package_installed ubuntu-desktop-minimal || package_installed ubuntu-desktop; then
    IS_DESKTOP=1
    if (( ! FORCE )); then
      die "Ubuntu Desktop packages are installed. This profile targets servers; review and rerun with --force if intentional."
    fi
    warn "Desktop packages detected; X11 forwarding, coredump, firewall, and umask changes may affect desktop workflows."
  fi

  [[ "$(ps -p 1 -o comm= 2>/dev/null | xargs)" == "systemd" ]] || {
    if (( FORCE )); then warn "PID 1 is not systemd; service-management steps may fail."; else die "PID 1 is not systemd."; fi
  }
}

collect_ssh_session() {
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    local -a fields=()
    IFS=' ' read -r -a fields <<< "$SSH_CONNECTION"
    if (( ${#fields[@]} >= 4 )); then
      CURRENT_SSH_SOURCE_IP="${fields[0]}"
      CURRENT_SSH_SOURCE_PORT="${fields[1]}"
    fi
  fi
}

valid_authorized_keys_file() {
  local file="$1"
  [[ -f "$file" && ! -L "$file" ]] || return 1
  [[ -s "$file" ]] || return 1
  if command_exists ssh-keygen && ssh-keygen -l -f "$file" >/dev/null 2>&1; then
    return 0
  fi
  awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^(ssh-ed25519|sk-ssh-ed25519@openssh.com|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh.com|rsa-sha2-(256|512)|ssh-rsa)$/) found=1
      }
    }
    END { exit(found ? 0 : 1) }
  ' "$file"
}

expand_authorized_keys_path() {
  local raw="$1" user="$2" home="$3" uid="$4" expanded
  expanded="${raw//%%/__PERCENT__}"
  expanded="${expanded//%h/$home}"
  expanded="${expanded//%u/$user}"
  expanded="${expanded//%U/$uid}"
  expanded="${expanded//__PERCENT__/%}"
  if [[ "$expanded" != /* ]]; then expanded="$home/$expanded"; fi
  printf '%s\n' "$expanded"
}

collect_authorized_keys_files() {
  local user="$1" home="$2" uid="$3" line token expanded
  local -a configured=()
  ADMIN_AUTHORIZED_KEYS_FILES=()

  if (( SSH_SERVER_PRESENT )); then
    line="$(/usr/sbin/sshd -T -C "user=$user,host=$(hostname -f 2>/dev/null || hostname),addr=${CURRENT_SSH_SOURCE_IP:-127.0.0.1}" 2>/dev/null | awk '$1=="authorizedkeysfile" {$1=""; sub(/^ /, ""); print; exit}')"
  else
    line=""
  fi
  [[ -n "$line" ]] || line=".ssh/authorized_keys .ssh/authorized_keys2"
  IFS=' ' read -r -a configured <<< "$line"

  for token in "${configured[@]}"; do
    expanded="$(expand_authorized_keys_path "$token" "$user" "$home" "$uid")"
    if valid_authorized_keys_file "$expanded"; then
      ADMIN_AUTHORIZED_KEYS_FILES+=("$expanded")
    fi
  done
  dedupe_array ADMIN_AUTHORIZED_KEYS_FILES
}

admin_key_paths_fixable() {
  local file owner parent parent_owner home_owner
  home_owner="$(stat -c '%U' "$ADMIN_HOME" 2>/dev/null || true)"
  if [[ "$home_owner" != "$ADMIN_USER" && "$home_owner" != "root" ]]; then
    warn "Admin home '$ADMIN_HOME' is owned by '$home_owner'; SSH key safety cannot be guaranteed."
    return 1
  fi
  for file in "${ADMIN_AUTHORIZED_KEYS_FILES[@]}"; do
    owner="$(stat -c '%U' "$file" 2>/dev/null || true)"
    parent="$(dirname "$file")"
    parent_owner="$(stat -c '%U' "$parent" 2>/dev/null || true)"
    if [[ "$owner" != "$ADMIN_USER" && "$owner" != "root" ]]; then
      warn "AuthorizedKeysFile '$file' has unsafe owner '$owner'."
      return 1
    fi
    if [[ "$parent_owner" != "$ADMIN_USER" && "$parent_owner" != "root" ]]; then
      warn "AuthorizedKeysFile directory '$parent' has unsafe owner '$parent_owner'."
      return 1
    fi
    if [[ "$file" == "$ADMIN_HOME"/* ]]; then
      if [[ -L "$parent" ]]; then warn "SSH key directory '$parent' is a symlink."; return 1; fi
    elif find "$parent" -maxdepth 0 -perm /022 -print -quit | grep -q .; then
      warn "Global AuthorizedKeysFile directory '$parent' is group/world writable."
      return 1
    fi
  done
  return 0
}

confirm_current_publickey_session() {
  (( SSH_SERVER_PRESENT )) || return 1
  [[ -n "$CURRENT_SSH_SOURCE_IP" && -n "$CURRENT_SSH_SOURCE_PORT" ]] || return 1
  [[ -n "$ADMIN_USER" ]] || return 1
  [[ "${SUDO_USER:-}" == "$ADMIN_USER" || "${USER:-}" == "$ADMIN_USER" || "${LOGNAME:-}" == "$ADMIN_USER" ]] || return 1
  command_exists journalctl || return 1

  local needle="Accepted publickey for ${ADMIN_USER} from ${CURRENT_SSH_SOURCE_IP} port ${CURRENT_SSH_SOURCE_PORT}"
  journalctl --since '-24 hours' _COMM=sshd --no-pager -o cat 2>/dev/null | grep -Fq "$needle"
}

resolve_admin_and_ssh_safety() {
  CURRENT_STAGE="SSH lockout preflight"
  SSH_SERVER_PRESENT=0
  SSH_PORTS=()
  collect_ssh_session

  if [[ -x /usr/sbin/sshd && -f /etc/ssh/sshd_config ]]; then
    SSH_SERVER_PRESENT=1
    if ! /usr/sbin/sshd -t; then
      die "The existing OpenSSH server configuration is invalid. Fix 'sshd -t' before hardening."
    fi
    mapfile -t SSH_PORTS < <(/usr/sbin/sshd -T 2>/dev/null | awk '$1=="port" && $2 ~ /^[0-9]+$/ {print $2}' | sort -n -u)
    (( ${#SSH_PORTS[@]} > 0 )) || SSH_PORTS=(22)
    remove_ssh_ports_from_additional_tcp
  fi

  if [[ -z "$ADMIN_USER" && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    ADMIN_USER="$SUDO_USER"
  fi

  ADMIN_KEY_SAFE=0
  SESSION_PUBLICKEY_CONFIRMED=0
  WILL_DISABLE_PASSWORD_AUTH=0
  WILL_DISABLE_ROOT_LOGIN=0

  if [[ -n "$ADMIN_USER" ]]; then
    id "$ADMIN_USER" >/dev/null 2>&1 || die "Admin user '$ADMIN_USER' does not exist."
    [[ "$ADMIN_USER" != "root" ]] || die "--admin-user must be a non-root account."

    local shell uid
    shell="$(getent passwd "$ADMIN_USER" | awk -F: '{print $7}')"
    uid="$(id -u "$ADMIN_USER")"
    ADMIN_HOME="$(getent passwd "$ADMIN_USER" | awk -F: '{print $6}')"
    [[ -n "$ADMIN_HOME" && -d "$ADMIN_HOME" ]] || die "Admin user '$ADMIN_USER' has no usable home directory."
    [[ "$shell" != */nologin && "$shell" != */false ]] || die "Admin user '$ADMIN_USER' has a non-login shell: $shell"

    if ! id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qx sudo; then
      die "Admin user '$ADMIN_USER' is not a member of the sudo group."
    fi

    collect_authorized_keys_files "$ADMIN_USER" "$ADMIN_HOME" "$uid"
    if (( ${#ADMIN_AUTHORIZED_KEYS_FILES[@]} > 0 )) && admin_key_paths_fixable; then
      ADMIN_KEY_SAFE=1
    fi

    if confirm_current_publickey_session; then
      SESSION_PUBLICKEY_CONFIRMED=1
    fi
  fi

  case "$PASSWORD_POLICY" in
    preserve)
      WILL_DISABLE_PASSWORD_AUTH=0
      ;;
    disable)
      (( SSH_SERVER_PRESENT )) || die "--disable-password-auth was requested, but OpenSSH server is not installed."
      (( ADMIN_KEY_SAFE )) || die "Refusing key-only SSH: '$ADMIN_USER' lacks a valid local AuthorizedKeysFile and sudo access."
      WILL_DISABLE_PASSWORD_AUTH=1
      WILL_DISABLE_ROOT_LOGIN=1
      if (( ! SESSION_PUBLICKEY_CONFIRMED )); then
        warn "A current public-key login could not be confirmed in the SSH journal. Proceeding only because --disable-password-auth was explicit."
      fi
      ;;
    auto)
      if (( ADMIN_KEY_SAFE && SESSION_PUBLICKEY_CONFIRMED )); then
        WILL_DISABLE_PASSWORD_AUTH=1
        WILL_DISABLE_ROOT_LOGIN=1
      else
        WILL_DISABLE_PASSWORD_AUTH=0
        WILL_DISABLE_ROOT_LOGIN=0
      fi
      ;;
  esac

  if (( SSH_SERVER_PRESENT && ENABLE_SSH_HARDENING )); then
    if (( WILL_DISABLE_PASSWORD_AUTH )); then
      pass "Key-only SSH is eligible for '$ADMIN_USER'; a valid sudo account and AuthorizedKeysFile were found."
    else
      warn "SSH password policy will be preserved. Use --disable-password-auth only after testing key login for a non-root sudo user."
    fi
  fi
}

check_ssh_cidr_lockout() {
  (( ENABLE_UFW )) || return 0
  (( ${#SSH_ALLOW_CIDRS[@]} > 0 )) || return 0
  [[ -n "$CURRENT_SSH_SOURCE_IP" ]] || return 0

  if ! ip_in_any_cidr "$CURRENT_SSH_SOURCE_IP" "${SSH_ALLOW_CIDRS[@]}"; then
    if (( FORCE )); then
      warn "Current SSH source $CURRENT_SSH_SOURCE_IP is outside every supplied SSH CIDR; continuing because --force was used."
    else
      die "Current SSH source $CURRENT_SSH_SOURCE_IP is outside every --ssh-allow-cidr. Refusing a likely lockout."
    fi
  fi
}

preflight_conflicts() {
  CURRENT_STAGE="conflict detection"
  if (( ENABLE_UFW )) && service_active firewalld.service; then
    if (( FORCE )); then
      warn "firewalld is active. UFW will be configured too because --force was used; overlapping firewall managers are unsafe."
    else
      die "firewalld is active. Do not run UFW and firewalld together; disable one or rerun with --no-ufw."
    fi
  fi
  if (( ENABLE_UFW )) && service_active nftables.service; then
    warn "nftables.service is active. Existing custom rules may interact with UFW; review the resulting ruleset."
  fi
  if service_active docker.service || service_active containerd.service || service_active kubelet.service; then
    warn "A container runtime/orchestrator is active. Published container ports can bypass or interact unexpectedly with host UFW policy."
  fi
  if (( ENABLE_PWQUALITY )) && (service_active sssd.service || service_active winbind.service); then
    warn "SSSD or Winbind is active. The local PAM pwquality profile can affect domain password-change workflows; use --no-pwquality unless the identity design has been tested."
  fi
}

acquire_lock() {
  install -d -m 0755 /run/lock
  # shellcheck disable=SC3045
  exec {LOCK_FD}>/run/lock/ubuntu-hardening.lock
  flock -n "$LOCK_FD" || die "Another hardening process is already running."
}

record_state_value() {
  local key="$1" value="$2" file="$3"
  [[ "$key" =~ ^[A-Z0-9_]+$ ]] || die "Invalid backup-state key: $key"
  value="${value//$'\n'/ }"
  value="${value//$'\t'/ }"
  printf '%s\t%s\n' "$key" "$value" >> "$file"
}

state_get() {
  local file="$1" key="$2"
  awk -F '\t' -v wanted="$key" '$1 == wanted { sub(/^[^\t]*\t/, ""); print; exit }' "$file"
}

record_service_state() {
  local name="$1" prefix="$2" file="$3"
  record_state_value "${prefix}_ACTIVE" "$(bool_word service_active "$name")" "$file"
  record_state_value "${prefix}_ENABLED" "$(service_enabled_value "$name")" "$file"
}

record_path_metadata() {
  local path="$1" prefix="$2" file="$3"
  if [[ -e "$path" || -L "$path" ]]; then
    record_state_value "${prefix}_EXISTED" yes "$file"
    record_state_value "${prefix}_UID" "$(stat -c '%u' -- "$path")" "$file"
    record_state_value "${prefix}_GID" "$(stat -c '%g' -- "$path")" "$file"
    record_state_value "${prefix}_MODE" "$(stat -c '%a' -- "$path")" "$file"
  else
    record_state_value "${prefix}_EXISTED" no "$file"
    record_state_value "${prefix}_UID" "" "$file"
    record_state_value "${prefix}_GID" "" "$file"
    record_state_value "${prefix}_MODE" "" "$file"
  fi
}

restore_path_metadata() {
  local path="$1" existed="$2" uid="$3" gid="$4" mode="$5"
  if [[ "$existed" == "yes" ]]; then
    if [[ -e "$path" && ! -L "$path" && "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{3,4}$ ]]; then
      chown "$uid:$gid" -- "$path" || warn "Could not restore ownership on $path."
      chmod "$mode" -- "$path" || warn "Could not restore mode on $path."
    else
      warn "Could not fully restore saved metadata for $path."
    fi
  elif [[ -e "$path" || -L "$path" ]]; then
    # Do not delete security logs created after hardening; retaining evidence is safer.
    log "Retaining newly created path from the hardening period: $path"
  fi
}

save_runtime_sysctls() {
  local output="$1" key iface_path iface
  local -a keys=(
    kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict
    kernel.yama.ptrace_scope kernel.perf_event_paranoid kernel.sysrq
    fs.suid_dumpable fs.protected_hardlinks fs.protected_symlinks
    fs.protected_fifos fs.protected_regular
    net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses
    net.ipv4.tcp_syncookies net.ipv4.tcp_rfc1337
  )
  : > "$output"
  chmod 0600 "$output"
  for iface_path in /proc/sys/net/ipv4/conf/*; do
    [[ -d "$iface_path" ]] || continue
    iface="${iface_path##*/}"
    keys+=(
      "net.ipv4.conf.${iface}.accept_source_route"
      "net.ipv4.conf.${iface}.accept_redirects"
      "net.ipv4.conf.${iface}.secure_redirects"
      "net.ipv4.conf.${iface}.send_redirects"
      "net.ipv4.conf.${iface}.log_martians"
      "net.ipv4.conf.${iface}.rp_filter"
    )
  done
  for iface_path in /proc/sys/net/ipv6/conf/*; do
    [[ -d "$iface_path" ]] || continue
    iface="${iface_path##*/}"
    keys+=(
      "net.ipv6.conf.${iface}.accept_source_route"
      "net.ipv6.conf.${iface}.accept_redirects"
    )
  done
  for key in "${keys[@]}"; do
    if [[ -e "/proc/sys/${key//./\/}" ]]; then
      printf '%s\t%s\n' "$key" "$(sysctl -n "$key" 2>/dev/null || true)" >> "$output"
    fi
  done
}

create_admin_ssh_metadata_backup() {
  local output="$1" key item rel
  local -a paths=() relative=()
  local -A seen=()
  (( ADMIN_KEY_SAFE )) || return 0
  paths+=("$ADMIN_HOME")
  for key in "${ADMIN_AUTHORIZED_KEYS_FILES[@]}"; do
    paths+=("$(dirname "$key")" "$key")
  done
  for item in "${paths[@]}"; do
    [[ -e "$item" || -L "$item" ]] || continue
    if [[ -z "${seen[$item]+x}" ]]; then
      rel="${item#/}"
      relative+=("$rel")
      seen["$item"]=1
    fi
  done
  (( ${#relative[@]} > 0 )) || return 0
  tar --no-recursion --acls --xattrs --numeric-owner -C / -cpf "$output" "${relative[@]}"
  chmod 0600 "$output"
}

create_backup() {
  CURRENT_STAGE="transactional backup"
  local stamp state_file archive path rel
  local -a existing=() relative=() checksum_files=()
  stamp="$(date -u +'%Y%m%dT%H%M%SZ')-${BASHPID}"
  install -d -m 0700 -o root -g root "$BACKUP_ROOT"
  BACKUP_DIR="$BACKUP_ROOT/$stamp"
  [[ ! -e "$BACKUP_DIR" ]] || die "Backup directory already exists: $BACKUP_DIR"
  install -d -m 0700 -o root -g root "$BACKUP_DIR"
  state_file="$BACKUP_DIR/state.tsv"
  : > "$state_file"
  chmod 0600 "$state_file"

  record_state_value SCRIPT_VERSION "$SCRIPT_VERSION" "$state_file"
  record_state_value CREATED_UTC "$(date -u --iso-8601=seconds)" "$state_file"
  record_state_value HOSTNAME "$(hostname)" "$state_file"
  record_state_value UFW_ACTIVE "$(if command_exists ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then echo yes; else echo no; fi)" "$state_file"

  record_state_value PKG_UFW "$(bool_word package_installed ufw)" "$state_file"
  record_state_value PKG_FAIL2BAN "$(bool_word package_installed fail2ban)" "$state_file"
  record_state_value PKG_AUDITD "$(bool_word package_installed auditd)" "$state_file"
  record_state_value PKG_APPARMOR "$(bool_word package_installed apparmor)" "$state_file"
  record_state_value PKG_RSYSLOG "$(bool_word package_installed rsyslog)" "$state_file"
  record_state_value PKG_AIDE "$(bool_word package_installed aide)" "$state_file"

  record_service_state fail2ban.service FAIL2BAN "$state_file"
  record_service_state auditd.service AUDITD "$state_file"
  record_service_state apparmor.service APPARMOR "$state_file"
  record_service_state rsyslog.service RSYSLOG "$state_file"
  record_service_state apt-daily.timer APT_DAILY "$state_file"
  record_service_state apt-daily-upgrade.timer APT_DAILY_UPGRADE "$state_file"
  record_service_state dailyaidecheck.timer AIDE_TIMER "$state_file"
  record_path_metadata /var/log/journal VAR_LOG_JOURNAL "$state_file"
  record_path_metadata /var/log/sudo.log SUDO_LOG "$state_file"

  : > "$BACKUP_DIR/audit-rules-before.txt"
  chmod 0600 "$BACKUP_DIR/audit-rules-before.txt"
  if command_exists auditctl && auditctl -s >/dev/null 2>&1; then
    record_state_value AUDIT_KERNEL_ENABLED "$(auditctl -s 2>/dev/null | awk '$1=="enabled" {print $2; exit}')" "$state_file"
    auditctl -l > "$BACKUP_DIR/audit-rules-before.txt" 2>/dev/null || true
  else
    record_state_value AUDIT_KERNEL_ENABLED unavailable "$state_file"
  fi

  printf '%s\n' "${MANAGED_FILES[@]}" > "$BACKUP_DIR/managed-files.txt"
  chmod 0600 "$BACKUP_DIR/managed-files.txt"
  dpkg-query -W -f='${binary:Package}\t${Version}\n' > "$BACKUP_DIR/packages-before.tsv" 2>/dev/null || true
  chmod 0600 "$BACKUP_DIR/packages-before.tsv"
  save_runtime_sysctls "$BACKUP_DIR/sysctl-before.tsv"
  create_admin_ssh_metadata_backup "$BACKUP_DIR/admin-ssh-metadata.tar"

  for path in "${BACKUP_PATHS[@]}"; do
    if [[ -e "$path" || -L "$path" ]]; then
      existing+=("$path")
      rel="${path#/}"
      relative+=("$rel")
    fi
  done
  printf '%s\n' "${existing[@]}" > "$BACKUP_DIR/paths.txt"
  chmod 0600 "$BACKUP_DIR/paths.txt"

  archive="$BACKUP_DIR/config.tar"
  if (( ${#relative[@]} > 0 )); then
    tar --acls --xattrs --numeric-owner -C / -cpf "$archive" "${relative[@]}"
  else
    tar -C / -cpf "$archive" --files-from /dev/null
  fi
  chmod 0600 "$archive"
  checksum_files=(config.tar state.tsv managed-files.txt packages-before.tsv sysctl-before.tsv paths.txt audit-rules-before.txt)
  [[ -f "$BACKUP_DIR/admin-ssh-metadata.tar" ]] && checksum_files+=(admin-ssh-metadata.tar)
  (
    cd "$BACKUP_DIR"
    sha256sum "${checksum_files[@]}" > SHA256SUMS
    chmod 0600 SHA256SUMS
  )

  ln -sfnT "$stamp" "$BACKUP_ROOT/latest"
  pass "Configuration backup created: $BACKUP_DIR"
}

write_file() {
  local path="$1" mode="$2" owner="$3" group="$4" tmp
  [[ -d "$(dirname "$path")" ]] || install -d -m 0755 -o root -g root "$(dirname "$path")"
  [[ ! -L "$path" ]] || die "Refusing to replace symlinked managed file: $path"
  tmp="$(mktemp "${path}.tmp.XXXXXX")"
  cat > "$tmp"
  chown "$owner:$group" "$tmp"
  chmod "$mode" "$tmp"

  if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"
    log "Unchanged: $path"
  else
    mv -f "$tmp" "$path"
    log "Updated: $path"
  fi
}

remove_our_managed_file() {
  local path="$1"
  if [[ -L "$path" ]]; then
    die "Refusing to remove symlinked managed path: $path"
  elif [[ -f "$path" ]]; then
    if grep -Fqs 'Managed by ubuntu-24.04-hardening.sh' "$path"; then
      rm -f -- "$path"
      log "Removed this script's managed file: $path"
    else
      warn "Preserving $path because it does not contain this script's ownership marker."
    fi
  fi
}

set_equals_key() {
  local file="$1" key="$2" value="$3" mode="${4:-0640}" owner="${5:-root}" group="${6:-root}"
  local tmp
  [[ -f "$file" ]] || touch "$file"
  tmp="$(mktemp "${file}.tmp.XXXXXX")"
  awk -v key="$key" -v value="$value" '
    BEGIN { done=0 }
    $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      if (!done) print key " = " value
      done=1
      next
    }
    { print }
    END { if (!done) print key " = " value }
  ' "$file" > "$tmp"
  chown "$owner:$group" "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$file"
}

set_shell_key() {
  local file="$1" key="$2" value="$3" mode="${4:-0644}" owner="${5:-root}" group="${6:-root}"
  local tmp
  [[ -f "$file" ]] || touch "$file"
  tmp="$(mktemp "${file}.tmp.XXXXXX")"
  awk -v key="$key" -v value="$value" '
    BEGIN { done=0 }
    $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      if (!done) print key "=" value
      done=1
      next
    }
    { print }
    END { if (!done) print key "=" value }
  ' "$file" > "$tmp"
  chown "$owner:$group" "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$file"
}

set_space_key() {
  local file="$1" key="$2" value="$3" mode="${4:-0644}" owner="${5:-root}" group="${6:-root}"
  local tmp
  [[ -f "$file" ]] || touch "$file"
  tmp="$(mktemp "${file}.tmp.XXXXXX")"
  awk -v key="$key" -v value="$value" '
    BEGIN { done=0 }
    $0 ~ "^[[:space:]]*" key "([[:space:]]+|$)" {
      if (!done) print key "\t" value
      done=1
      next
    }
    { print }
    END { if (!done) print key "\t" value }
  ' "$file" > "$tmp"
  chown "$owner:$group" "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$file"
}

install_packages() {
  CURRENT_STAGE="security package installation"
  local -a packages=(python3-minimal needrestart rsyslog logrotate)
  (( ENABLE_UFW )) && packages+=(ufw)
  (( ENABLE_FAIL2BAN )) && packages+=(fail2ban python3-systemd)
  (( ENABLE_AUDITD )) && packages+=(auditd audispd-plugins)
  (( ENABLE_APPARMOR )) && packages+=(apparmor apparmor-utils)
  (( ENABLE_UNATTENDED )) && packages+=(unattended-upgrades)
  (( ENABLE_PWQUALITY )) && packages+=(libpam-pwquality)
  (( WITH_AIDE )) && packages+=(aide aide-common)
  dedupe_array packages

  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a
  apt-get -o Acquire::Retries=3 update
  apt-get -y -o Acquire::Retries=3 \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    install --no-install-recommends "${packages[@]}"

  if (( UPGRADE_SYSTEM )); then
    CURRENT_STAGE="system package upgrade"
    apt-get -y -o Acquire::Retries=3 \
      -o Dpkg::Options::="--force-confdef" \
      -o Dpkg::Options::="--force-confold" upgrade
  fi
}

fix_admin_key_permissions() {
  (( ADMIN_KEY_SAFE )) || return 0
  local file owner parent parent_owner home_owner
  home_owner="$(stat -c '%U' "$ADMIN_HOME")"
  if [[ "$home_owner" != "$ADMIN_USER" && "$home_owner" != "root" ]]; then
    die "Unsafe owner '$home_owner' on admin home '$ADMIN_HOME'. Expected '$ADMIN_USER' or root."
  fi
  chmod go-w "$ADMIN_HOME"

  for file in "${ADMIN_AUTHORIZED_KEYS_FILES[@]}"; do
    owner="$(stat -c '%U' "$file")"
    if [[ "$owner" != "$ADMIN_USER" && "$owner" != "root" ]]; then
      die "Unsafe owner '$owner' on AuthorizedKeysFile '$file'. Expected '$ADMIN_USER' or root."
    fi
    parent="$(dirname "$file")"
    parent_owner="$(stat -c '%U' "$parent")"
    if [[ "$parent_owner" != "$ADMIN_USER" && "$parent_owner" != "root" ]]; then
      die "Unsafe owner '$parent_owner' on SSH key directory '$parent'."
    fi

    if [[ "$file" == "$ADMIN_HOME"/* ]]; then
      [[ ! -L "$parent" ]] || die "Refusing symlinked SSH key directory: $parent"
      chmod go-rwx "$parent"
      chmod 0600 "$file"
    else
      if find "$parent" -maxdepth 0 -perm /022 -print -quit | grep -q .; then
        die "Global AuthorizedKeysFile directory is group/world writable: $parent"
      fi
      chmod go-w "$file"
    fi
  done
}

sshd_effective_value() {
  local key="$1" user="${2:-}" addr="${3:-}" host
  host="$(hostname -f 2>/dev/null || hostname)"
  if [[ -n "$user" ]]; then
    /usr/sbin/sshd -T -C "user=${user},host=${host},addr=${addr:-127.0.0.1}" 2>/dev/null |       awk -v key="$key" '$1==key {$1=""; sub(/^ /, ""); print; exit}'
  else
    /usr/sbin/sshd -T 2>/dev/null | awk -v key="$key" '$1==key {$1=""; sub(/^ /, ""); print; exit}'
  fi
}

restore_one_file() {
  local target="$1" saved="$2" existed="$3"
  if (( existed )); then
    cp -a -- "$saved" "$target"
  else
    rm -f -- "$target"
  fi
}

configure_ssh() {
  (( ENABLE_SSH_HARDENING && SSH_SERVER_PRESENT )) || {
    (( ENABLE_SSH_HARDENING )) && warn "OpenSSH server is not installed; SSH hardening was skipped."
    return 0
  }
  CURRENT_STAGE="OpenSSH hardening"
  fix_admin_key_permissions

  local target="/etc/ssh/sshd_config.d/00-hardening.conf"
  local saved existed=0
  saved="$(mktemp)"
  if [[ -e "$target" ]]; then cp -a "$target" "$saved"; existed=1; fi

  {
    cat <<'SSHCONF'
# Managed by ubuntu-24.04-hardening.sh. Local changes may be replaced.
# Ubuntu/OpenSSH defaults select modern algorithms; this file intentionally
# does not pin Ciphers, MACs, KexAlgorithms, or HostKeyAlgorithms.
PubkeyAuthentication yes
PermitEmptyPasswords no
HostbasedAuthentication no
IgnoreRhosts yes
StrictModes yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
PermitUserEnvironment no
PermitTunnel no
GatewayPorts no
Compression no
DebianBanner no
LogLevel VERBOSE
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
UsePAM yes
SSHCONF
    if (( WILL_DISABLE_ROOT_LOGIN )); then printf 'PermitRootLogin no\n'; fi
    if (( WILL_DISABLE_PASSWORD_AUTH )); then
      printf 'PasswordAuthentication no\n'
      printf 'KbdInteractiveAuthentication no\n'
      printf 'AuthenticationMethods publickey\n'
    fi
    if (( DISABLE_SSH_FORWARDING )); then printf 'DisableForwarding yes\n'; fi
  } | write_file "$target" 0644 root root

  if ! /usr/sbin/sshd -t; then
    restore_one_file "$target" "$saved" "$existed"
    rm -f "$saved"
    die "The managed SSH drop-in failed 'sshd -t'; the prior file was restored."
  fi

  local -a expected=(
    "pubkeyauthentication=yes"
    "permitemptypasswords=no"
    "hostbasedauthentication=no"
    "ignorerhosts=yes"
    "strictmodes=yes"
    "maxauthtries=3"
    "logingracetime=30"
    "x11forwarding=no"
    "permituserenvironment=no"
    "permittunnel=no"
    "gatewayports=no"
    "compression=no"
    "debianbanner=no"
    "loglevel=VERBOSE"
    "clientaliveinterval=300"
    "clientalivecountmax=2"
    "usedns=no"
    "usepam=yes"
  )
  (( WILL_DISABLE_ROOT_LOGIN )) && expected+=("permitrootlogin=no")
  if (( WILL_DISABLE_PASSWORD_AUTH )); then
    expected+=("passwordauthentication=no" "kbdinteractiveauthentication=no" "authenticationmethods=publickey")
  fi
  (( DISABLE_SSH_FORWARDING )) && expected+=("disableforwarding=yes")

  local pair key wanted actual context_actual context_user context_addr mismatch=0
  context_user="${ADMIN_USER:-root}"
  context_addr="${CURRENT_SSH_SOURCE_IP:-127.0.0.1}"
  for pair in "${expected[@]}"; do
    key="${pair%%=*}"
    wanted="${pair#*=}"
    actual="$(sshd_effective_value "$key")"
    if [[ "${actual,,}" != "${wanted,,}" ]]; then
      fail "Global SSH setting '$key' is '$actual', expected '$wanted'. The Include order may prevent the drop-in from taking precedence."
      mismatch=1
    fi
    if [[ "$key" == "permitrootlogin" ]]; then context_user="root"; else context_user="${ADMIN_USER:-root}"; fi
    context_actual="$(sshd_effective_value "$key" "$context_user" "$context_addr")"
    if [[ "${context_actual,,}" != "${wanted,,}" ]]; then
      fail "Contextual SSH setting '$key' for user '$context_user' from '$context_addr' is '$context_actual', expected '$wanted'. A Match block may override the baseline."
      mismatch=1
    fi
  done
  if (( mismatch )); then
    restore_one_file "$target" "$saved" "$existed"
    /usr/sbin/sshd -t || true
    rm -f "$saved"
    die "Effective SSH validation failed; the previous drop-in was restored."
  fi
  rm -f "$saved"

  systemctl daemon-reload
  if service_active ssh.service; then
    systemctl reload ssh.service
  elif service_active ssh.socket; then
    log "ssh.socket is active; validated settings will apply to new sshd instances."
  else
    warn "Neither ssh.service nor ssh.socket is active; configuration is valid but was not reloaded."
  fi
  pass "OpenSSH configuration is valid and effective. Keep this session open until a second login is tested."
}

ufw_run() {
  if ! ufw --dry-run "$@" >/dev/null 2>&1; then
    die "UFW rejected command: ufw $*"
  fi
  ufw "$@"
}

configure_ufw() {
  (( ENABLE_UFW )) || return 0
  CURRENT_STAGE="UFW firewall hardening"

  [[ -f /etc/default/ufw ]] && set_shell_key /etc/default/ufw IPV6 yes 0644 root root

  ufw_run default deny incoming
  ufw_run default allow outgoing
  ufw_run default deny routed
  ufw_run logging low

  local port cidr
  if (( SSH_SERVER_PRESENT )); then
    for port in "${SSH_PORTS[@]}"; do
      if (( ${#SSH_ALLOW_CIDRS[@]} > 0 )); then
        for cidr in "${SSH_ALLOW_CIDRS[@]}"; do
          ufw_run prepend allow proto tcp from "$cidr" to any port "$port" comment "hardening-ssh"
        done
      else
        ufw_run prepend limit "${port}/tcp" comment "hardening-ssh"
      fi
    done
  fi

  for port in "${ALLOW_TCP_PORTS[@]}"; do
    ufw_run allow "${port}/tcp" comment "hardening-tcp-${port}"
  done
  for port in "${ALLOW_UDP_PORTS[@]}"; do
    ufw_run allow "${port}/udp" comment "hardening-udp-${port}"
  done

  ufw --dry-run --force enable >/dev/null 2>&1 || die "UFW rejected the enable operation."
  ufw --force enable
  ufw status verbose

  if (( ${#SSH_ALLOW_CIDRS[@]} > 0 )); then
    local broad_ssh=0
    for port in "${SSH_PORTS[@]}"; do
      if ufw status 2>/dev/null | grep -Eq "^${port}/tcp[[:space:]]+ALLOW[[:space:]]+Anywhere([[:space:]]|$)"; then broad_ssh=1; fi
    done
    if ufw status 2>/dev/null | grep -Eq '^OpenSSH[[:space:]]+ALLOW[[:space:]]+Anywhere([[:space:]]|$)'; then broad_ssh=1; fi
    if (( broad_ssh )); then
      warn "A pre-existing broad SSH allow rule still exists. This script preserves existing UFW rules; remove obsolete broad rules manually after review."
    fi
  fi
  pass "UFW is active. SSH was opened before enforcement."
}

configure_fail2ban() {
  (( ENABLE_FAIL2BAN )) || return 0
  CURRENT_STAGE="Fail2ban configuration"
  if (( ! SSH_SERVER_PRESENT )); then
    warn "OpenSSH server is absent; no Fail2ban SSH jail was enabled."
    return 0
  fi

  local ports_csv
  ports_csv="$(IFS=,; echo "${SSH_PORTS[*]}")"
  write_file /etc/fail2ban/jail.d/99-hardening.local 0644 root root <<EOF_F2B
# Managed by ubuntu-24.04-hardening.sh
[DEFAULT]
backend = systemd
bantime = 1h
findtime = 10m
maxretry = 5
usedns = no
ignoreself = true

[sshd]
enabled = true
port = ${ports_csv}
mode = normal
EOF_F2B

  fail2ban-client -t
  systemctl enable fail2ban.service >/dev/null 2>&1 || true
  systemctl restart fail2ban.service
  fail2ban-client ping
  pass "Fail2ban SSH jail is configured on port(s): $ports_csv"
}

configure_unattended_upgrades() {
  (( ENABLE_UNATTENDED )) || return 0
  CURRENT_STAGE="automatic security updates"

  local reboot_word="false"
  (( AUTO_REBOOT )) && reboot_word="true"
  write_file /etc/apt/apt.conf.d/52-hardening-local 0644 root root <<EOF_APT
// Managed by ubuntu-24.04-hardening.sh
// This later drop-in enables periodic jobs without overwriting Ubuntu's
// package-owned 20auto-upgrades file or vendor-maintained Allowed-Origins.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Automatic-Reboot "${reboot_word}";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "${AUTO_REBOOT_TIME}";
EOF_APT

  apt-config dump >/dev/null
  systemctl daemon-reload
  systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null
  if command_exists unattended-upgrade; then
    if ! timeout 180 unattended-upgrade --dry-run >/dev/null 2>&1; then
      warn "unattended-upgrade dry-run did not complete successfully (often caused by another APT lock); timers are still configured."
    fi
  fi
  pass "Daily package-list refresh and unattended upgrades are enabled (automatic reboot: $reboot_word at $AUTO_REBOOT_TIME)."
}

configure_pwquality_and_accounts() {
  CURRENT_STAGE="password and account defaults"
  if (( ENABLE_PWQUALITY )); then
    write_file /etc/security/pwquality.conf.d/99-hardening.conf 0644 root root <<'PWQ'
# Managed by ubuntu-24.04-hardening.sh
# Length-first policy; no mandatory character-class composition rules.
minlen = 15
retry = 3
dictcheck = 1
usercheck = 1
gecoscheck = 1
enforcing = 1
enforce_for_root = 1
PWQ

    pam-auth-update --package --enable pwquality
    if ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' /etc/pam.d/common-password; then
      warn "pam_pwquality is not active in /etc/pam.d/common-password, likely because PAM has local customizations. It was not force-overwritten."
    fi
  fi

  write_file /etc/profile.d/99-hardening-umask.sh 0644 root root <<'UMASK'
# Managed by ubuntu-24.04-hardening.sh
umask 027
UMASK
  if (( DISABLE_COREDUMPS )); then
    write_file /etc/security/limits.d/99-hardening.conf 0644 root root <<'LIMITS'
# Managed by ubuntu-24.04-hardening.sh
*    hard    core    0
root hard    core    0
LIMITS
  else
    remove_our_managed_file /etc/security/limits.d/99-hardening.conf
    log "This script's coredump limits are absent because --keep-coredumps was selected."
  fi

  if [[ -f /etc/login.defs ]]; then
    set_space_key /etc/login.defs UMASK 027 0644 root root
    set_space_key /etc/login.defs HOME_MODE 0750 0644 root root
  fi
  pass "Password quality and restrictive defaults are configured without forced periodic password expiry."
}

configure_sudo() {
  CURRENT_STAGE="sudo policy"
  local target="/etc/sudoers.d/99-hardening" tmp
  tmp="$(mktemp)"
  cat > "$tmp" <<'SUDOERS'
# Managed by ubuntu-24.04-hardening.sh
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults timestamp_timeout=5
Defaults passwd_tries=3
SUDOERS
  chmod 0440 "$tmp"
  chown root:root "$tmp"
  visudo -cf "$tmp" >/dev/null
  write_file "$target" 0440 root root < "$tmp"
  rm -f "$tmp"
  visudo -cf /etc/sudoers >/dev/null
  [[ ! -L /var/log/sudo.log ]] || die "Refusing symlinked sudo log: /var/log/sudo.log"
  touch /var/log/sudo.log
  chown root:adm /var/log/sudo.log
  chmod 0640 /var/log/sudo.log

  write_file /etc/logrotate.d/ubuntu-hardening-sudo 0644 root root <<'LOGROTATE'
# Managed by ubuntu-24.04-hardening.sh
/var/log/sudo.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
LOGROTATE
  if command_exists logrotate; then
    logrotate --debug /etc/logrotate.d/ubuntu-hardening-sudo >/dev/null 2>&1 || die "The sudo logrotate policy failed validation."
  fi
  pass "sudo commands use a PTY and a rotated root-controlled log at /var/log/sudo.log."
}

configure_sysctl() {
  CURRENT_STAGE="kernel and network sysctl hardening"
  local rpf=2
  (( STRICT_RPF )) && rpf=1

  write_file /etc/sysctl.d/99-hardening.conf 0644 root root <<EOF_SYSCTL
# Managed by ubuntu-24.04-hardening.sh
# This intentionally does not disable IPv6, IP forwarding, user namespaces,
# or other facilities whose safety depends on the server's role.
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
kernel.sysrq = 0
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = ${rpf}
net.ipv4.conf.default.rp_filter = ${rpf}
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF_SYSCTL

  if ! sysctl -e -p /etc/sysctl.d/99-hardening.conf >/dev/null; then
    warn "One or more sysctl values could not be applied at runtime; they remain configured for boot and should be reviewed."
  fi

  local iface key
  for iface_path in /proc/sys/net/ipv4/conf/*; do
    [[ -d "$iface_path" ]] || continue
    iface="${iface_path##*/}"
    for key in accept_source_route accept_redirects secure_redirects send_redirects; do
      sysctl -q -w "net.ipv4.conf.${iface}.${key}=0" 2>/dev/null || true
    done
    sysctl -q -w "net.ipv4.conf.${iface}.log_martians=1" 2>/dev/null || true
    sysctl -q -w "net.ipv4.conf.${iface}.rp_filter=${rpf}" 2>/dev/null || true
  done
  for iface_path in /proc/sys/net/ipv6/conf/*; do
    [[ -d "$iface_path" ]] || continue
    iface="${iface_path##*/}"
    sysctl -q -w "net.ipv6.conf.${iface}.accept_source_route=0" 2>/dev/null || true
    sysctl -q -w "net.ipv6.conf.${iface}.accept_redirects=0" 2>/dev/null || true
  done
  pass "Kernel/network baseline applied (rp_filter=$rpf)."
}

configure_logging_and_coredumps() {
  CURRENT_STAGE="persistent logging and coredump policy"
  [[ ! -L /var/log/journal ]] || die "Refusing symlinked persistent journal directory: /var/log/journal"
  install -d -m 2755 -o root -g systemd-journal /var/log/journal
  systemd-tmpfiles --create --prefix /var/log/journal || true

  write_file /etc/systemd/journald.conf.d/99-hardening.conf 0644 root root <<'JOURNAL'
# Managed by ubuntu-24.04-hardening.sh
[Journal]
Storage=persistent
Compress=yes
Seal=yes
ForwardToSyslog=yes
JOURNAL

  write_file /etc/rsyslog.d/99-hardening.conf 0644 root root <<'RSYSLOG'
# Managed by ubuntu-24.04-hardening.sh
$FileCreateMode 0640
$DirCreateMode 0750
$Umask 0027
RSYSLOG
  rsyslogd -N1 >/dev/null

  if (( DISABLE_COREDUMPS )); then
    write_file /etc/systemd/coredump.conf.d/99-hardening.conf 0644 root root <<'COREDUMP'
# Managed by ubuntu-24.04-hardening.sh
[Coredump]
Storage=none
ProcessSizeMax=0
COREDUMP
  else
    remove_our_managed_file /etc/systemd/coredump.conf.d/99-hardening.conf
    log "This script's systemd-coredump restriction is absent because --keep-coredumps was selected."
  fi

  systemctl enable --now rsyslog.service >/dev/null
  systemctl restart systemd-journald.service
  systemctl restart rsyslog.service
  pass "Persistent journal and restrictive log-file modes are configured."
}

append_audit_watch() {
  local output="$1" path="$2" perms="$3" key="$4"
  [[ -e "$path" ]] && printf -- '-w %s -p %s -k %s\n' "$path" "$perms" "$key" >> "$output"
}

configure_auditd() {
  (( ENABLE_AUDITD )) || return 0
  CURRENT_STAGE="Linux Audit configuration"

  set_equals_key /etc/audit/auditd.conf write_logs yes 0640 root root
  set_equals_key /etc/audit/auditd.conf log_group adm 0640 root root
  set_equals_key /etc/audit/auditd.conf max_log_file 50 0640 root root
  set_equals_key /etc/audit/auditd.conf num_logs 10 0640 root root
  set_equals_key /etc/audit/auditd.conf max_log_file_action ROTATE 0640 root root
  set_equals_key /etc/audit/auditd.conf space_left_action SYSLOG 0640 root root
  set_equals_key /etc/audit/auditd.conf admin_space_left_action SUSPEND 0640 root root
  set_equals_key /etc/audit/auditd.conf disk_full_action SUSPEND 0640 root root
  set_equals_key /etc/audit/auditd.conf disk_error_action SUSPEND 0640 root root
  set_equals_key /etc/audit/auditd.conf name_format HOSTNAME 0640 root root
  set_equals_key /etc/audit/auditd.conf flush INCREMENTAL_ASYNC 0640 root root
  set_equals_key /etc/audit/auditd.conf freq 50 0640 root root

  local tmp arch
  tmp="$(mktemp)"
  cat > "$tmp" <<'AUDIT_HEAD'
## Managed by ubuntu-24.04-hardening.sh
## Add site-specific rules in a separate, lexically earlier rules.d file.
-b 8192
-f 1
AUDIT_HEAD

  append_audit_watch "$tmp" /etc/passwd wa identity
  append_audit_watch "$tmp" /etc/group wa identity
  append_audit_watch "$tmp" /etc/shadow wa identity
  append_audit_watch "$tmp" /etc/gshadow wa identity
  append_audit_watch "$tmp" /etc/security/opasswd wa identity
  append_audit_watch "$tmp" /etc/sudoers wa scope
  append_audit_watch "$tmp" /etc/sudoers.d wa scope
  append_audit_watch "$tmp" /var/log/sudo.log wa actions
  append_audit_watch "$tmp" /etc/ssh/sshd_config wa sshd
  append_audit_watch "$tmp" /etc/ssh/sshd_config.d wa sshd
  append_audit_watch "$tmp" /etc/audit wa auditconfig
  append_audit_watch "$tmp" /etc/hosts wa network
  append_audit_watch "$tmp" /etc/hostname wa network
  append_audit_watch "$tmp" /etc/netplan wa network
  append_audit_watch "$tmp" /etc/systemd/system wa systemd
  append_audit_watch "$tmp" /etc/crontab wa cron
  append_audit_watch "$tmp" /etc/cron.d wa cron
  append_audit_watch "$tmp" /etc/cron.daily wa cron
  append_audit_watch "$tmp" /etc/cron.hourly wa cron
  append_audit_watch "$tmp" /etc/cron.weekly wa cron
  append_audit_watch "$tmp" /etc/cron.monthly wa cron

  case "$(uname -m)" in
    x86_64) 
      for arch in b64 b32; do
        printf -- '-a always,exit -F arch=%s -S adjtimex,settimeofday,clock_settime -k time-change\n' "$arch" >> "$tmp"
        printf -- '-a always,exit -F arch=%s -S sethostname,setdomainname -k system-locale\n' "$arch" >> "$tmp"
        printf -- '-a always,exit -F arch=%s -S mount,umount2 -F auid>=1000 -F auid!=unset -k mounts\n' "$arch" >> "$tmp"
        printf -- '-a always,exit -F arch=%s -S init_module,finit_module,delete_module -k modules\n' "$arch" >> "$tmp"
      done
      ;;
    aarch64|arm64)
      arch=b64
      printf -- '-a always,exit -F arch=%s -S adjtimex,settimeofday,clock_settime -k time-change\n' "$arch" >> "$tmp"
      printf -- '-a always,exit -F arch=%s -S sethostname,setdomainname -k system-locale\n' "$arch" >> "$tmp"
      printf -- '-a always,exit -F arch=%s -S mount,umount2 -F auid>=1000 -F auid!=unset -k mounts\n' "$arch" >> "$tmp"
      printf -- '-a always,exit -F arch=%s -S init_module,finit_module,delete_module -k modules\n' "$arch" >> "$tmp"
      ;;
    *) warn "Architecture $(uname -m) is not covered by the syscall audit subset; file watches will still be installed." ;;
  esac

  if (( AUDIT_IMMUTABLE )); then
    printf -- '-e 2\n' >> "$tmp"
  else
    printf -- '-e 1\n' >> "$tmp"
  fi
  write_file /etc/audit/rules.d/99-hardening.rules 0640 root root < "$tmp"
  rm -f "$tmp"

  augenrules --check >/dev/null
  systemctl enable auditd.service >/dev/null 2>&1 || true
  if ! service_active auditd.service; then
    if ! systemctl start auditd.service; then warn "auditd could not start; check kernel audit support and journal logs."; fi
  else
    if ! service auditd restart >/dev/null 2>&1; then warn "auditd configuration restart was refused; rules will still be loaded where possible."; fi
  fi

  local current_enabled=""
  current_enabled="$(auditctl -s 2>/dev/null | awk '$1=="enabled" {print $2}')"
  if [[ "$current_enabled" == "2" ]]; then
    warn "Audit is already immutable; new rule files will take effect after reboot."
  elif ! augenrules --load; then
    warn "Audit rules could not be loaded at runtime; they remain configured for the next boot."
  fi

  if auditctl -s >/dev/null 2>&1; then
    pass "Linux Audit is configured (immutable=$AUDIT_IMMUTABLE)."
  else
    warn "auditctl cannot query the kernel audit subsystem."
  fi
}

configure_apparmor() {
  (( ENABLE_APPARMOR )) || return 0
  CURRENT_STAGE="AppArmor enablement"
  systemctl enable apparmor.service >/dev/null 2>&1 || true
  if ! systemctl start apparmor.service; then warn "AppArmor service could not start."; fi
  if ! systemctl reload apparmor.service; then warn "AppArmor profiles could not be reloaded cleanly."; fi
  if aa-status --enabled >/dev/null 2>&1; then
    pass "AppArmor is enabled; existing profile modes were preserved."
  else
    warn "AppArmor is not enabled in the running kernel. Check boot parameters and virtualization support."
  fi
}

configure_strict_modules() {
  (( STRICT_MODULES )) || return 0
  CURRENT_STAGE="optional kernel module restrictions"
  write_file /etc/modprobe.d/99-hardening-blacklist.conf 0644 root root <<'MODULES'
# Managed by ubuntu-24.04-hardening.sh
# Optional strict profile. Existing loaded modules are not forcibly removed.
install cramfs /bin/false
blacklist cramfs
install freevxfs /bin/false
blacklist freevxfs
install hfs /bin/false
blacklist hfs
install hfsplus /bin/false
blacklist hfsplus
install jffs2 /bin/false
blacklist jffs2
install dccp /bin/false
blacklist dccp
install rds /bin/false
blacklist rds
install sctp /bin/false
blacklist sctp
install tipc /bin/false
blacklist tipc
MODULES
  depmod -a
  pass "Optional uncommon filesystem/protocol modules are blocked on future load."
}

set_owner_mode_if_exists() {
  local path="$1" owner="$2" group="$3" mode="$4"
  if [[ -e "$path" ]]; then
    chown "$owner:$group" "$path"
    chmod "$mode" "$path"
  fi
}

fix_sensitive_permissions() {
  CURRENT_STAGE="sensitive file permissions"
  set_owner_mode_if_exists /etc/passwd root root 0644
  set_owner_mode_if_exists /etc/group root root 0644
  set_owner_mode_if_exists /etc/shadow root shadow 0640
  set_owner_mode_if_exists /etc/gshadow root shadow 0640
  set_owner_mode_if_exists /etc/passwd- root root 0600
  set_owner_mode_if_exists /etc/group- root root 0600
  set_owner_mode_if_exists /etc/shadow- root root 0600
  set_owner_mode_if_exists /etc/gshadow- root root 0600
  set_owner_mode_if_exists /etc/sudoers root root 0440
  set_owner_mode_if_exists /boot/grub/grub.cfg root root 0600

  local key
  while IFS= read -r -d '' key; do
    chown root:root "$key"
    chmod 0600 "$key"
  done < <(find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key' -print0 2>/dev/null)
  while IFS= read -r -d '' key; do
    chown root:root "$key"
    chmod 0644 "$key"
  done < <(find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*_key.pub' -print0 2>/dev/null)

  pass "Core account databases, sudoers, GRUB config, and SSH host keys have restrictive ownership/modes."
}

configure_aide() {
  (( WITH_AIDE )) || return 0
  CURRENT_STAGE="AIDE initialization"
  if compgen -G '/var/lib/aide/aide.db*' >/dev/null; then
    log "Existing AIDE database found; preserving the established baseline."
  else
    aideinit -y -f
  fi
  if systemctl list-unit-files dailyaidecheck.timer --no-legend 2>/dev/null | grep -q dailyaidecheck.timer; then
    systemctl enable --now dailyaidecheck.timer >/dev/null
    pass "AIDE baseline exists and dailyaidecheck.timer is enabled."
  else
    warn "AIDE installed, but dailyaidecheck.timer was not found on this image."
  fi
}

run_final_validation() {
  CURRENT_STAGE="final validation"
  local errors=0

  if (( SSH_SERVER_PRESENT && ENABLE_SSH_HARDENING )); then
    /usr/sbin/sshd -t || { fail "sshd validation failed"; errors=$((errors + 1)); }
  fi
  visudo -cf /etc/sudoers >/dev/null || { fail "sudoers validation failed"; errors=$((errors + 1)); }
  rsyslogd -N1 >/dev/null || { fail "rsyslog validation failed"; errors=$((errors + 1)); }
  if command_exists logrotate; then
    logrotate --debug /etc/logrotate.d/ubuntu-hardening-sudo >/dev/null 2>&1 || { fail "sudo logrotate validation failed"; errors=$((errors + 1)); }
  fi
  if (( ENABLE_FAIL2BAN && SSH_SERVER_PRESENT )); then
    fail2ban-client -t >/dev/null || { fail "Fail2ban validation failed"; errors=$((errors + 1)); }
  fi
  if (( ENABLE_UFW )); then
    ufw status | grep -q '^Status: active' || { fail "UFW is not active"; errors=$((errors + 1)); }
  fi
  if (( ENABLE_UNATTENDED )); then
    systemctl is-enabled --quiet apt-daily-upgrade.timer || { fail "apt-daily-upgrade.timer is not enabled"; errors=$((errors + 1)); }
  fi

  if (( errors > 0 )); then
    die "Final validation reported $errors error(s). Review the log and use the backup rollback if necessary."
  fi
  pass "All mandatory post-change validations passed."
}

show_plan() {
  printf '\n%sPlanned hardening transaction%s\n' "$C_BOLD" "$C_RESET"
  printf '  Target:                 %s\n' "$(. /etc/os-release; echo "${PRETTY_NAME:-unknown}")"
  printf '  Virtualization:         %s\n' "$VIRT_TYPE"
  printf '  Admin user:             %s\n' "${ADMIN_USER:-not resolved}"
  printf '  SSH server present:     %s\n' "$( (( SSH_SERVER_PRESENT )) && echo yes || echo no )"
  printf '  SSH ports:              %s\n' "$(IFS=,; echo "${SSH_PORTS[*]:-none}")"
  printf '  Valid admin key:        %s\n' "$( (( ADMIN_KEY_SAFE )) && echo yes || echo no )"
  printf '  Current key login seen: %s\n' "$( (( SESSION_PUBLICKEY_CONFIRMED )) && echo yes || echo no )"
  printf '  Disable SSH passwords:  %s\n' "$( (( WILL_DISABLE_PASSWORD_AUTH )) && echo yes || echo no )"
  printf '  Disable root SSH login: %s\n' "$( (( WILL_DISABLE_ROOT_LOGIN )) && echo yes || echo no )"
  printf '  SSH source CIDRs:       %s\n' "$(IFS=,; echo "${SSH_ALLOW_CIDRS[*]:-any}")"
  printf '  Additional TCP:         %s\n' "$(IFS=,; echo "${ALLOW_TCP_PORTS[*]:-none}")"
  printf '  Additional UDP:         %s\n' "$(IFS=,; echo "${ALLOW_UDP_PORTS[*]:-none}")"
  printf '  UFW / Fail2ban:         %s / %s\n' "$ENABLE_UFW" "$ENABLE_FAIL2BAN"
  printf '  Auditd / AppArmor:      %s / %s\n' "$ENABLE_AUDITD" "$ENABLE_APPARMOR"
  printf '  Unattended updates:     %s (auto reboot: %s)\n' "$ENABLE_UNATTENDED" "$AUTO_REBOOT"
  printf '  Package upgrade now:    %s\n' "$UPGRADE_SYSTEM"
  printf '  AIDE:                   %s\n' "$WITH_AIDE"
  printf '  Strict rp_filter:       %s\n' "$STRICT_RPF"
  printf '  Strict module profile:  %s\n' "$STRICT_MODULES"
  printf '\nNo files, packages, services, firewall rules, or sysctls were changed.\n'
}

AUDIT_PASS=0
AUDIT_WARN=0
AUDIT_FAIL=0

audit_pass() { AUDIT_PASS=$((AUDIT_PASS + 1)); pass "$*"; }
audit_warn() { AUDIT_WARN=$((AUDIT_WARN + 1)); warn "$*"; }
audit_fail() { AUDIT_FAIL=$((AUDIT_FAIL + 1)); fail "$*"; }

audit_posture() {
  CURRENT_STAGE="read-only posture audit"
  printf '%sUbuntu 24.04 security posture audit%s\n' "$C_BOLD" "$C_RESET"
  printf 'Generated: %s\n\n' "$(date --iso-8601=seconds)"

  # shellcheck disable=SC1091
  source /etc/os-release
  printf 'System\n'
  printf '  OS:              %s\n' "${PRETTY_NAME:-unknown}"
  printf '  Kernel:          %s\n' "$(uname -srmo)"
  printf '  Virtualization:  %s\n' "$VIRT_TYPE"
  printf '  PID 1:           %s\n' "$(ps -p 1 -o comm= 2>/dev/null | xargs)"
  printf '  Root filesystem: %s\n' "$(findmnt -no SOURCE,FSTYPE,OPTIONS / 2>/dev/null || echo unknown)"
  if [[ -e /var/run/reboot-required ]]; then audit_warn "A reboot is required."; else audit_pass "No reboot-required marker is present."; fi
  if command_exists mokutil; then printf '  Secure Boot:     %s\n' "$(mokutil --sb-state 2>/dev/null | head -n1 || echo unknown)"; fi

  local update_count
  update_count="$(apt list --upgradable 2>/dev/null | tail -n +2 | sed '/^[[:space:]]*$/d' | wc -l | xargs)"
  printf '  Upgradable packages: %s\n\n' "$update_count"

  printf 'OpenSSH\n'
  if (( SSH_SERVER_PRESENT )); then
    if /usr/sbin/sshd -t; then audit_pass "sshd configuration parses successfully."; else audit_fail "sshd configuration is invalid."; fi
    local root_login password_auth kbd_auth ports
    root_login="$(sshd_effective_value permitrootlogin)"
    password_auth="$(sshd_effective_value passwordauthentication)"
    kbd_auth="$(sshd_effective_value kbdinteractiveauthentication)"
    ports="$(IFS=,; echo "${SSH_PORTS[*]}")"
    printf '  Ports:                        %s\n' "$ports"
    printf '  PermitRootLogin:              %s\n' "$root_login"
    printf '  PasswordAuthentication:       %s\n' "$password_auth"
    printf '  KbdInteractiveAuthentication: %s\n' "$kbd_auth"
    [[ "$root_login" == "no" ]] && audit_pass "Direct root SSH login is disabled." || audit_warn "Direct root SSH login is not fully disabled."
    [[ "$password_auth" == "no" ]] && audit_pass "SSH password authentication is disabled." || audit_warn "SSH password authentication remains enabled/effective."
  else
    audit_pass "OpenSSH server is not installed."
  fi
  printf '\n'

  printf 'Firewall and abuse controls\n'
  if command_exists ufw; then
    if ufw status 2>/dev/null | grep -q '^Status: active'; then audit_pass "UFW is active."; else audit_warn "UFW is inactive."; fi
    ufw status verbose 2>/dev/null | sed 's/^/  /' || true
  else
    audit_warn "UFW is not installed."
  fi
  if command_exists fail2ban-client && fail2ban-client ping >/dev/null 2>&1; then
    audit_pass "Fail2ban is running."
    fail2ban-client status 2>/dev/null | sed 's/^/  /' || true
  elif (( SSH_SERVER_PRESENT )); then
    audit_warn "Fail2ban is not running for this SSH-exposed host."
  fi
  printf '\n'

  printf 'Updates and mandatory access control\n'
  if systemctl is-enabled --quiet apt-daily-upgrade.timer 2>/dev/null && systemctl is-active --quiet apt-daily-upgrade.timer 2>/dev/null; then
    audit_pass "apt-daily-upgrade.timer is enabled and active."
  else
    audit_warn "apt-daily-upgrade.timer is not both enabled and active."
  fi
  if command_exists aa-status && aa-status --enabled >/dev/null 2>&1; then
    audit_pass "AppArmor is enabled."
    aa-status 2>/dev/null | head -n 12 | sed 's/^/  /' || true
  else
    audit_warn "AppArmor is not enabled or aa-status is unavailable."
  fi
  printf '\n'

  printf 'Audit and logging\n'
  if command_exists auditctl && auditctl -s >/dev/null 2>&1; then
    audit_pass "Kernel audit status is queryable."
    auditctl -s 2>/dev/null | sed 's/^/  /'
    printf '  Loaded audit rules: %s\n' "$(auditctl -l 2>/dev/null | wc -l | xargs)"
  else
    audit_warn "Linux Audit is unavailable or disabled."
  fi
  if [[ -d /var/log/journal ]]; then audit_pass "Persistent systemd journal directory exists."; else audit_warn "Persistent journal directory is absent."; fi
  printf '\n'

  printf 'Accounts\n'
  local uid0 empty_pw dup_uid dup_gid
  uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd | paste -sd, -)"
  printf '  UID 0 accounts: %s\n' "$uid0"
  [[ "$uid0" == "root" ]] && audit_pass "Only root has UID 0." || audit_fail "Additional UID 0 account(s) exist."
  if [[ -r /etc/shadow ]]; then
    empty_pw="$(awk -F: '$2=="" {print $1}' /etc/shadow | paste -sd, -)"
    [[ -z "$empty_pw" ]] && audit_pass "No empty password hashes found." || audit_fail "Accounts with empty password fields: $empty_pw"
  else
    audit_warn "Cannot read /etc/shadow; empty-password check skipped."
  fi
  dup_uid="$(cut -d: -f3 /etc/passwd | sort | uniq -d | paste -sd, -)"
  dup_gid="$(cut -d: -f3 /etc/group | sort | uniq -d | paste -sd, -)"
  [[ -z "$dup_uid" ]] && audit_pass "No duplicate UIDs found." || audit_fail "Duplicate UIDs: $dup_uid"
  [[ -z "$dup_gid" ]] && audit_pass "No duplicate GIDs found." || audit_fail "Duplicate GIDs: $dup_gid"
  printf '\n'

  printf 'Selected kernel controls\n'
  local key expected actual
  while IFS='=' read -r key expected; do
    actual="$(sysctl -n "$key" 2>/dev/null || echo unavailable)"
    printf '  %-44s current=%-12s expected=%s\n' "$key" "$actual" "$expected"
    [[ "$actual" == "$expected" ]] || audit_warn "$key differs from the baseline value $expected."
  done <<'SYSCTLCHECK'
kernel.randomize_va_space=2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
SYSCTLCHECK
  printf '\n'

  printf 'Failed systemd units\n'
  systemctl --failed --no-pager --plain 2>/dev/null | sed 's/^/  /' || true
  printf '\nListening sockets\n'
  if command_exists ss; then ss -lntup 2>/dev/null | sed 's/^/  /'; else printf '  ss is unavailable\n'; fi

  if service_active docker.service || service_active containerd.service || service_active kubelet.service; then
    audit_warn "Container networking is active; verify published-port exposure independently of UFW."
  fi

  printf '\n%sAudit summary:%s %s pass, %s warning, %s failure\n' "$C_BOLD" "$C_RESET" "$AUDIT_PASS" "$AUDIT_WARN" "$AUDIT_FAIL"
  printf 'This is a technical baseline, not proof of compliance or application security.\n'
}

restore_service_state() {
  local service="$1" enabled="$2" active="$3"
  # A unit may have been masked before hardening yet still have been running.
  # Temporarily unmask, restore activity, then restore its unit-file state.
  systemctl unmask "$service" >/dev/null 2>&1 || true
  if [[ "$active" == "yes" ]]; then
    systemctl start "$service" >/dev/null 2>&1 || true
  else
    systemctl stop "$service" >/dev/null 2>&1 || true
  fi
  case "$enabled" in
    enabled) systemctl enable "$service" >/dev/null 2>&1 || true ;;
    enabled-runtime) systemctl enable --runtime "$service" >/dev/null 2>&1 || true ;;
    disabled|not-found) systemctl disable "$service" >/dev/null 2>&1 || true ;;
    masked) systemctl mask "$service" >/dev/null 2>&1 || true ;;
    masked-runtime) systemctl mask --runtime "$service" >/dev/null 2>&1 || true ;;
    *) : ;; # static, indirect, generated, transient, alias, linked, etc.
  esac
}

resolve_rollback_path() {
  local target="$1" resolved
  if [[ "$target" == "latest" ]]; then
    [[ -L "$BACKUP_ROOT/latest" || -d "$BACKUP_ROOT/latest" ]] || die "No latest backup exists under $BACKUP_ROOT."
    resolved="$(readlink -f "$BACKUP_ROOT/latest")"
  else
    resolved="$(readlink -f "$target")"
  fi
  [[ "$resolved" == "$BACKUP_ROOT/"* ]] || die "Rollback backups must reside beneath $BACKUP_ROOT."
  [[ -d "$resolved" ]] || die "Rollback directory does not exist: $resolved"
  [[ "$(stat -c '%U' "$resolved")" == "root" ]] || die "Rollback directory is not owned by root: $resolved"
  if find "$resolved" -maxdepth 0 -perm /022 -print -quit | grep -q .; then
    die "Rollback directory is group/world writable: $resolved"
  fi
  printf '%s\n' "$resolved"
}

restore_saved_sysctls() {
  local file="$1" key value failures=0
  [[ -f "$file" ]] || return 0
  while IFS=$'\t' read -r key value; do
    [[ -n "$key" ]] || continue
    [[ "$key" =~ ^[a-zA-Z0-9_.]+$ ]] || { warn "Skipping invalid saved sysctl key: $key"; failures=$((failures + 1)); continue; }
    if [[ -e "/proc/sys/${key//./\/}" ]]; then
      sysctl -q -w "$key=$value" 2>/dev/null || failures=$((failures + 1))
    fi
  done < "$file"
  (( failures == 0 )) || warn "$failures saved runtime sysctl value(s) could not be restored."
}

validate_tar_archive() {
  local archive="$1" member
  [[ -f "$archive" ]] || return 0
  while IFS= read -r member; do
    [[ -n "$member" ]] || continue
    case "$member" in
      /*|..|../*|*/../*|*/..) die "Unsafe path '$member' in rollback archive '$archive'." ;;
    esac
  done < <(tar -tf "$archive")
}

restore_audit_runtime() {
  local prior_enabled="$1" saved_rules="$2" current_enabled tmp
  command_exists auditctl || return 0
  current_enabled="$(auditctl -s 2>/dev/null | awk '$1=="enabled" {print $2; exit}')"
  if [[ "$current_enabled" == "2" ]]; then
    warn "The running audit subsystem is immutable; its pre-change runtime rules require a reboot to restore. Persistent rule files were restored."
    return 0
  fi
  if [[ "$prior_enabled" =~ ^[012]$ ]]; then
    auditctl -D >/dev/null 2>&1 || warn "Could not clear current audit rules during rollback."
    if [[ -s "$saved_rules" ]]; then
      tmp="$(mktemp)"
      grep -vE '^[[:space:]]*(No rules|$)' "$saved_rules" > "$tmp" || true
      if [[ -s "$tmp" ]]; then auditctl -R "$tmp" >/dev/null 2>&1 || warn "Some saved runtime audit rules could not be restored."; fi
      rm -f "$tmp"
    fi
    auditctl -e "$prior_enabled" >/dev/null 2>&1 || warn "Could not restore audit enabled state to $prior_enabled."
  elif command_exists augenrules; then
    augenrules --load >/dev/null 2>&1 || true
  fi
}

rollback_backup() {
  require_root
  acquire_lock
  CURRENT_STAGE="rollback validation"
  local dir state archive managed admin_meta sysctl_state file
  local UFW_ACTIVE FAIL2BAN_ENABLED FAIL2BAN_ACTIVE AUDITD_ENABLED AUDITD_ACTIVE
  local APPARMOR_ENABLED APPARMOR_ACTIVE RSYSLOG_ENABLED RSYSLOG_ACTIVE
  local APT_DAILY_ENABLED APT_DAILY_ACTIVE APT_DAILY_UPGRADE_ENABLED APT_DAILY_UPGRADE_ACTIVE
  local AIDE_TIMER_ENABLED AIDE_TIMER_ACTIVE AUDIT_KERNEL_ENABLED
  local VAR_LOG_JOURNAL_EXISTED VAR_LOG_JOURNAL_UID VAR_LOG_JOURNAL_GID VAR_LOG_JOURNAL_MODE
  local SUDO_LOG_EXISTED SUDO_LOG_UID SUDO_LOG_GID SUDO_LOG_MODE

  dir="$(resolve_rollback_path "$ROLLBACK_TARGET")"
  state="$dir/state.tsv"
  archive="$dir/config.tar"
  managed="$dir/managed-files.txt"
  admin_meta="$dir/admin-ssh-metadata.tar"
  sysctl_state="$dir/sysctl-before.tsv"
  [[ -f "$state" && -f "$archive" && -f "$managed" && -f "$dir/SHA256SUMS" ]] || die "Invalid backup directory: $dir"
  if find "$dir" -mindepth 1 -maxdepth 1       \( ! -user root -o -perm /022 \) -print -quit | grep -q .; then
    die "One or more rollback files are not root-owned or are group/world writable: $dir"
  fi
  (cd "$dir" && sha256sum -c SHA256SUMS)
  validate_tar_archive "$archive"
  [[ -f "$admin_meta" ]] && validate_tar_archive "$admin_meta"

  UFW_ACTIVE="$(state_get "$state" UFW_ACTIVE)"; UFW_ACTIVE="${UFW_ACTIVE:-no}"
  FAIL2BAN_ENABLED="$(state_get "$state" FAIL2BAN_ENABLED)"; FAIL2BAN_ENABLED="${FAIL2BAN_ENABLED:-disabled}"
  FAIL2BAN_ACTIVE="$(state_get "$state" FAIL2BAN_ACTIVE)"; FAIL2BAN_ACTIVE="${FAIL2BAN_ACTIVE:-no}"
  AUDITD_ENABLED="$(state_get "$state" AUDITD_ENABLED)"; AUDITD_ENABLED="${AUDITD_ENABLED:-disabled}"
  AUDITD_ACTIVE="$(state_get "$state" AUDITD_ACTIVE)"; AUDITD_ACTIVE="${AUDITD_ACTIVE:-no}"
  APPARMOR_ENABLED="$(state_get "$state" APPARMOR_ENABLED)"; APPARMOR_ENABLED="${APPARMOR_ENABLED:-disabled}"
  APPARMOR_ACTIVE="$(state_get "$state" APPARMOR_ACTIVE)"; APPARMOR_ACTIVE="${APPARMOR_ACTIVE:-no}"
  RSYSLOG_ENABLED="$(state_get "$state" RSYSLOG_ENABLED)"; RSYSLOG_ENABLED="${RSYSLOG_ENABLED:-disabled}"
  RSYSLOG_ACTIVE="$(state_get "$state" RSYSLOG_ACTIVE)"; RSYSLOG_ACTIVE="${RSYSLOG_ACTIVE:-no}"
  APT_DAILY_ENABLED="$(state_get "$state" APT_DAILY_ENABLED)"; APT_DAILY_ENABLED="${APT_DAILY_ENABLED:-disabled}"
  APT_DAILY_ACTIVE="$(state_get "$state" APT_DAILY_ACTIVE)"; APT_DAILY_ACTIVE="${APT_DAILY_ACTIVE:-no}"
  APT_DAILY_UPGRADE_ENABLED="$(state_get "$state" APT_DAILY_UPGRADE_ENABLED)"; APT_DAILY_UPGRADE_ENABLED="${APT_DAILY_UPGRADE_ENABLED:-disabled}"
  APT_DAILY_UPGRADE_ACTIVE="$(state_get "$state" APT_DAILY_UPGRADE_ACTIVE)"; APT_DAILY_UPGRADE_ACTIVE="${APT_DAILY_UPGRADE_ACTIVE:-no}"
  AIDE_TIMER_ENABLED="$(state_get "$state" AIDE_TIMER_ENABLED)"; AIDE_TIMER_ENABLED="${AIDE_TIMER_ENABLED:-disabled}"
  AIDE_TIMER_ACTIVE="$(state_get "$state" AIDE_TIMER_ACTIVE)"; AIDE_TIMER_ACTIVE="${AIDE_TIMER_ACTIVE:-no}"
  AUDIT_KERNEL_ENABLED="$(state_get "$state" AUDIT_KERNEL_ENABLED)"; AUDIT_KERNEL_ENABLED="${AUDIT_KERNEL_ENABLED:-unavailable}"
  VAR_LOG_JOURNAL_EXISTED="$(state_get "$state" VAR_LOG_JOURNAL_EXISTED)"; VAR_LOG_JOURNAL_EXISTED="${VAR_LOG_JOURNAL_EXISTED:-no}"
  VAR_LOG_JOURNAL_UID="$(state_get "$state" VAR_LOG_JOURNAL_UID)"
  VAR_LOG_JOURNAL_GID="$(state_get "$state" VAR_LOG_JOURNAL_GID)"
  VAR_LOG_JOURNAL_MODE="$(state_get "$state" VAR_LOG_JOURNAL_MODE)"
  SUDO_LOG_EXISTED="$(state_get "$state" SUDO_LOG_EXISTED)"; SUDO_LOG_EXISTED="${SUDO_LOG_EXISTED:-no}"
  SUDO_LOG_UID="$(state_get "$state" SUDO_LOG_UID)"
  SUDO_LOG_GID="$(state_get "$state" SUDO_LOG_GID)"
  SUDO_LOG_MODE="$(state_get "$state" SUDO_LOG_MODE)"

  CURRENT_STAGE="configuration rollback"
  if command_exists ufw; then ufw --force disable >/dev/null 2>&1 || true; fi
  if service_active fail2ban.service; then systemctl stop fail2ban.service || true; fi

  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    [[ "$file" == /etc/* && "$file" != *'..'* ]] || die "Unsafe managed path in backup manifest: $file"
    rm -f -- "$file"
  done < "$managed"

  tar --acls --xattrs --numeric-owner -C / -xpf "$archive"
  if [[ -f "$admin_meta" ]]; then
    tar --acls --xattrs --numeric-owner -C / -xpf "$admin_meta"
  fi
  systemctl daemon-reload

  if [[ -x /usr/sbin/sshd ]] && /usr/sbin/sshd -t; then
    if service_active ssh.service; then systemctl reload ssh.service || true; fi
  else
    warn "Restored SSH configuration did not pass sshd -t or sshd is absent; inspect before opening a new session."
  fi

  sysctl --system >/dev/null 2>&1 || warn "Some restored persistent sysctl settings could not be applied at runtime."
  restore_saved_sysctls "$sysctl_state"
  if command_exists visudo; then
    visudo -cf /etc/sudoers >/dev/null || warn "Restored sudoers validation failed."
  fi
  if command_exists rsyslogd; then
    rsyslogd -N1 >/dev/null || warn "Restored rsyslog validation failed."
  fi

  restore_service_state fail2ban.service "$FAIL2BAN_ENABLED" "$FAIL2BAN_ACTIVE"
  restore_service_state auditd.service "$AUDITD_ENABLED" "$AUDITD_ACTIVE"
  restore_service_state apparmor.service "$APPARMOR_ENABLED" "$APPARMOR_ACTIVE"
  restore_service_state rsyslog.service "$RSYSLOG_ENABLED" "$RSYSLOG_ACTIVE"
  restore_service_state apt-daily.timer "$APT_DAILY_ENABLED" "$APT_DAILY_ACTIVE"
  restore_service_state apt-daily-upgrade.timer "$APT_DAILY_UPGRADE_ENABLED" "$APT_DAILY_UPGRADE_ACTIVE"
  restore_service_state dailyaidecheck.timer "$AIDE_TIMER_ENABLED" "$AIDE_TIMER_ACTIVE"

  restore_audit_runtime "$AUDIT_KERNEL_ENABLED" "$dir/audit-rules-before.txt"

  if command_exists ufw; then
    if [[ "$UFW_ACTIVE" == "yes" ]]; then ufw --force enable >/dev/null; else ufw --force disable >/dev/null; fi
  fi
  restore_path_metadata /var/log/journal "$VAR_LOG_JOURNAL_EXISTED" "$VAR_LOG_JOURNAL_UID" "$VAR_LOG_JOURNAL_GID" "$VAR_LOG_JOURNAL_MODE"
  restore_path_metadata /var/log/sudo.log "$SUDO_LOG_EXISTED" "$SUDO_LOG_UID" "$SUDO_LOG_GID" "$SUDO_LOG_MODE"
  systemctl restart systemd-journald.service >/dev/null 2>&1 || true
  if service_active rsyslog.service; then systemctl restart rsyslog.service >/dev/null 2>&1 || true; fi

  pass "Configuration, SSH-key metadata, log-path metadata, runtime sysctls, and recorded service/firewall states were restored from $dir"
  warn "Package installations/upgrades and generated AIDE databases are intentionally not uninstalled by rollback."
}

apply_hardening() {
  require_root
  acquire_lock
  preflight_conflicts
  check_ssh_cidr_lockout
  create_backup
  install_packages

  configure_ssh
  configure_ufw
  configure_fail2ban
  configure_unattended_upgrades
  configure_pwquality_and_accounts
  configure_sudo
  configure_sysctl
  configure_logging_and_coredumps
  configure_auditd
  configure_apparmor
  configure_strict_modules
  fix_sensitive_permissions
  configure_aide
  run_final_validation

  printf '\n%sHardening transaction completed successfully.%s\n' "$C_BOLD$C_GREEN" "$C_RESET"
  printf 'Backup:  %s\n' "$BACKUP_DIR"
  printf 'Rollback: sudo %s --rollback %q\n' "$SCRIPT_NAME" "$BACKUP_DIR"
  if [[ -e /var/run/reboot-required ]]; then
    warn "A reboot is required. Keep the current SSH session open and test a second login before rebooting."
  elif (( SSH_SERVER_PRESENT )); then
    warn "Keep this SSH session open until a second login has been tested successfully."
  fi
  if (( ENABLE_UFW )) && (service_active docker.service || service_active containerd.service || service_active kubelet.service); then
    warn "Review container-published ports with 'ss -lntup' and the container runtime; UFW alone is not a complete container firewall boundary."
  fi
}

main() {
  setup_logging
  validate_options

  case "$MODE" in
    rollback)
      rollback_backup
      ;;
    audit)
      if (( EUID != 0 )); then warn "Running audit without root; shadow, firewall, audit, and service details may be incomplete."; fi
      detect_environment
      resolve_admin_and_ssh_safety
      audit_posture
      ;;
    dry-run)
      require_root
      detect_environment
      resolve_admin_and_ssh_safety
      preflight_conflicts
      check_ssh_cidr_lockout
      show_plan
      ;;
    apply)
      require_root
      detect_environment
      resolve_admin_and_ssh_safety
      apply_hardening
      ;;
    *) die "Internal error: unknown mode '$MODE'." ;;
  esac
}

if [[ "${UBUNTU_HARDENING_LIB_ONLY:-0}" != "1" ]]; then
  main "$@"
fi
