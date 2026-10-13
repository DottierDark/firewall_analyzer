#!/usr/bin/env bash
#
# Firewall Analyzer — one-step setup.
#
#   ./setup.sh                 install (if needed) and open the web interface
#   ./setup.sh --install-only  set everything up but do not start the server
#   ./setup.sh --port 9000     start on a different port
#   ./setup.sh --share         listen on all interfaces so the team can reach it
#   ./setup.sh --reset-passwords
#                              set new passwords on the four accounts and exit
#   ./setup.sh --uninstall     remove the packages this script installed
#
# Installs into your user account (~/.local), not system-wide, and never needs
# sudo. Safe to run more than once: accounts are only created on the first run.

set -euo pipefail

REPO_URL="https://github.com/ashmxwy/firewall_analyzer.git"
BRANCH="gui"                       # the branch the web interface lives on
PORT="8000"
HOST="127.0.0.1"
START=1
RESET=0
UNINSTALL=0

# Passwords for the four seeded accounts. Applied only on the first run, when
# the accounts are created; override by exporting these before running.
: "${FWA_PASSWORD_ADMIN:=Admin!2345}"
: "${FWA_PASSWORD_EXECUTIVE:=Exec!2345}"
: "${FWA_PASSWORD_MANAGER:=Manager!2345}"
: "${FWA_PASSWORD_ANALYST:=Analyst!2345}"
export FWA_PASSWORD_ADMIN FWA_PASSWORD_EXECUTIVE FWA_PASSWORD_MANAGER FWA_PASSWORD_ANALYST

# ── pretty output ─────────────────────────────────────────────────────────
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
  YELLOW=$'\033[33m'; RESET_C=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; RESET_C=""
fi
step() { printf "\n%s==>%s %s\n" "$BOLD" "$RESET_C" "$1"; }
ok()   { printf "    %s✓%s %s\n" "$GREEN" "$RESET_C" "$1"; }
warn() { printf "    %s!%s %s\n" "$YELLOW" "$RESET_C" "$1"; }
die()  { printf "\n%sError:%s %s\n\n" "$RED" "$RESET_C" "$1" >&2; exit 1; }

# ── arguments ─────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --install-only)     START=0; shift ;;
    --reset-passwords)  RESET=1; shift ;;
    --uninstall)        UNINSTALL=1; shift ;;
    --share)            HOST="0.0.0.0"; shift ;;
    --port)             PORT="${2:-}"; [ -n "$PORT" ] || die "--port needs a number"; shift 2 ;;
    -h|--help)          sed -n '3,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)                  die "Unknown option: $1  (try --help)" ;;
  esac
done

cd "$(dirname "$0")"

# ── python ────────────────────────────────────────────────────────────────
PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 &&
     "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
    PY="$candidate"; break
  fi
done
[ -n "$PY" ] || die "Python 3.8 or newer is required but was not found.
       Ubuntu/Debian:  sudo apt install python3 python3-pip"

# ── uninstall ─────────────────────────────────────────────────────────────
if [ "$UNINSTALL" -eq 1 ]; then
  step "Removing the packages this script installed"
  PIP_ARGS=""
  "$PY" -m pip uninstall -y firewall_analyzer $PIP_ARGS 2>/dev/null ||
    "$PY" -m pip uninstall -y --break-system-packages firewall_analyzer 2>/dev/null || true
  ok "firewall_analyzer removed"
  printf "    %sfastapi, uvicorn, python-multipart and openpyxl were left in place;%s\n" "$DIM" "$RESET_C"
  printf "    %sremove them with: %s -m pip uninstall fastapi uvicorn python-multipart openpyxl%s\n\n" \
    "$DIM" "$PY" "$RESET_C"
  printf "    %sYour data in var/ was not touched.%s\n\n" "$DIM" "$RESET_C"
  exit 0
fi

# ── 1. the code ───────────────────────────────────────────────────────────
step "Checking the repository"

[ -f "pyproject.toml" ] || die "Run this from inside the firewall_analyzer directory.
       On a fresh machine:  git clone -b $BRANCH $REPO_URL"

# The web interface only exists on the $BRANCH branch; main is older. Cloning
# without -b lands on main, where there is no webui and no [ui] extra, and the
# install then fails with a confusing 'does not provide the extra' warning.
if [ ! -d "src/firewall_analyzer/webui" ]; then
  CURRENT="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
  warn "This checkout ($CURRENT) has no web interface."
  if git rev-parse --verify "origin/$BRANCH" >/dev/null 2>&1; then
    printf "      Switch to the '%s' branch now? [Y/n] " "$BRANCH"
    read -r reply </dev/tty || reply="y"
    case "${reply:-y}" in
      [Nn]*) die "Nothing to install on this branch." ;;
      *) git checkout "$BRANCH" && git pull --ff-only origin "$BRANCH"
         ok "switched to $BRANCH" ;;
    esac
  else
    die "Branch '$BRANCH' not found. Try:  git fetch origin && git checkout $BRANCH"
  fi
else
  ok "web interface present"
fi

ok "$("$PY" --version)"

# ── 2. install into the user account ──────────────────────────────────────
step "Installing into your user account"

"$PY" -m pip --version >/dev/null 2>&1 || die "pip is not available for $PY.
       Ubuntu/Debian:  sudo apt install python3-pip"

# Debian, Ubuntu 23.04+ and Fedora mark the system Python "externally managed"
# (PEP 668), which makes pip refuse to install outside a virtual environment.
# Installing to --user keeps everything under ~/.local and never writes to
# /usr, so the only extra flag needed is the one that acknowledges the marker.
EXTRA=""
if "$PY" -c 'import sysconfig,os,sys; sys.exit(0 if os.path.exists(os.path.join(sysconfig.get_path("stdlib"),"EXTERNALLY-MANAGED")) else 1)'; then
  EXTRA="--break-system-packages"
  warn "system Python is marked externally managed (PEP 668)"
  printf "      %sinstalling to ~/.local with --break-system-packages;%s\n" "$DIM" "$RESET_C"
  printf "      %snothing under /usr is modified%s\n" "$DIM" "$RESET_C"
fi

# shellcheck disable=SC2086
if ! "$PY" -m pip install --user --quiet $EXTRA -e ".[ui]"; then
  die "Install failed.
       If you are offline, fastapi, uvicorn, python-multipart and openpyxl
       cannot be downloaded. Otherwise re-run without --quiet to see why:
         $PY -m pip install --user $EXTRA -e \".[ui]\""
fi
ok "installed to ~/.local"

if [ -f "data/palo_alto_applipedia.json" ]; then
  ok "Applipedia database found ($(du -h data/palo_alto_applipedia.json | cut -f1))"
else
  warn "Applipedia database missing — analyses still run, without application risk"
fi

# The console script lands in ~/.local/bin, which is not always on PATH.
# Running it as a module sidesteps that entirely, so it works either way.
LAUNCH_BIN="$("$PY" -c 'import sysconfig,os; print(os.path.join(sysconfig.get_path("scripts", "posix_user" if os.name=="posix" else "nt_user"), "firewall-analyzer-ui"))' 2>/dev/null || echo "")"
if [ -n "$LAUNCH_BIN" ] && [ -x "$LAUNCH_BIN" ]; then
  case ":$PATH:" in
    *":$(dirname "$LAUNCH_BIN"):"*) ok "firewall-analyzer-ui is on your PATH" ;;
    *) warn "$(dirname "$LAUNCH_BIN") is not on your PATH"
       printf "      %sadd it with: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc%s\n" \
         "$DIM" "$RESET_C" ;;
  esac
fi

# ── 3. run ────────────────────────────────────────────────────────────────
if [ "$RESET" -eq 1 ]; then
  step "Resetting account passwords"
  exec "$PY" -m firewall_analyzer.webui.cli --reset-passwords
fi

if [ "$START" -eq 0 ]; then
  step "Done"
  printf "    Start it with:  %s./setup.sh%s\n" "$BOLD" "$RESET_C"
  printf "    Or directly:    %sfirewall-analyzer-ui%s\n\n" "$DIM" "$RESET_C"
  exit 0
fi

step "Starting the web interface"
if [ -f "var/firewall_analyzer.db" ]; then
  ok "existing database found — accounts were NOT recreated"

  # The passwords above are only applied when the accounts are first created.
  # If this database predates them, signing in with them fails and the reason
  # is invisible — so check the stored hash and say so outright.
  if ! "$PY" - <<'PYCHECK'
import os, sys
sys.path.insert(0, "src")
os.environ.setdefault("FWA_DATA_DIR", os.path.join(os.getcwd(), "var"))
try:
    from firewall_analyzer.webui import auth, store
    user = store.get_user_by_username("admin")
    expected = os.environ.get("FWA_PASSWORD_ADMIN", "")
    sys.exit(0 if user and expected and auth.verify_password(expected, user["password_hash"]) else 1)
except Exception:
    sys.exit(0)   # cannot tell; stay quiet rather than cry wolf
PYCHECK
  then
    printf "\n    %s!%s %sThe admin password is not the one this script would set.%s\n" \
      "$YELLOW" "$RESET_C" "$BOLD" "$RESET_C"
    printf "      This database was created earlier, so the passwords above were ignored.\n"
    printf "      Fix it with:  %s./setup.sh --reset-passwords%s\n\n" "$BOLD" "$RESET_C"
  else
    ok "the four default passwords are current"
  fi
else
  ok "first run — the four accounts will be created and printed below"
fi

# Run as a module rather than by command name: identical behaviour, but immune
# to ~/.local/bin being absent from PATH. A browser tab opens automatically.
exec "$PY" -m firewall_analyzer.webui.cli --host "$HOST" --port "$PORT"
