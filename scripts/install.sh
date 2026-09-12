#!/usr/bin/env bash
# SpiderForge installer for Kali / Debian / Ubuntu / macOS.
set -euo pipefail

APP=spiderforge
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf "\033[1;36m[%s]\033[0m %s\n" "$APP" "$*"; }
warn() { printf "\033[1;33m[%s]\033[0m %s\n" "$APP" "$*"; }
die()  { printf "\033[1;31m[%s]\033[0m %s\n" "$APP" "$*" >&2; exit 1; }

# --- 1. Python check -------------------------------------------------------
PY="$(command -v python3 || true)"
[ -n "$PY" ] || die "python3 not found"
"$PY" - <<'PY' || die "Python >= 3.10 required"
import sys
raise SystemExit(0 if sys.version_info[:2] >= (3, 10) else 1)
PY
log "Python OK: $($PY --version 2>&1)"

# --- 2. pip/pipx ----------------------------------------------------------
if ! command -v pipx >/dev/null 2>&1; then
  warn "pipx not found. Install it for a clean isolated install:"
  warn "  python3 -m pip install --user pipx && python3 -m pipx ensurepath"
fi

# --- 3. Install -----------------------------------------------------------
if command -v pipx >/dev/null 2>&1; then
  log "Installing with pipx (from $REPO_DIR)"
  pipx install --force "$REPO_DIR"
else
  log "Falling back to pip --user"
  "$PY" -m pip install --user --upgrade "$REPO_DIR"
fi

# --- 4. Directories -------------------------------------------------------
mkdir -p "$HOME/.spiderforge/workspaces" "$HOME/.spiderforge/logs" "$HOME/.config/spiderforge"
log "Created ~/.spiderforge and ~/.config/spiderforge"

# --- 5. Default config ----------------------------------------------------
CFG="$HOME/.config/spiderforge/config.yaml"
if [ ! -f "$CFG" ]; then
  cat > "$CFG" <<'YAML'
scanner:
  concurrency: 20
  timeout: 20.0
  max_depth: 5
  aggressive: false
recon:
  subdomains: true
  ports: false
  technologies: true
browser:
  enabled: false
  screenshots: false
reporting:
  json: true
  html: true
  markdown: true
  pdf: false
logging:
  level: INFO
YAML
  log "Wrote default config to $CFG"
fi

# --- 6. Playwright (optional) --------------------------------------------
if command -v spiderforge >/dev/null 2>&1; then
  if spiderforge browser status 2>/dev/null | grep -q "installed"; then
    log "Chromium already installed"
  else
    read -r -p "$(printf '\033[1;33m[%s]\033[0m Install Chromium for browser automation? [y/N] ' "$APP")" ans || true
    case "$ans" in
      y|Y) "$PY" -m pip install --user "playwright>=1.44.0" || true
           spiderforge browser install || warn "Chromium install failed — rerun: spiderforge browser install"
           ;;
      *) warn "Skipped. Run 'spiderforge browser install' when ready." ;;
    esac
  fi

  log "Checking external tools..."
  spiderforge integrations check || true

  log "Running doctor..."
  spiderforge doctor || warn "doctor returned non-zero"

  log "Installed version: $(spiderforge --version 2>&1)"
else
  warn "spiderforge not on PATH yet — restart your shell or run 'pipx ensurepath'"
fi

log "Done."