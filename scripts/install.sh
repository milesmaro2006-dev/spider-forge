#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  SpiderForge — One-shot installer
#  Supports: Kali / Debian / Ubuntu / macOS
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

APP=spiderforge
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Colors ───
CYAN=$'\033[1;36m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'
RED=$'\033[1;31m'; DIM=$'\033[2m'; RESET=$'\033[0m'

log()  { printf "%s[%s]%s %s\n" "$CYAN" "$APP" "$RESET" "$*"; }
ok()   { printf "%s[✓]%s %s\n" "$GREEN" "$RESET" "$*"; }
warn() { printf "%s[!]%s %s\n" "$YELLOW" "$RESET" "$*"; }
die()  { printf "%s[✗]%s %s\n" "$RED" "$RESET" "$*" >&2; exit 1; }
ask()  { printf "%s[?]%s %s " "$CYAN" "$RESET" "$*"; }

# ═══════════════════════════════════════════════════════════════
#  Banner
# ═══════════════════════════════════════════════════════════════
printf "%s" "$CYAN"
cat <<'BANNER'
    ███████╗██████╗ ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
    ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
    ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
    ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██║██║   ██║██╔══╝
    ███████║██║     ██║██████╔╝███████╗██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
    ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
BANNER
printf "%s\n" "$RESET"

# ═══════════════════════════════════════════════════════════════
#  1) Python check
# ═══════════════════════════════════════════════════════════════
PY="$(command -v python3 || true)"
[ -n "$PY" ] || die "python3 not found. Install Python 3.10+ first."
"$PY" - <<'PY' || die "Python >= 3.10 required"
import sys
raise SystemExit(0 if sys.version_info[:2] >= (3, 10) else 1)
PY
ok "Python OK: $($PY --version 2>&1)"

# ═══════════════════════════════════════════════════════════════
#  2) pipx check (install if missing)
# ═══════════════════════════════════════════════════════════════
if ! command -v pipx >/dev/null 2>&1; then
    warn "pipx not found — installing..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
        sudo apt-get install -y pipx || die "apt install pipx failed"
    else
        "$PY" -m pip install --user --upgrade pipx || die "pipx install failed"
    fi
    "$PY" -m pipx ensurepath || true
    # أضف pipx للـ PATH في الجلسة الحالية
    export PATH="$HOME/.local/bin:$PATH"
    ok "pipx installed"
else
    ok "pipx available: $(pipx --version)"
fi

# ═══════════════════════════════════════════════════════════════
#  3) Install spiderforge core via pipx
# ═══════════════════════════════════════════════════════════════
log "Installing SpiderForge core (from $REPO_DIR)..."
pipx install --force "$REPO_DIR" || die "spiderforge install failed"
ok "spiderforge installed"

# ═══════════════════════════════════════════════════════════════
#  4) Optional: Web Dashboard
# ═══════════════════════════════════════════════════════════════
ask "Install Web Dashboard (fastapi + uvicorn)? [y/N]"
read -r WEB
if [[ "${WEB:-N}" =~ ^[Yy]$ ]]; then
    log "Installing web extras..."
    pipx inject spiderforge fastapi "uvicorn[standard]" \
        || warn "web inject failed — install manually: pipx inject spiderforge fastapi uvicorn[standard]"
    ok "Web Dashboard ready"
else
    printf "%s  Skipped. Install later with:%s\n" "$DIM" "$RESET"
    printf "%s    pipx inject spiderforge fastapi 'uvicorn[standard]'%s\n" "$DIM" "$RESET"
fi

# ═══════════════════════════════════════════════════════════════
#  5) Optional: PDF export
# ═══════════════════════════════════════════════════════════════
ask "Install PDF export (weasyprint)? [y/N]"
read -r PDF
if [[ "${PDF:-N}" =~ ^[Yy]$ ]]; then
    log "Installing PDF engine..."
    # system libs (Linux only)
    if command -v apt-get >/dev/null 2>&1; then
        log "Installing system libraries for WeasyPrint..."
        sudo apt-get install -y --no-install-recommends \
            libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
            || warn "some system libs failed to install"
    fi
    pipx inject spiderforge weasyprint \
        || warn "weasyprint inject failed — install manually"
    ok "PDF export ready"
else
    printf "%s  Skipped. Install later with:%s\n" "$DIM" "$RESET"
    printf "%s    pipx inject spiderforge weasyprint%s\n" "$DIM" "$RESET"
fi

# ═══════════════════════════════════════════════════════════════
#  6) Create user directories
# ═══════════════════════════════════════════════════════════════
mkdir -p "$HOME/.spiderforge/workspaces" \
         "$HOME/.spiderforge/logs" \
         "$HOME/.config/spiderforge"
ok "Created ~/.spiderforge and ~/.config/spiderforge"

# ═══════════════════════════════════════════════════════════════
#  7) Default config
# ═══════════════════════════════════════════════════════════════
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
  enable_json: true
  enable_html: true
  enable_markdown: true
  enable_pdf: false
logging:
  level: INFO
YAML
    ok "Wrote default config to $CFG"
fi

# ═══════════════════════════════════════════════════════════════
#  8) Health check
# ═══════════════════════════════════════════════════════════════
echo ""
log "Running pre-flight health check..."
if command -v spiderforge >/dev/null 2>&1; then
    spiderforge doctor || warn "doctor returned non-zero"
else
    warn "spiderforge not on PATH yet."
    warn "Restart your shell, or run: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
ok "Installation complete!"
printf "%sRun:%s  %sspiderforge%s\n" "$DIM" "$RESET" "$GREEN" "$RESET"
