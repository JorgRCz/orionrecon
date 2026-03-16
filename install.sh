#!/usr/bin/env bash
# ============================================================
# Pentest Framework — Script de instalación
# ============================================================
set +e  # no abortar si algo falla — continuar con lo que se pueda

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ $*${NC}"; }
fail() { echo -e "${RED}  ✗ $*${NC}"; }
info() { echo -e "  ℹ $*"; }

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║     OrionRecon — Instalación         ║"
echo "  ║  Attack Surface Recon Toolkit        ║"
echo "  ║  By Jorge RC                         ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

# ── Python deps ──────────────────────────────────────────
info "Instalando dependencias Python..."
if command -v pip3 &>/dev/null; then
    pip3 install --break-system-packages -r "${SCRIPT_DIR}/requirements.txt" --quiet
    ok "Python packages instalados"
elif command -v pip &>/dev/null; then
    pip install --break-system-packages -r "${SCRIPT_DIR}/requirements.txt" --quiet
    ok "Python packages instalados"
else
    fail "pip no encontrado. Instala Python 3: sudo apt install python3-pip"
    exit 1
fi

# ── nmap ─────────────────────────────────────────────────
info "Verificando nmap..."
if command -v nmap &>/dev/null; then
    ok "nmap ya instalado: $(nmap --version | head -1)"
else
    warn "nmap no encontrado. Ejecuta: sudo apt install nmap"
fi

# ── theHarvester ─────────────────────────────────────────
info "Verificando theHarvester..."
if command -v theHarvester &>/dev/null || command -v theharvester &>/dev/null; then
    ok "theHarvester ya instalado"
else
    info "Instalando theHarvester..."
    pip3 install --break-system-packages theHarvester --quiet && ok "theHarvester instalado" || warn "Fallo instalando theHarvester"
fi

# ── Go tools ─────────────────────────────────────────────
if command -v go &>/dev/null; then
    info "Go encontrado: $(go version)"

    # subfinder
    if ! command -v subfinder &>/dev/null; then
        info "Instalando subfinder..."
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null \
            && ok "subfinder instalado" || warn "Fallo instalando subfinder"
    else
        ok "subfinder ya instalado"
    fi

    # nuclei
    if ! command -v nuclei &>/dev/null; then
        info "Instalando nuclei..."
        go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null \
            && ok "nuclei instalado" || warn "Fallo instalando nuclei"
    else
        ok "nuclei ya instalado"
    fi

    # ffuf
    if ! command -v ffuf &>/dev/null; then
        info "Instalando ffuf..."
        go install github.com/ffuf/ffuf/v2@latest 2>/dev/null \
            && ok "ffuf instalado" || warn "Fallo instalando ffuf"
    else
        ok "ffuf ya instalado"
    fi

    # amass
    if ! command -v amass &>/dev/null; then
        info "Instalando amass..."
        go install github.com/owasp-amass/amass/v4/...@master 2>/dev/null \
            && ok "amass instalado" || warn "Fallo instalando amass (puede tardar)"
    else
        ok "amass ya instalado"
    fi

    # httpx
    if ! command -v httpx &>/dev/null; then
        info "Instalando httpx..."
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null \
            && ok "httpx instalado" || warn "Fallo instalando httpx"
    else
        ok "httpx ya instalado"
    fi

    # naabu
    if ! command -v naabu &>/dev/null; then
        info "Instalando naabu..."
        go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null \
            && ok "naabu instalado" || warn "Fallo instalando naabu"
    else
        ok "naabu ya instalado"
    fi

    # dnsx
    if ! command -v dnsx &>/dev/null; then
        info "Instalando dnsx..."
        go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null \
            && ok "dnsx instalado" || warn "Fallo instalando dnsx"
    else
        ok "dnsx ya instalado"
    fi

    # alterx
    if ! command -v alterx &>/dev/null; then
        info "Instalando alterx..."
        go install github.com/projectdiscovery/alterx/cmd/alterx@latest 2>/dev/null \
            && ok "alterx instalado" || warn "Fallo instalando alterx"
    else
        ok "alterx ya instalado"
    fi

    # katana
    if ! command -v katana &>/dev/null; then
        info "Instalando katana..."
        go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null \
            && ok "katana instalado" || warn "Fallo instalando katana"
    else
        ok "katana ya instalado"
    fi

    # asnmap
    if ! command -v asnmap &>/dev/null; then
        info "Instalando asnmap..."
        go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest 2>/dev/null \
            && ok "asnmap instalado" || warn "Fallo instalando asnmap"
    else
        ok "asnmap ya instalado"
    fi

    # gau
    if ! command -v gau &>/dev/null; then
        info "Instalando gau..."
        go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null \
            && ok "gau instalado" || warn "Fallo instalando gau"
    else
        ok "gau ya instalado"
    fi

    # gowitness
    if ! command -v gowitness &>/dev/null; then
        info "Instalando gowitness..."
        go install github.com/sensepost/gowitness@latest 2>/dev/null \
            && ok "gowitness instalado" || warn "Fallo instalando gowitness"
    else
        ok "gowitness ya instalado"
    fi

else
    warn "Go no encontrado. subfinder/nuclei/ffuf/amass/httpx/naabu/dnsx/alterx/katana/asnmap/gau/gowitness requieren Go."
    warn "Instala Go: https://go.dev/dl/"
fi

# ── wafw00f ───────────────────────────────────────────────
info "Verificando wafw00f..."
if command -v wafw00f &>/dev/null; then
    ok "wafw00f ya instalado"
else
    info "Instalando wafw00f..."
    pip3 install --break-system-packages wafw00f --quiet && ok "wafw00f instalado" || warn "Fallo instalando wafw00f"
fi

# ── sslscan (primario TLS) ────────────────────────────────
info "Verificando sslscan..."
if command -v sslscan &>/dev/null; then
    ok "sslscan ya instalado: $(sslscan --version 2>&1 | head -1)"
elif command -v apt &>/dev/null; then
    info "Instalando sslscan..."
    sudo apt install sslscan -y --quiet 2>/dev/null \
        && ok "sslscan instalado" || warn "Fallo instalando sslscan"
else
    warn "sslscan no disponible. Instala: sudo apt install sslscan"
fi

# ── testssl.sh (secundario TLS — análisis profundo) ───────
info "Verificando testssl.sh..."
if command -v testssl.sh &>/dev/null || command -v testssl &>/dev/null; then
    ok "testssl.sh ya instalado"
elif command -v apt &>/dev/null; then
    info "Instalando testssl.sh vía apt..."
    sudo apt install testssl.sh -y --quiet 2>/dev/null \
        && ok "testssl.sh instalado" \
        || {
            warn "No se pudo instalar via apt, clonando desde GitHub..."
            git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl.sh 2>/dev/null \
                && sudo ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
                && ok "testssl.sh instalado en /opt/testssl.sh" \
                || warn "Fallo instalando testssl.sh"
        }
else
    warn "testssl.sh no encontrado. Instala manualmente: git clone https://github.com/drwetter/testssl.sh /opt/testssl.sh"
fi

# ── SecLists ─────────────────────────────────────────────
info "Verificando wordlists..."
if [ -d "/usr/share/seclists" ] || [ -d "/opt/SecLists" ]; then
    ok "SecLists encontrado"
elif command -v apt &>/dev/null; then
    info "Instalando SecLists vía apt..."
    sudo apt install seclists -y --quiet 2>/dev/null \
        && ok "SecLists instalado" || warn "No se pudo instalar SecLists automáticamente"
else
    warn "SecLists no encontrado. Instala: sudo apt install seclists"
    warn "O manualmente: git clone https://github.com/danielmiessler/SecLists /opt/SecLists"
fi

# ── nuclei templates ─────────────────────────────────────
if command -v nuclei &>/dev/null; then
    info "Actualizando nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && ok "Templates actualizados" \
        || warn "No se pudieron actualizar templates"
fi

# ── Comando global orionrecon ─────────────────────────────
ORION_BIN="/usr/local/bin/orionrecon"
info "Registrando comando global 'orionrecon'..."

# Crear launcher script
LAUNCHER=$(mktemp)
cat > "${LAUNCHER}" << LAUNCHER_EOF
#!/usr/bin/env bash
exec python3 "${SCRIPT_DIR}/pentest.py" "\$@"
LAUNCHER_EOF

if sudo mv "${LAUNCHER}" "${ORION_BIN}" && sudo chmod +x "${ORION_BIN}"; then
    ok "Comando 'orionrecon' instalado en ${ORION_BIN}"
else
    # Fallback sin sudo: instalar en ~/.local/bin
    LOCAL_BIN="${HOME}/.local/bin"
    mkdir -p "${LOCAL_BIN}"
    LAUNCHER2=$(mktemp)
    cat > "${LAUNCHER2}" << LAUNCHER_EOF2
#!/usr/bin/env bash
exec python3 "${SCRIPT_DIR}/pentest.py" "\$@"
LAUNCHER_EOF2
    mv "${LAUNCHER2}" "${LOCAL_BIN}/orionrecon"
    chmod +x "${LOCAL_BIN}/orionrecon"
    ok "Comando 'orionrecon' instalado en ${LOCAL_BIN}/orionrecon"

    # Añadir ~/.local/bin al PATH si no está
    SHELL_RC=""
    if [ -n "${ZSH_VERSION}" ] || [ "$(basename "${SHELL}")" = "zsh" ]; then
        SHELL_RC="${HOME}/.zshrc"
    else
        SHELL_RC="${HOME}/.bashrc"
    fi

    if ! grep -q "${LOCAL_BIN}" "${SHELL_RC}" 2>/dev/null; then
        echo "export PATH=\"\$PATH:${LOCAL_BIN}\"" >> "${SHELL_RC}"
        ok "PATH actualizado en ${SHELL_RC}"
        warn "Reinicia el terminal o ejecuta: source ${SHELL_RC}"
    fi
fi

# ── Permisos ─────────────────────────────────────────────
chmod +x "${SCRIPT_DIR}/pentest.py"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║     OrionRecon — Listo               ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
echo "  Uso:"
echo "    orionrecon check                                   # verificar herramientas"
echo "    orionrecon scan objetivo.com                       # scan completo"
echo "    orionrecon scan objetivo.com -m recon nmap nuclei  # módulos específicos"
echo "    orionrecon nmap 192.168.1.1 -p quick web vuln      # nmap artillery"
echo "    orionrecon recon objetivo.com                      # solo OSINT"
echo "    orionrecon tech https://objetivo.com               # tech detection"
echo "    orionrecon fuzz https://objetivo.com -m directories parameters"
echo ""
