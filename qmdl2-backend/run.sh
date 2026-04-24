#!/usr/bin/env bash
# ──────────────────────────────────────────────
# QMDL2 UE Log Decoder — Setup & Run
# ──────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}━━━ QMDL2 UE Log Decoder ━━━${NC}"
echo ""

# ── Step 1: Check Python ──
echo -e "${YELLOW}[1/4] Checking Python...${NC}"
if command -v python3 &>/dev/null; then
    PY=$(python3 --version)
    echo -e "  ${GREEN}✓ $PY${NC}"
else
    echo -e "  ${RED}✗ Python 3.10+ required${NC}"
    exit 1
fi

# ── Step 2: Install pip dependencies ──
echo -e "${YELLOW}[2/4] Installing Python dependencies...${NC}"
pip install -q -r requirements.txt
echo -e "  ${GREEN}✓ Dependencies installed${NC}"

# ── Step 3: Check SCAT ──
echo -e "${YELLOW}[3/4] Checking SCAT (signalcat)...${NC}"
if python3 -c "import scat" 2>/dev/null; then
    echo -e "  ${GREEN}✓ SCAT available${NC}"
else
    echo -e "  ${RED}✗ SCAT not found. Run: pip install signalcat${NC}"
fi

# ── Step 4: Check tshark ──
echo -e "${YELLOW}[4/4] Checking tshark...${NC}"
if command -v tshark &>/dev/null; then
    TSHARK_VER=$(tshark --version | head -1)
    echo -e "  ${GREEN}✓ $TSHARK_VER${NC}"
else
    echo -e "  ${RED}✗ tshark not found${NC}"
    echo -e "  Install:"
    echo -e "    Ubuntu/Debian: ${CYAN}sudo apt install tshark${NC}"
    echo -e "    macOS:         ${CYAN}brew install wireshark${NC}"
    echo ""
fi

echo ""
echo -e "${CYAN}━━━ Starting server ━━━${NC}"
echo -e "  API:  ${GREEN}http://localhost:8000${NC}"
echo -e "  Docs: ${GREEN}http://localhost:8000/docs${NC}"
echo ""

# Run FastAPI
exec fastapi dev main.py --host 0.0.0.0 --port 8000
