#!/usr/bin/env bash
# =============================================================================
# build_rpm.sh — Research-to-Production RPM Packager for GNN-IDS
# Requires: rpmbuild, rpmdevtools (Fedora: sudo dnf install rpmdevtools rpm-build)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_PATH="${SCRIPT_DIR}/src/model.onnx"
EXTRACTOR_PATH="${SCRIPT_DIR}/src/feature_extractor.pkl"
SPEC_FILE="${SCRIPT_DIR}/packaging/gnn-ids.spec"
PKG_NAME="gnn-ids"
PKG_VERSION="1.0.0"
PKG_RELEASE="1"

# ANSI colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

banner() { echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"; \
           echo -e "${BLUE}║   GNN-IDS  RPM  Build  System            ║${NC}"; \
           echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"; }

check_deliverables() {
    local missing=0
    echo -e "\n${YELLOW}[1/4] Checking researcher deliverables...${NC}"

    if [[ ! -f "${MODEL_PATH}" ]]; then
        echo -e "  ${RED}✗  MISSING: ${MODEL_PATH}${NC}"
        missing=1
    else
        echo -e "  ${GREEN}✓  Found:   ${MODEL_PATH} ($(du -sh "${MODEL_PATH}" | cut -f1))${NC}"
    fi

    if [[ ! -f "${EXTRACTOR_PATH}" ]]; then
        echo -e "  ${RED}✗  MISSING: ${EXTRACTOR_PATH}${NC}"
        missing=1
    else
        echo -e "  ${GREEN}✓  Found:   ${EXTRACTOR_PATH} ($(du -sh "${EXTRACTOR_PATH}" | cut -f1))${NC}"
    fi

    if [[ ${missing} -eq 1 ]]; then
        echo ""
        echo -e "${RED}═══════════════════════════════════════════════════${NC}"
        echo -e "${RED}  DELIVERABLES MISSING — Cannot build RPM yet.${NC}"
        echo -e "${RED}═══════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "${YELLOW}  ► RESEARCHER INSTRUCTIONS:${NC}"
        echo ""
        echo "    1. Activate the Conda environment:"
        echo "       conda activate gnn-ids"
        echo ""
        echo "    2. Place the 8 CIC-IDS-2017 CSV files in data/"
        echo ""
        echo "    3. Run the GPU training script:"
        echo "       python src/train_gpu.py --epochs 50 --batch-size 512"
        echo ""
        echo "    4. Training will produce:"
        echo "       - src/model.onnx          (ONNX Opset 12, IR 8)"
        echo "       - src/feature_extractor.pkl"
        echo ""
        echo "    5. Send BOTH files back to the packager."
        echo ""
        echo "    6. Re-run this script: ./build_rpm.sh"
        echo ""
        exit 1
    fi
}

validate_onnx() {
    echo -e "\n${YELLOW}[2/4] Validating ONNX model...${NC}"
    python3 - <<'PYEOF'
import onnx, sys
m = onnx.load("src/model.onnx")
try:
    onnx.checker.check_model(m)
    print(f"  ✓  ONNX model valid | IR={m.ir_version} | opset={m.opset_import[0].version}")
except onnx.checker.ValidationError as e:
    print(f"  ✗  ONNX validation FAILED: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
}

setup_rpm_tree() {
    echo -e "\n${YELLOW}[3/4] Setting up rpmbuild tree...${NC}"
    rpmdev-setuptree 2>/dev/null || true

    local build_root="${HOME}/rpmbuild"
    local sources_dir="${build_root}/SOURCES"
    local src_tarball="${sources_dir}/${PKG_NAME}-${PKG_VERSION}.tar.gz"

    # Stage files
    local stage_dir="/tmp/${PKG_NAME}-${PKG_VERSION}"
    rm   -rf "${stage_dir}"
    mkdir -p "${stage_dir}/opt/gnn-ids"
    mkdir -p "${stage_dir}/usr/lib/systemd/system"
    mkdir -p "${stage_dir}/usr/bin"
    mkdir -p "${stage_dir}/var/log/gnn-ids"
    mkdir -p "${stage_dir}/etc/gnn-ids"

    cp "${MODEL_PATH}"     "${stage_dir}/opt/gnn-ids/"
    cp "${EXTRACTOR_PATH}" "${stage_dir}/opt/gnn-ids/"
    cp src/main.py         "${stage_dir}/opt/gnn-ids/"
    cp src/inference.py    "${stage_dir}/opt/gnn-ids/"
    cp packaging/gnn-ids.service "${stage_dir}/usr/lib/systemd/system/"
    cp packaging/gnn-ids.conf    "${stage_dir}/etc/gnn-ids/"

    # Launcher wrapper
    cat > "${stage_dir}/usr/bin/gnn-ids" <<'WRAPPER'
#!/usr/bin/bash
exec /usr/bin/python3 /opt/gnn-ids/main.py "$@"
WRAPPER
    chmod 755 "${stage_dir}/usr/bin/gnn-ids"

    tar -czf "${src_tarball}" -C /tmp "${PKG_NAME}-${PKG_VERSION}"
    cp "${SPEC_FILE}" "${build_root}/SPECS/"
    echo -e "  ${GREEN}✓  Source tarball: ${src_tarball}${NC}"
}

build_rpm() {
    echo -e "\n${YELLOW}[4/4] Building RPM...${NC}"
    rpmbuild -bb "${HOME}/rpmbuild/SPECS/gnn-ids.spec" \
             --define "_version ${PKG_VERSION}"        \
             --define "_release ${PKG_RELEASE}"

    local rpm_path
    rpm_path=$(find "${HOME}/rpmbuild/RPMS" -name "${PKG_NAME}-*.rpm" | head -1)
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  RPM BUILD SUCCESSFUL!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
    echo -e "  Package : ${rpm_path}"
    echo -e "  Install : sudo dnf install ${rpm_path}"
    echo -e "  Enable  : sudo systemctl enable --now gnn-ids"
    echo -e "  Logs    : journalctl -u gnn-ids -f"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────
banner
check_deliverables
validate_onnx
setup_rpm_tree
build_rpm
