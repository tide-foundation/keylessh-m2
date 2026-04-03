#!/bin/bash
set -e

# Build Punchd VPN MSI installer
#
# Prerequisites:
#   Linux:   sudo apt install msitools gcab
#   Windows: dotnet tool install --global wix
#
# Usage:
#   ./build-msi.sh [path-to-exe] [version]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXE_PATH="${1:-$SCRIPT_DIR/../target/x86_64-pc-windows-gnu/release/punchd-vpn.exe}"
VERSION="${2:-1.0.0}"
OUTPUT="$SCRIPT_DIR/punchd-vpn-${VERSION}.msi"

if [ ! -f "$EXE_PATH" ]; then
    echo "Error: punchd-vpn.exe not found at $EXE_PATH"
    echo "Build it first:"
    echo "  cargo build --release --target x86_64-pc-windows-gnu --bin punchd-vpn"
    exit 1
fi

echo "Building Punchd VPN MSI..."
echo "  Exe: $EXE_PATH"
echo "  Version: $VERSION"

if command -v wix &>/dev/null; then
    echo "  Builder: wix (WiX Toolset)"
    cp "$EXE_PATH" "$SCRIPT_DIR/punchd-vpn.exe"
    wix build "$SCRIPT_DIR/punchd-vpn.wxs" -arch x64 -o "$OUTPUT"
    rm -f "$SCRIPT_DIR/punchd-vpn.exe"
elif command -v msibuild &>/dev/null; then
    echo "  Builder: msibuild (msitools)"

    if ! command -v gcab &>/dev/null; then
        echo "Error: gcab not found. Install: sudo apt install gcab"
        exit 1
    fi

    WORK=$(mktemp -d)
    trap "rm -rf $WORK" EXIT

    EXE_NAME="punchd-vpn.exe"
    EXE_SIZE=$(stat -c%s "$EXE_PATH")
    cp "$EXE_PATH" "$WORK/$EXE_NAME"

    PRODUCT_CODE="{$(python3 -c 'import uuid; print(str(uuid.uuid4()).upper())')}"
    UPGRADE_CODE="{8B5E2F3A-4C1D-4A7E-9F2B-1D3E5A7C9B0F}"

    # Create cabinet
    (cd "$WORK" && gcab -c punchd.cab "$EXE_NAME")

    # --- Build IDT files (tab-delimited, real tabs) ---
    T=$'\t'

    # Property table
    cat > "$WORK/_SummaryInformation.idt" <<EOF
PropertyId${T}Value
i2${T}l255
_SummaryInformation${T}PropertyId
2${T}Punchd VPN
3${T}Punchd VPN
4${T}KeyleSSH
7${T}Intel;1033
9${T}${PRODUCT_CODE}
14${T}200
15${T}2
EOF

    cat > "$WORK/Property.idt" <<EOF
Property${T}Value
s72${T}l0
Property${T}Property
ProductName${T}Punchd VPN
ProductVersion${T}${VERSION}
Manufacturer${T}KeyleSSH
ProductCode${T}${PRODUCT_CODE}
UpgradeCode${T}${UPGRADE_CODE}
ProductLanguage${T}1033
SecureCustomProperties${T}INSTALLFOLDER
EOF

    cat > "$WORK/Directory.idt" <<EOF
Directory${T}Directory_Parent${T}DefaultDir
s72${T}S72${T}l255
Directory${T}Directory
TARGETDIR${T}${T}SourceDir
ProgramFiles64Folder${T}TARGETDIR${T}.
INSTALLFOLDER${T}ProgramFiles64Folder${T}Punchd VPN
CommonAppDataFolder${T}TARGETDIR${T}.
PunchdVpnDataDir${T}CommonAppDataFolder${T}punchd-vpn
EOF

    cat > "$WORK/Component.idt" <<EOF
Component${T}ComponentId${T}Directory_${T}Attributes${T}Condition${T}KeyPath
s72${T}S38${T}s72${T}i2${T}S255${T}S72
Component${T}Component
MainExecutable${T}{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}${T}INSTALLFOLDER${T}256${T}${T}PunchdVpnExe
ConfigDir${T}{B2C3D4E5-F6A7-8901-BCDE-F12345678901}${T}PunchdVpnDataDir${T}4${T}${T}ConfigReg
EOF

    cat > "$WORK/File.idt" <<EOF
File${T}Component_${T}FileName${T}FileSize${T}Version${T}Language${T}Attributes${T}Sequence
s72${T}s72${T}l255${T}i4${T}S72${T}S20${T}I2${T}i4
File${T}File
PunchdVpnExe${T}MainExecutable${T}punchd-vpn.exe${T}${EXE_SIZE}${T}${T}${T}512${T}1
EOF

    cat > "$WORK/Feature.idt" <<EOF
Feature${T}Feature_Parent${T}Title${T}Description${T}Display${T}Level${T}Directory_${T}Attributes
s38${T}S38${T}L64${T}L255${T}I2${T}i2${T}S72${T}i2
Feature${T}Feature
ProductFeature${T}${T}Punchd VPN${T}WebRTC VPN client${T}${T}1${T}INSTALLFOLDER${T}0
EOF

    cat > "$WORK/FeatureComponents.idt" <<EOF
Feature_${T}Component_
s38${T}s72
FeatureComponents${T}Feature_${T}Component_
ProductFeature${T}MainExecutable
ProductFeature${T}ConfigDir
EOF

    cat > "$WORK/Media.idt" <<EOF
DiskId${T}LastSequence${T}DiskPrompt${T}Cabinet${T}VolumeLabel${T}Source
i2${T}i4${T}L64${T}S255${T}S32${T}S72
Media${T}DiskId
1${T}1${T}${T}#punchd.cab${T}${T}
EOF

    cat > "$WORK/Registry.idt" <<EOF
Registry${T}Root${T}Key${T}Name${T}Value${T}Component_
s72${T}i2${T}l255${T}L255${T}L0${T}s72
Registry${T}Registry
ConfigReg${T}2${T}Software\\KeyleSSH\\PunchdVPN${T}Installed${T}#1${T}ConfigDir
EOF

    cat > "$WORK/ServiceInstall.idt" <<EOF
ServiceInstall${T}Name${T}DisplayName${T}ServiceType${T}StartType${T}ErrorControl${T}LoadOrderGroup${T}Dependencies${T}StartName${T}Password${T}Arguments${T}Component_${T}Description
s72${T}s255${T}L255${T}i4${T}i4${T}i4${T}S255${T}S255${T}S255${T}S255${T}S255${T}s72${T}L255
ServiceInstall${T}ServiceInstall
PunchdVpnSvc${T}punchd-vpn${T}Punchd VPN Service${T}16${T}2${T}1${T}${T}${T}${T}${T}--service${T}MainExecutable${T}VPN client for punchd-bridge gateways
EOF

    cat > "$WORK/ServiceControl.idt" <<EOF
ServiceControl${T}Name${T}Event${T}Arguments${T}Wait${T}Component_
s72${T}l255${T}i2${T}S255${T}I2${T}s72
ServiceControl${T}ServiceControl
PunchdVpnCtl${T}punchd-vpn${T}177${T}${T}1${T}MainExecutable
EOF

    # InstallExecuteSequence — the critical table that tells MSI what to do
    cat > "$WORK/InstallExecuteSequence.idt" <<EOF
Action${T}Condition${T}Sequence
s72${T}S255${T}I2
InstallExecuteSequence${T}Action
CostInitialize${T}${T}800
FileCost${T}${T}900
CostFinalize${T}${T}1000
InstallValidate${T}${T}1400
InstallInitialize${T}${T}1500
ProcessComponents${T}${T}1600
UnpublishFeatures${T}${T}1800
StopServices${T}${T}2000
DeleteServices${T}${T}2010
RemoveRegistryValues${T}${T}2600
RemoveFiles${T}${T}3500
RemoveFolders${T}${T}3600
CreateFolders${T}${T}3700
InstallFiles${T}${T}4000
WriteRegistryValues${T}${T}5000
InstallServices${T}${T}5800
StartServices${T}${T}5900
RegisterUser${T}${T}6000
RegisterProduct${T}${T}6100
PublishFeatures${T}${T}6300
PublishProduct${T}${T}6400
InstallFinalize${T}${T}6600
EOF

    # InstallUISequence (minimal — needed for GUI mode)
    cat > "$WORK/InstallUISequence.idt" <<EOF
Action${T}Condition${T}Sequence
s72${T}S255${T}I2
InstallUISequence${T}Action
CostInitialize${T}${T}800
FileCost${T}${T}900
CostFinalize${T}${T}1000
ExecuteAction${T}${T}1300
EOF

    # Create MSI
    rm -f "$OUTPUT"

    # Set summary info
    msibuild "$OUTPUT" -s \
        "Punchd VPN" \
        "KeyleSSH" \
        "x64;1033" \
        "$PRODUCT_CODE"

    # Import all tables
    for idt in Property Directory Component File Feature FeatureComponents \
               Media Registry ServiceInstall ServiceControl \
               InstallExecuteSequence InstallUISequence; do
        msibuild "$OUTPUT" -i "$WORK/$idt.idt"
    done

    # Embed cabinet
    msibuild "$OUTPUT" -a punchd.cab "$WORK/punchd.cab"

else
    echo "Error: No MSI build tool found."
    echo "  Linux:   sudo apt install msitools gcab"
    echo "  Windows: dotnet tool install --global wix"
    exit 1
fi

if [ -f "$OUTPUT" ]; then
    SIZE=$(du -h "$OUTPUT" | cut -f1)
    echo ""
    echo "MSI built: $OUTPUT ($SIZE)"
    echo ""
    echo "Install (GUI):    msiexec /i punchd-vpn-${VERSION}.msi"
    echo "Install (silent): msiexec /i punchd-vpn-${VERSION}.msi /qn"
else
    echo "Error: MSI was not produced"
    exit 1
fi
