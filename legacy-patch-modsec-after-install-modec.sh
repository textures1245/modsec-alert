#!/bin/bash
set -e

# =============================================================================
# NGINX MODSEC RULE PATCH SCRIPT
# =============================================================================
# This script overwrites ONLY selected ModSecurity rule files inside:
#   /etc/nginx/modsec
#
# It does NOT:
#   - delete any files
#   - modify coreruleset/
#   - auto reload nginx
#
# After patch:
#   1. nginx -t
#   2. systemctl reload nginx
#
# Manual rollback steps:
#   1. Remove modified files
#   2. Restore from backup directory shown below
#   3. Run nginx -t
#   4. Reload nginx
# =============================================================================

MODSEC_DIR="/etc/nginx/modsec"
LOCAL_RULES_DIR="$(pwd)/rules"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
BACKUP_DIR="/etc/nginx/modsec-backup-${TIMESTAMP}"

echo "[+] Starting ModSecurity rule patch..."

# -----------------------------------------------------------------------------
# 1. Validate directory
# -----------------------------------------------------------------------------
if [ ! -d "$MODSEC_DIR" ]; then
  echo "[!] ERROR: $MODSEC_DIR not found."
  exit 1
fi

if [ ! -d "$LOCAL_RULES_DIR" ]; then
  echo "[!] ERROR: Local rules directory not found."
  exit 1
fi

# -----------------------------------------------------------------------------
# 2. Backup entire modsec directory
# -----------------------------------------------------------------------------
echo "[+] Creating backup at $BACKUP_DIR"
cp -a "$MODSEC_DIR" "$BACKUP_DIR"

# -----------------------------------------------------------------------------
# 3. Overwrite specific files only
# -----------------------------------------------------------------------------
echo "[+] Updating selected rule files..."

FILES=(
  "main.conf"
  "modsecurity.conf"
  "sec_actions.conf"
  "sec_base_modsecurity_disable.conf"
  "sec_rule_removal.conf"
)

for file in "${FILES[@]}"; do
  if [ -f "$LOCAL_RULES_DIR/$file" ]; then
    cp -f "$LOCAL_RULES_DIR/$file" "$MODSEC_DIR/$file"
    echo "    - Updated $file"
  else
    echo "    - Skipped $file (not found locally)"
  fi
done

echo ""
echo "[✓] Patch completed."
echo ""
echo "Next steps:"
echo "  sudo nginx -t"
echo "  sudo systemctl reload nginx"
echo ""
echo "Backup available at:"
echo "  $BACKUP_DIR"
