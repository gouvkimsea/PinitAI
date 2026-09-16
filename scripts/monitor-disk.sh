#!/usr/bin/env bash
# ==============================================================================
# PinIt ScamCheck AI - Production Host & Volume Disk Space Monitor
# ==============================================================================
# Usage: ./scripts/monitor-disk.sh [THRESHOLD_PERCENT] [TARGET_PATH]
# Default threshold: 85%
# Default path: .
# ==============================================================================

set -euo pipefail

THRESHOLD="${1:-85}"
TARGET_PATH="${2:-.}"

echo "========================================================"
echo " PinIt AI - Disk Space Monitor"
echo " Target Path: ${TARGET_PATH}"
echo " Threshold:   ${THRESHOLD}%"
echo " Timestamp:   $(date -u +"%Y-%m-%d %H:%M:%SZ")"
echo "========================================================"

# Extract usage percentage using df
USAGE=$(df -P "${TARGET_PATH}" | awk 'NR==2 {gsub("%","",$5); print $5}')
MOUNT_POINT=$(df -P "${TARGET_PATH}" | awk 'NR==2 {print $6}')
AVAILABLE_SPACE=$(df -h -P "${TARGET_PATH}" | awk 'NR==2 {print $4}')
TOTAL_SPACE=$(df -h -P "${TARGET_PATH}" | awk 'NR==2 {print $2}')

echo "Mount Point:     ${MOUNT_POINT}"
echo "Total Storage:   ${TOTAL_SPACE}"
echo "Available Space: ${AVAILABLE_SPACE}"
echo "Current Usage:   ${USAGE}%"
echo "--------------------------------------------------------"

if [ "${USAGE}" -ge "${THRESHOLD}" ]; then
  echo "🚨 [CRITICAL ALERT] Disk usage (${USAGE}%) exceeds threshold of ${THRESHOLD}% on ${MOUNT_POINT}!"
  echo "Action Required: Check /app/storage, /app/logs, and Docker volume caches."
  exit 1
else
  echo "✅ [HEALTHY] Disk usage is within acceptable limits (${USAGE}% < ${THRESHOLD}%)."
  exit 0
fi
