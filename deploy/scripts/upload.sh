#!/usr/bin/env bash
# deploy/scripts/upload.sh — Upload a signed AOS update bundle to the update server
#
# Uploads the bundle tarball and its minisign signature to the AOS update
# server. Verifies the signature file exists before uploading and confirms
# the upload integrity via server-side checksum.
#
# Usage:
#   upload.sh <bundle-path> <server-url>
#
# Arguments:
#   bundle-path  — Path to the signed bundle tarball (e.g. ./aos-update-0.2.0.tar)
#   server-url   — Base URL of the update server (e.g. https://updates.aos.dev)
#
# Environment variables:
#   AOS_UPLOAD_TOKEN  — Bearer token for authenticating with the update server
#   AOS_UPLOAD_TIMEOUT — Upload timeout in seconds (default: 600)
#
# Exit codes:
#   0 — Upload successful, checksum verified
#   1 — Invalid arguments or missing files
#   2 — Upload failed
#   3 — Checksum verification failed
#
# The update server API expects:
#   PUT /v1/bundles/<filename>          — bundle tarball
#   PUT /v1/bundles/<filename>.minisig  — detached signature
#   GET /v1/bundles/<filename>/checksum — returns SHA-256 for verification

set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────
readonly PROGNAME="$(basename "$0")"
readonly UPLOAD_TIMEOUT="${AOS_UPLOAD_TIMEOUT:-600}"

# ── Helpers ────────────────────────────────────────────────────────────
log()   { printf '[%s] %s\n' "$PROGNAME" "$*"; }
error() { printf '[%s] ERROR: %s\n' "$PROGNAME" "$*" >&2; }
die()   { error "$1"; exit "${2:-1}"; }

usage() {
  cat >&2 <<EOF
Usage: $PROGNAME <bundle-path> <server-url>

Upload a signed AOS update bundle to the update server.

Arguments:
  bundle-path   Path to the signed bundle tarball
  server-url    Base URL of the update server

Environment:
  AOS_UPLOAD_TOKEN     Bearer token for authentication (required)
  AOS_UPLOAD_TIMEOUT   Upload timeout in seconds (default: 600)
EOF
  exit 1
}

# ── Argument validation ───────────────────────────────────────────────
[ $# -eq 2 ] || usage

BUNDLE_PATH="$1"
SERVER_URL="${2%/}"  # Strip trailing slash

# Validate bundle file.
[ -f "$BUNDLE_PATH" ] || die "Bundle not found: $BUNDLE_PATH"

# Derive signature path.
SIG_PATH="${BUNDLE_PATH}.minisig"
[ -f "$SIG_PATH" ] || die "Signature not found: $SIG_PATH (bundle must be signed before upload)"

# Validate auth token.
[ -n "${AOS_UPLOAD_TOKEN:-}" ] || die "AOS_UPLOAD_TOKEN environment variable is not set"

# ── Compute local checksum ────────────────────────────────────────────
BUNDLE_NAME="$(basename "$BUNDLE_PATH")"
SIG_NAME="$(basename "$SIG_PATH")"

log "Computing local SHA-256 checksum"
LOCAL_SHA256="$(sha256sum "$BUNDLE_PATH" | cut -d' ' -f1)"
log "  Bundle:   $BUNDLE_NAME"
log "  SHA-256:  $LOCAL_SHA256"
log "  Size:     $(du -h "$BUNDLE_PATH" | cut -f1)"

# ── Upload bundle ─────────────────────────────────────────────────────
log "Uploading bundle to ${SERVER_URL}/v1/bundles/${BUNDLE_NAME}"

http_code=$(curl \
  --fail \
  --silent \
  --show-error \
  --output /dev/null \
  --write-out '%{http_code}' \
  --max-time "$UPLOAD_TIMEOUT" \
  --retry 3 \
  --retry-delay 5 \
  --retry-max-time "$((UPLOAD_TIMEOUT * 2))" \
  -X PUT \
  -H "Authorization: Bearer ${AOS_UPLOAD_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Content-SHA256: ${LOCAL_SHA256}" \
  --data-binary "@${BUNDLE_PATH}" \
  "${SERVER_URL}/v1/bundles/${BUNDLE_NAME}" \
) || die "Bundle upload failed (HTTP $http_code)" 2

log "Bundle uploaded successfully (HTTP ${http_code})"

# ── Upload signature ──────────────────────────────────────────────────
log "Uploading signature to ${SERVER_URL}/v1/bundles/${SIG_NAME}"

http_code=$(curl \
  --fail \
  --silent \
  --show-error \
  --output /dev/null \
  --write-out '%{http_code}' \
  --max-time 60 \
  --retry 3 \
  --retry-delay 5 \
  -X PUT \
  -H "Authorization: Bearer ${AOS_UPLOAD_TOKEN}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@${SIG_PATH}" \
  "${SERVER_URL}/v1/bundles/${SIG_NAME}" \
) || die "Signature upload failed (HTTP $http_code)" 2

log "Signature uploaded successfully (HTTP ${http_code})"

# ── Verify upload checksum ────────────────────────────────────────────
log "Verifying upload integrity"

remote_sha256=$(curl \
  --fail \
  --silent \
  --show-error \
  --max-time 30 \
  --retry 3 \
  --retry-delay 2 \
  -H "Authorization: Bearer ${AOS_UPLOAD_TOKEN}" \
  "${SERVER_URL}/v1/bundles/${BUNDLE_NAME}/checksum" \
) || die "Failed to retrieve remote checksum" 3

# The server may return JSON or plain text; extract the hash.
# Handle JSON: {"sha256": "abc..."} or plain: abc...
if printf '%s' "$remote_sha256" | grep -q '"sha256"'; then
  remote_sha256=$(printf '%s' "$remote_sha256" | sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([a-f0-9]*\)".*/\1/p')
fi
remote_sha256=$(printf '%s' "$remote_sha256" | tr -d '[:space:]')

if [ "$LOCAL_SHA256" != "$remote_sha256" ]; then
  error "Checksum mismatch!"
  error "  Local:  $LOCAL_SHA256"
  error "  Remote: $remote_sha256"
  die "Upload integrity verification failed — the bundle may be corrupt on the server" 3
fi

log "Checksum verified: $LOCAL_SHA256"
log "Upload complete: ${SERVER_URL}/v1/bundles/${BUNDLE_NAME}"
