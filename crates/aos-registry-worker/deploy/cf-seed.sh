#!/usr/bin/env bash
# cf-seed.sh — seed a Cloudflare deployment of the AOS registry Worker.
#
# The Worker is read-only (no write/admin API), so a new deployment is bootstrapped
# entirely through `wrangler`: apply the D1 schema, insert the registry row (its
# `trust_keys` are the cryptographic root of trust), and upload the signed surface
# to R2. The Cron indexer then derives packages/channels/releases from R2.
#
# This is OPERATOR tooling run on a developer machine against your Cloudflare
# account (not a hermetic build) — it shells out to `wrangler`. See DEPLOY.md for
# the full walkthrough, including provisioning and `wrangler deploy`.
#
# Usage:
#   deploy/cf-seed.sh \
#     --slug demo --prefix demo \
#     --surface ./surface \
#     --trust-key 'maintainer:Ed25519:AAAAC3NzaC1lZDI1NTE5...' \
#     [--trust-key '<another roster line>'] \
#     [--db aos-registry-hub] [--bucket aos-registry-surfaces] \
#     [--source-url 'r2://aos-registry-surfaces/demo'] \
#     [--visibility public] [--require-signatures 1] \
#     [--apply-schema] [--local] [--wrangler 'nix run .#miniflare -- wrangler']
#
# Run with no surface upload by passing an empty/absent --surface (schema +
# registry row only). Idempotent for the surface upload; the registry-row INSERT
# uses INSERT OR REPLACE keyed on the unique slug.
set -euo pipefail

DB="aos-registry-hub"
BUCKET="aos-registry-surfaces"
SLUG=""
PREFIX=""
SURFACE=""
SOURCE_URL=""
VISIBILITY="public"
REQUIRE_SIGS="1"
REMOTE="--remote"
APPLY_SCHEMA="0"
WRANGLER="wrangler"
TRUST_KEYS=()

die() { echo "cf-seed: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --slug) SLUG="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --surface) SURFACE="$2"; shift 2 ;;
    --trust-key) TRUST_KEYS+=("$2"); shift 2 ;;
    --db) DB="$2"; shift 2 ;;
    --bucket) BUCKET="$2"; shift 2 ;;
    --source-url) SOURCE_URL="$2"; shift 2 ;;
    --visibility) VISIBILITY="$2"; shift 2 ;;
    --require-signatures) REQUIRE_SIGS="$2"; shift 2 ;;
    --apply-schema) APPLY_SCHEMA="1"; shift ;;
    --local) REMOTE="--local"; shift ;;
    --wrangler) WRANGLER="$2"; shift 2 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$SLUG" ] || die "--slug is required"
[ "${#TRUST_KEYS[@]}" -gt 0 ] || die "at least one --trust-key is required (the registry's trust anchor)"
[ -n "$PREFIX" ] || PREFIX="$SLUG"
[ -n "$SOURCE_URL" ] || SOURCE_URL="r2://$BUCKET/$PREFIX"

# `wrangler` may be a multi-word launcher (e.g. "nix run .#miniflare -- wrangler").
# shellcheck disable=SC2206
WRANGLER_CMD=($WRANGLER)
SCHEMA_FILE="$(cd "$(dirname "$0")/.." && pwd)/migrations/0001_schema.sql"

run_wrangler() { "${WRANGLER_CMD[@]}" "$@"; }

# Build the trust_keys JSON array from the roster lines, JSON-escaping each.
json_trust_keys() {
  local out="[" first=1 k esc
  for k in "${TRUST_KEYS[@]}"; do
    esc=${k//\\/\\\\}; esc=${esc//\"/\\\"}
    if [ "$first" = 1 ]; then first=0; else out+=","; fi
    out+="\"$esc\""
  done
  out+="]"
  printf '%s' "$out"
}

echo "==> Target D1=$DB  R2=$BUCKET  registry=$SLUG (prefix '$PREFIX', $VISIBILITY)  $REMOTE"

if [ "$APPLY_SCHEMA" = "1" ]; then
  [ -f "$SCHEMA_FILE" ] || die "schema not found at $SCHEMA_FILE"
  echo "==> Applying D1 schema"
  run_wrangler d1 execute "$DB" $REMOTE --file "$SCHEMA_FILE"
fi

echo "==> Seeding registry row + trust anchor"
TRUST_JSON="$(json_trust_keys)"
# Escape single quotes for the SQL string literals.
SLUG_SQL=${SLUG//\'/\'\'}
SRC_SQL=${SOURCE_URL//\'/\'\'}
TRUST_SQL=${TRUST_JSON//\'/\'\'}
VIS_SQL=${VISIBILITY//\'/\'\'}
PREFIX_SQL=${PREFIX//\'/\'\'}
run_wrangler d1 execute "$DB" $REMOTE --command \
"INSERT OR REPLACE INTO registries
   (slug, source_url, trust_keys, require_signatures, created_at, visibility, prefix)
 VALUES
   ('$SLUG_SQL', '$SRC_SQL', '$TRUST_SQL', $REQUIRE_SIGS, unixepoch(), '$VIS_SQL', '$PREFIX_SQL');"

if [ -n "$SURFACE" ]; then
  [ -d "$SURFACE" ] || die "surface dir not found: $SURFACE"
  echo "==> Uploading surface from $SURFACE to R2 under '$PREFIX/'"
  count=0
  while IFS= read -r -d '' f; do
    rel=${f#"$SURFACE"/}
    run_wrangler r2 object put "$BUCKET/$PREFIX/$rel" --file "$f" $REMOTE >/dev/null
    count=$((count + 1))
  done < <(find "$SURFACE" -type f -print0)
  echo "==> Uploaded $count surface objects"
fi

echo "==> Done. Next: 'wrangler deploy', then let the */15 Cron index — or force it"
echo "    now with 'wrangler dev --test-scheduled' + curl /__scheduled."
