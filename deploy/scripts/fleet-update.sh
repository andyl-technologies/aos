#!/usr/bin/env bash
# deploy/scripts/fleet-update.sh — Rolling fleet update for AOS nodes
#
# Performs a controlled rolling update across a fleet of AOS nodes.
# For each host: uploads the update bundle, triggers the update, waits
# for the node to reboot and pass health checks, then proceeds to the
# next batch.
#
# Usage:
#   fleet-update.sh [OPTIONS] <bundle-path> <inventory-file>
#
# Arguments:
#   bundle-path     Path to the signed update bundle tarball
#   inventory-file  File listing target hosts, one per line
#                   Lines starting with # are comments, empty lines are skipped
#
# Options:
#   -p, --parallelism N    Number of nodes to update concurrently (default: 1)
#   -t, --timeout N        Per-node health check timeout in seconds (default: 300)
#   -d, --delay N          Delay between batches in seconds (default: 30)
#   -u, --user USER        SSH user for remote commands (default: aos)
#   -k, --ssh-key PATH     SSH private key path (default: ~/.ssh/id_ed25519)
#   -H, --health-endpoint  Health check URL path (default: /healthz)
#   -P, --health-port N    Health check port (default: 10248)
#   --dry-run              Show what would be done without making changes
#   --no-rollback          Disable automatic rollback on failure
#   --continue-on-failure  Continue with remaining hosts after a failure
#   -h, --help             Show this help message
#
# Exit codes:
#   0 — All nodes updated successfully
#   1 — Invalid arguments
#   2 — One or more nodes failed to update
#   3 — Rollback was triggered
#
# The script expects each node to have the aos-update-tool installed,
# which handles bundle extraction, store path registration, profile
# switching, and boot entry update.

set -euo pipefail

# ── Constants ──────────────────────────────────────────────────────────
readonly PROGNAME="$(basename "$0")"
readonly TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"

# ── Defaults ───────────────────────────────────────────────────────────
PARALLELISM=1
HEALTH_TIMEOUT=300
BATCH_DELAY=30
SSH_USER="aos"
SSH_KEY="$HOME/.ssh/id_ed25519"
HEALTH_ENDPOINT="/healthz"
HEALTH_PORT=10248
DRY_RUN=false
NO_ROLLBACK=false
CONTINUE_ON_FAILURE=false

# ── State tracking ────────────────────────────────────────────────────
declare -a SUCCEEDED=()
declare -a FAILED=()
declare -a SKIPPED=()
declare -a ROLLED_BACK=()

# ── Helpers ────────────────────────────────────────────────────────────
log()   { printf '[%s] [%s] %s\n' "$PROGNAME" "$(date -u +%H:%M:%S)" "$*"; }
warn()  { printf '[%s] [%s] WARN: %s\n' "$PROGNAME" "$(date -u +%H:%M:%S)" "$*" >&2; }
error() { printf '[%s] [%s] ERROR: %s\n' "$PROGNAME" "$(date -u +%H:%M:%S)" "$*" >&2; }
die()   { error "$1"; exit "${2:-1}"; }

usage() {
  # Extract usage from the header comment.
  sed -n '/^# Usage:/,/^[^#]/{ /^#/s/^# //p; }' "$0" >&2
  echo "" >&2
  sed -n '/^# Options:/,/^[^#]/{ /^#/s/^# //p; }' "$0" >&2
  exit 1
}

# ssh_cmd HOST COMMAND — Run a command on a remote host via SSH.
ssh_cmd() {
  local host="$1"
  shift
  ssh -o ConnectTimeout=10 \
      -o StrictHostKeyChecking=accept-new \
      -o BatchMode=yes \
      -o LogLevel=ERROR \
      -i "$SSH_KEY" \
      "${SSH_USER}@${host}" \
      "$@"
}

# scp_to HOST LOCAL REMOTE — Copy a file to a remote host.
scp_to() {
  local host="$1" local_path="$2" remote_path="$3"
  scp -o ConnectTimeout=10 \
      -o StrictHostKeyChecking=accept-new \
      -o BatchMode=yes \
      -o LogLevel=ERROR \
      -i "$SSH_KEY" \
      "$local_path" \
      "${SSH_USER}@${host}:${remote_path}"
}

# wait_for_health HOST — Wait for a node to pass its health check.
wait_for_health() {
  local host="$1"
  local deadline=$((SECONDS + HEALTH_TIMEOUT))
  local attempt=0

  log "  Waiting for health check on $host (timeout: ${HEALTH_TIMEOUT}s)"

  while [ $SECONDS -lt $deadline ]; do
    attempt=$((attempt + 1))

    # Try HTTP health check first.
    if curl --silent --fail --max-time 5 \
         "http://${host}:${HEALTH_PORT}${HEALTH_ENDPOINT}" \
         > /dev/null 2>&1; then
      log "  Health check passed on $host (attempt $attempt)"
      return 0
    fi

    # Fall back to SSH connectivity check if HTTP fails.
    if [ $((attempt % 5)) -eq 0 ]; then
      if ssh_cmd "$host" "systemctl is-system-running --wait" 2>/dev/null; then
        log "  System running on $host (SSH fallback, attempt $attempt)"
        return 0
      fi
    fi

    sleep 5
  done

  error "Health check timed out on $host after ${HEALTH_TIMEOUT}s ($attempt attempts)"
  return 1
}

# rollback_node HOST — Trigger a rollback on a node.
rollback_node() {
  local host="$1"

  if $NO_ROLLBACK; then
    warn "Rollback disabled for $host (--no-rollback)"
    return 1
  fi

  log "  Triggering rollback on $host"

  if $DRY_RUN; then
    log "  [DRY RUN] Would rollback $host"
    return 0
  fi

  if ssh_cmd "$host" "sudo aos-update rollback" 2>/dev/null; then
    log "  Rollback command sent to $host"

    # Wait for the node to come back after rollback reboot.
    if wait_for_health "$host"; then
      log "  Rollback successful on $host"
      ROLLED_BACK+=("$host")
      return 0
    else
      error "Node $host did not recover after rollback"
      return 1
    fi
  else
    error "Failed to send rollback command to $host"
    return 1
  fi
}

# update_node HOST BUNDLE — Perform the full update cycle on a single node.
update_node() {
  local host="$1"
  local bundle="$2"
  local bundle_name
  bundle_name="$(basename "$bundle")"

  log "Updating node: $host"

  if $DRY_RUN; then
    log "  [DRY RUN] Would upload $bundle_name to $host"
    log "  [DRY RUN] Would trigger update on $host"
    log "  [DRY RUN] Would wait for health check on $host"
    SUCCEEDED+=("$host")
    return 0
  fi

  # ── Step 1: Upload bundle ──────────────────────────────────────────
  log "  Uploading bundle to $host"
  if ! scp_to "$host" "$bundle" "/tmp/${bundle_name}"; then
    error "Failed to upload bundle to $host"
    FAILED+=("$host")
    return 1
  fi

  # Also upload the signature.
  if [ -f "${bundle}.minisig" ]; then
    scp_to "$host" "${bundle}.minisig" "/tmp/${bundle_name}.minisig" || true
  fi

  # ── Step 2: Trigger update ─────────────────────────────────────────
  log "  Triggering update on $host"
  if ! ssh_cmd "$host" "sudo aos-update apply /tmp/${bundle_name}"; then
    error "Update command failed on $host"

    # Attempt rollback.
    if rollback_node "$host"; then
      FAILED+=("$host")
    else
      FAILED+=("$host")
    fi
    return 1
  fi

  # ── Step 3: Wait for reboot and health check ───────────────────────
  log "  Waiting for $host to reboot"
  sleep 10  # Grace period for reboot initiation.

  if ! wait_for_health "$host"; then
    error "Node $host failed health check after update"

    # Attempt rollback.
    if rollback_node "$host"; then
      warn "Node $host rolled back successfully"
    else
      error "Node $host: rollback also failed — manual intervention required"
    fi
    FAILED+=("$host")
    return 1
  fi

  # ── Step 4: Verify the new version ─────────────────────────────────
  log "  Verifying updated version on $host"
  remote_version=$(ssh_cmd "$host" "cat /etc/os-release" 2>/dev/null | \
    sed -n 's/^VERSION_ID=//p' | tr -d '"') || true

  if [ -n "$remote_version" ]; then
    log "  Node $host running version: $remote_version"
  fi

  # ── Step 5: Clean up ───────────────────────────────────────────────
  ssh_cmd "$host" "rm -f /tmp/${bundle_name} /tmp/${bundle_name}.minisig" 2>/dev/null || true

  log "  Node $host updated successfully"
  SUCCEEDED+=("$host")
  return 0
}

# ── Argument parsing ──────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    -p|--parallelism)
      PARALLELISM="$2"; shift 2 ;;
    -t|--timeout)
      HEALTH_TIMEOUT="$2"; shift 2 ;;
    -d|--delay)
      BATCH_DELAY="$2"; shift 2 ;;
    -u|--user)
      SSH_USER="$2"; shift 2 ;;
    -k|--ssh-key)
      SSH_KEY="$2"; shift 2 ;;
    -H|--health-endpoint)
      HEALTH_ENDPOINT="$2"; shift 2 ;;
    -P|--health-port)
      HEALTH_PORT="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=true; shift ;;
    --no-rollback)
      NO_ROLLBACK=true; shift ;;
    --continue-on-failure)
      CONTINUE_ON_FAILURE=true; shift ;;
    -h|--help)
      usage ;;
    -*)
      die "Unknown option: $1" 1 ;;
    *)
      break ;;
  esac
done

[ $# -eq 2 ] || usage

BUNDLE_PATH="$1"
INVENTORY_FILE="$2"

# ── Input validation ──────────────────────────────────────────────────
[ -f "$BUNDLE_PATH" ] || die "Bundle not found: $BUNDLE_PATH"
[ -f "$INVENTORY_FILE" ] || die "Inventory file not found: $INVENTORY_FILE"
[ -f "$SSH_KEY" ] || die "SSH key not found: $SSH_KEY"

# ── Parse inventory ──────────────────────────────────────────────────
declare -a HOSTS=()
while IFS= read -r line; do
  # Skip comments and empty lines.
  line="${line%%#*}"        # Strip inline comments
  line="${line// /}"        # Strip whitespace (simple)
  line="$(echo "$line" | xargs)"  # Trim
  [ -n "$line" ] || continue
  HOSTS+=("$line")
done < "$INVENTORY_FILE"

total_hosts=${#HOSTS[@]}
[ "$total_hosts" -gt 0 ] || die "No hosts found in inventory: $INVENTORY_FILE"

# ── Print plan ────────────────────────────────────────────────────────
log "============================================================"
log "AOS Fleet Update"
log "============================================================"
log "  Bundle:       $(basename "$BUNDLE_PATH")"
log "  Hosts:        $total_hosts"
log "  Parallelism:  $PARALLELISM"
log "  Timeout:      ${HEALTH_TIMEOUT}s per node"
log "  Batch delay:  ${BATCH_DELAY}s"
log "  SSH user:     $SSH_USER"
log "  Dry run:      $DRY_RUN"
log "  Auto rollback: $(if $NO_ROLLBACK; then echo "disabled"; else echo "enabled"; fi)"
log "============================================================"

if $DRY_RUN; then
  log "[DRY RUN MODE] No changes will be made"
fi

# ── Execute rolling update ────────────────────────────────────────────
batch_num=0

for ((i = 0; i < total_hosts; i += PARALLELISM)); do
  batch_num=$((batch_num + 1))
  batch_end=$((i + PARALLELISM))
  [ $batch_end -gt $total_hosts ] && batch_end=$total_hosts
  batch_size=$((batch_end - i))

  log ""
  log "── Batch $batch_num: nodes $((i + 1))-${batch_end} of $total_hosts ──"

  # Launch updates for this batch.
  declare -a BATCH_PIDS=()
  declare -a BATCH_HOSTS=()

  for ((j = i; j < batch_end; j++)); do
    host="${HOSTS[$j]}"
    BATCH_HOSTS+=("$host")

    if [ "$PARALLELISM" -eq 1 ]; then
      # Serial mode: run inline.
      if ! update_node "$host" "$BUNDLE_PATH"; then
        if ! $CONTINUE_ON_FAILURE; then
          error "Stopping fleet update due to failure on $host"
          break 2  # Exit both loops
        fi
        warn "Continuing despite failure on $host (--continue-on-failure)"
      fi
    else
      # Parallel mode: run in background.
      update_node "$host" "$BUNDLE_PATH" &
      BATCH_PIDS+=($!)
    fi
  done

  # Wait for parallel batch to complete.
  if [ "$PARALLELISM" -gt 1 ] && [ ${#BATCH_PIDS[@]} -gt 0 ]; then
    batch_failed=false
    for pid_idx in "${!BATCH_PIDS[@]}"; do
      pid="${BATCH_PIDS[$pid_idx]}"
      host="${BATCH_HOSTS[$pid_idx]}"
      if ! wait "$pid"; then
        error "Update failed for $host (PID $pid)"
        batch_failed=true
      fi
    done

    if $batch_failed && ! $CONTINUE_ON_FAILURE; then
      error "Stopping fleet update due to batch failure"
      break
    fi
  fi

  unset BATCH_PIDS BATCH_HOSTS

  # Delay between batches (skip after the last batch).
  if [ $batch_end -lt $total_hosts ] && [ "$BATCH_DELAY" -gt 0 ]; then
    log "  Waiting ${BATCH_DELAY}s before next batch"
    sleep "$BATCH_DELAY"
  fi
done

# ── Summary ───────────────────────────────────────────────────────────
log ""
log "============================================================"
log "Fleet Update Summary"
log "============================================================"
log "  Total hosts:   $total_hosts"
log "  Succeeded:     ${#SUCCEEDED[@]}"
log "  Failed:        ${#FAILED[@]}"
log "  Rolled back:   ${#ROLLED_BACK[@]}"
log "  Skipped:       ${#SKIPPED[@]}"

if [ ${#SUCCEEDED[@]} -gt 0 ]; then
  log ""
  log "  Succeeded:"
  for h in "${SUCCEEDED[@]}"; do
    log "    - $h"
  done
fi

if [ ${#FAILED[@]} -gt 0 ]; then
  log ""
  log "  Failed:"
  for h in "${FAILED[@]}"; do
    log "    - $h"
  done
fi

if [ ${#ROLLED_BACK[@]} -gt 0 ]; then
  log ""
  log "  Rolled back:"
  for h in "${ROLLED_BACK[@]}"; do
    log "    - $h"
  done
fi

log "============================================================"

# Exit with appropriate code.
if [ ${#FAILED[@]} -gt 0 ]; then
  if [ ${#ROLLED_BACK[@]} -gt 0 ]; then
    exit 3
  fi
  exit 2
fi

exit 0
