#!/usr/bin/env bash
# ANDYL OS -- Ignition Config Generation Script
#
# Generates Ignition JSON from Butane YAML templates by substituting
# machine-specific variables and transpiling with butane --strict.
#
# This script reads a machine definition (as environment variables or
# a config file) and produces a ready-to-deploy Ignition JSON config.
#
# Usage:
#   # Generate from a machine config file:
#   ./scripts/generate-ignition.sh \
#     --machine config/machines/k8s-worker-01.env \
#     --role worker \
#     --output generated/k8s-worker-01.ign
#
#   # Generate with inline variables:
#   HOSTNAME=k8s-worker-01.dc1.andyl.internal \
#   ROLE=k8s-worker \
#   IP_ADDRESS=10.0.7.1/24 \
#   GATEWAY=10.0.7.254 \
#   ./scripts/generate-ignition.sh \
#     --role worker \
#     --output generated/k8s-worker-01.ign
#
#   # Validate only (no output):
#   ./scripts/generate-ignition.sh --validate generated/k8s-worker-01.ign
#
# Machine config file format (.env):
#   HOSTNAME=k8s-worker-01.dc1.andyl.internal
#   ROLE=k8s-worker
#   REGION=us-east-1
#   ZONE=us-east-1a
#   DATACENTER=dc1
#   RACK=rack-07
#   IP_ADDRESS=10.0.7.1/24
#   GATEWAY=10.0.7.254
#   DNS_1=10.0.0.53
#   DNS_2=10.0.0.54
#   NTP_SERVER=10.0.0.123
#   INTERFACE=eno1
#   SSH_KEY_1="ssh-ed25519 AAAA... ops-team"
#   CA_CERT_FILE=secrets/ca.pem
#   NODE_CERT_FILE=secrets/nodes/k8s-worker-01.pem
#   NODE_KEY_FILE=secrets/nodes/k8s-worker-01-key.pem
#
# See:
#   RFC-0006 section 7 (Fleet Templating System)
#   Phase 6 section 6.10 (Config Generation Script)

set -euo pipefail

# ---------------------------------------------------------------------------
# Script directory and project root
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_DIR="${PROJECT_ROOT}/config/ignition"
OUTPUT_DIR="${PROJECT_ROOT}/generated/ignition"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

ROLE=""
MACHINE_CONFIG=""
OUTPUT_FILE=""
VALIDATE_ONLY=""
VERBOSE=""

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

usage() {
    cat <<'USAGE'
Usage: generate-ignition.sh [OPTIONS]

Options:
  --machine FILE    Machine config file (.env format)
  --role ROLE       Machine role: worker, control-plane, database, edge
  --output FILE     Output Ignition JSON file path
  --validate FILE   Validate an existing Ignition JSON file
  --verbose         Print detailed output
  --help            Show this help message

Environment variables (used if --machine is not specified):
  HOSTNAME          Fully qualified domain name
  ROLE              Machine role
  REGION            Cloud/datacenter region
  ZONE              Availability zone
  DATACENTER        Datacenter identifier
  RACK              Rack identifier
  IP_ADDRESS        Static IP with CIDR (e.g., 10.0.7.1/24)
  GATEWAY           Default gateway IP
  DNS_1, DNS_2      DNS server IPs
  NTP_SERVER        NTP server IP
  INTERFACE         Primary network interface name
  SSH_KEY_1         SSH authorized key for admin user
  CA_CERT_FILE      Path to TLS CA certificate PEM file
  NODE_CERT_FILE    Path to node TLS certificate PEM file
  NODE_KEY_FILE     Path to node TLS private key PEM file
USAGE
    exit "${1:-0}"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --machine)
            MACHINE_CONFIG="$2"
            shift 2
            ;;
        --role)
            ROLE="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --validate)
            VALIDATE_ONLY="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --help)
            usage 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            usage 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate-only mode
# ---------------------------------------------------------------------------

if [[ -n "${VALIDATE_ONLY}" ]]; then
    if ! command -v ignition-validate >/dev/null 2>&1; then
        echo "ERROR: ignition-validate not found in PATH" >&2
        echo "Install the andyl-ignition package or add it to PATH." >&2
        exit 1
    fi

    echo "Validating: ${VALIDATE_ONLY}"
    if ignition-validate "${VALIDATE_ONLY}"; then
        echo "VALID: ${VALIDATE_ONLY}"
        exit 0
    else
        echo "INVALID: ${VALIDATE_ONLY}" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Load machine config
# ---------------------------------------------------------------------------

if [[ -n "${MACHINE_CONFIG}" ]]; then
    if [[ ! -f "${MACHINE_CONFIG}" ]]; then
        echo "ERROR: Machine config file not found: ${MACHINE_CONFIG}" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "${MACHINE_CONFIG}"
fi

# ---------------------------------------------------------------------------
# Validate required variables
# ---------------------------------------------------------------------------

: "${HOSTNAME:?ERROR: HOSTNAME is required}"
: "${ROLE:=${ROLE:-}}"
: "${REGION:=us-east-1}"
: "${ZONE:=us-east-1a}"
: "${DATACENTER:=dc1}"
: "${RACK:=rack-01}"
: "${IP_ADDRESS:?ERROR: IP_ADDRESS is required (e.g., 10.0.7.1/24)}"
: "${GATEWAY:?ERROR: GATEWAY is required}"
: "${DNS_1:=10.0.0.53}"
: "${DNS_2:=10.0.0.54}"
: "${NTP_SERVER:=10.0.0.123}"
: "${INTERFACE:=eno1}"
: "${SSH_KEY_1:?ERROR: SSH_KEY_1 is required}"

# Determine role from environment or --role flag
if [[ -z "${ROLE}" ]]; then
    echo "ERROR: ROLE is required (--role or ROLE env var)" >&2
    exit 1
fi

# Map role names to Butane template files
case "${ROLE}" in
    worker|k8s-worker)
        ROLE_TEMPLATE="worker.bu"
        ROLE_VALUE="k8s-worker"
        ;;
    control-plane|k8s-control-plane)
        ROLE_TEMPLATE="control-plane.bu"
        ROLE_VALUE="k8s-control-plane"
        ;;
    *)
        echo "ERROR: Unknown role: ${ROLE}" >&2
        echo "Valid roles: worker, control-plane" >&2
        exit 1
        ;;
esac

# Default output file
if [[ -z "${OUTPUT_FILE}" ]]; then
    OUTPUT_FILE="${OUTPUT_DIR}/${HOSTNAME}.ign"
fi

# ---------------------------------------------------------------------------
# Load TLS certificates from files
# ---------------------------------------------------------------------------

CA_CERT=""
NODE_CERT=""
NODE_KEY=""

if [[ -n "${CA_CERT_FILE:-}" ]] && [[ -f "${CA_CERT_FILE}" ]]; then
    CA_CERT="$(cat "${CA_CERT_FILE}")"
elif [[ -n "${CA_CERT:-}" ]]; then
    CA_CERT="${CA_CERT}"
else
    echo "WARNING: No CA certificate provided (CA_CERT_FILE or CA_CERT)" >&2
    CA_CERT="REPLACE-WITH-CA-CERTIFICATE"
fi

if [[ -n "${NODE_CERT_FILE:-}" ]] && [[ -f "${NODE_CERT_FILE}" ]]; then
    NODE_CERT="$(cat "${NODE_CERT_FILE}")"
elif [[ -n "${NODE_CERT:-}" ]]; then
    NODE_CERT="${NODE_CERT}"
else
    echo "WARNING: No node certificate provided (NODE_CERT_FILE or NODE_CERT)" >&2
    NODE_CERT="REPLACE-WITH-NODE-CERTIFICATE"
fi

if [[ -n "${NODE_KEY_FILE:-}" ]] && [[ -f "${NODE_KEY_FILE}" ]]; then
    NODE_KEY="$(cat "${NODE_KEY_FILE}")"
elif [[ -n "${NODE_KEY:-}" ]]; then
    NODE_KEY="${NODE_KEY}"
else
    echo "WARNING: No node key provided (NODE_KEY_FILE or NODE_KEY)" >&2
    NODE_KEY="REPLACE-WITH-NODE-KEY"
fi

# Extract bare IP (without CIDR) for API server advertise address
IP_ADDRESS_BARE="${IP_ADDRESS%%/*}"

# ---------------------------------------------------------------------------
# Generate Butane YAML from templates
# ---------------------------------------------------------------------------

log() {
    if [[ -n "${VERBOSE}" ]]; then
        echo "$@"
    fi
}

log "Generating Ignition config for: ${HOSTNAME}"
log "  Role:      ${ROLE_VALUE}"
log "  IP:        ${IP_ADDRESS}"
log "  Interface: ${INTERFACE}"
log "  Template:  base.bu + ${ROLE_TEMPLATE}"
log "  Output:    ${OUTPUT_FILE}"

# Create output directory
mkdir -p "$(dirname "${OUTPUT_FILE}")"

# Read and substitute the base template
BASE_BUTANE="$(cat "${CONFIG_DIR}/base.bu")"

# Perform variable substitution on the base template.
# Using sed for simple string replacement.  Each variable is replaced
# with its value.  This is intentionally simple -- for production
# fleet management, use the Jinja2-based tools/generate-ignition-configs.py.

substitute_vars() {
    local content="$1"
    content="${content//HOSTNAME/${HOSTNAME}}"
    content="${content//ROLE/${ROLE_VALUE}}"
    content="${content//REGION/${REGION}}"
    content="${content//ZONE/${ZONE}}"
    content="${content//DATACENTER/${DATACENTER}}"
    content="${content//RACK/${RACK}}"
    content="${content//IP_ADDRESS/${IP_ADDRESS}}"
    content="${content//GATEWAY/${GATEWAY}}"
    content="${content//DNS_1/${DNS_1}}"
    content="${content//DNS_2/${DNS_2}}"
    content="${content//NTP_SERVER/${NTP_SERVER}}"
    content="${content//INTERFACE/${INTERFACE}}"
    content="${content//SSH_KEY_1/${SSH_KEY_1}}"
    content="${content//CA_CERT/${CA_CERT}}"
    content="${content//NODE_CERT/${NODE_CERT}}"
    content="${content//NODE_KEY/${NODE_KEY}}"
    content="${content//IP_ADDRESS_BARE/${IP_ADDRESS_BARE}}"

    # Role-specific variables
    content="${content//CLUSTER_DNS/${CLUSTER_DNS:-10.96.0.10}}"
    content="${content//CLUSTER_DOMAIN/${CLUSTER_DOMAIN:-cluster.local}}"
    content="${content//BOOTSTRAP_TOKEN/${BOOTSTRAP_TOKEN:-REPLACE-WITH-BOOTSTRAP-TOKEN}}"
    content="${content//API_SERVER/${API_SERVER:-https://api.andyl.internal:6443}}"
    content="${content//ETCD_NAME/${ETCD_NAME:-${HOSTNAME}}}"
    content="${content//ETCD_INITIAL_CLUSTER/${ETCD_INITIAL_CLUSTER:-${HOSTNAME}=https://${HOSTNAME}:2380}}"
    content="${content//ETCD_PEER_CERT/${ETCD_PEER_CERT:-REPLACE-WITH-ETCD-PEER-CERT}}"
    content="${content//ETCD_PEER_KEY/${ETCD_PEER_KEY:-REPLACE-WITH-ETCD-PEER-KEY}}"
    content="${content//API_SERVER_CERT/${API_SERVER_CERT:-REPLACE-WITH-API-SERVER-CERT}}"
    content="${content//API_SERVER_KEY/${API_SERVER_KEY:-REPLACE-WITH-API-SERVER-KEY}}"
    content="${content//SERVICE_CLUSTER_IP_RANGE/${SERVICE_CLUSTER_IP_RANGE:-10.96.0.0/12}}"
    content="${content//POD_CIDR/${POD_CIDR:-10.244.0.0/16}}"

    echo "${content}"
}

BASE_RENDERED="$(substitute_vars "${BASE_BUTANE}")"

# Read and substitute the role-specific template
ROLE_BUTANE="$(cat "${CONFIG_DIR}/${ROLE_TEMPLATE}")"
ROLE_RENDERED="$(substitute_vars "${ROLE_BUTANE}")"

# ---------------------------------------------------------------------------
# Transpile to Ignition JSON
# ---------------------------------------------------------------------------

# Check for butane in PATH
if ! command -v butane >/dev/null 2>&1; then
    echo "ERROR: butane not found in PATH" >&2
    echo "Install the andyl-butane package or add it to PATH." >&2
    exit 1
fi

# Transpile base template
log "Transpiling base template..."
BASE_IGN_FILE="$(mktemp)"
if ! echo "${BASE_RENDERED}" | butane --strict > "${BASE_IGN_FILE}" 2>&1; then
    echo "ERROR: butane --strict failed for base template" >&2
    cat "${BASE_IGN_FILE}" >&2
    rm -f "${BASE_IGN_FILE}"
    exit 1
fi

# Transpile role template
log "Transpiling role template (${ROLE_TEMPLATE})..."
ROLE_IGN_FILE="$(mktemp)"
if ! echo "${ROLE_RENDERED}" | butane --strict > "${ROLE_IGN_FILE}" 2>&1; then
    echo "ERROR: butane --strict failed for ${ROLE_TEMPLATE}" >&2
    cat "${ROLE_IGN_FILE}" >&2
    rm -f "${BASE_IGN_FILE}" "${ROLE_IGN_FILE}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Merge base and role Ignition configs
# ---------------------------------------------------------------------------
# Ignition supports config merging natively.  We use the base config
# as the primary config and the role config as an appended config.
# The merge is done by creating a wrapper config that includes both.
#
# For simplicity, we merge the JSON objects using a small inline script.
# In production, use the Jinja2-based generation pipeline which produces
# a single merged Butane YAML before transpilation.

log "Merging base and role configs..."

# Use Python for reliable JSON merging (available on build systems)
if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import json, sys

base = json.load(open('${BASE_IGN_FILE}'))
role = json.load(open('${ROLE_IGN_FILE}'))

# Merge storage.files
base.setdefault('storage', {})
role_storage = role.get('storage', {})
for key in ['files', 'directories', 'links', 'disks', 'raid', 'filesystems', 'luks']:
    if key in role_storage:
        base['storage'].setdefault(key, []).extend(role_storage[key])

# Merge passwd.users
if 'passwd' in role:
    base.setdefault('passwd', {}).setdefault('users', [])
    # Merge users by name (don't duplicate the core user)
    existing_names = {u['name'] for u in base['passwd']['users']}
    for user in role.get('passwd', {}).get('users', []):
        if user['name'] not in existing_names:
            base['passwd']['users'].append(user)

# Merge systemd.units
if 'systemd' in role:
    base.setdefault('systemd', {}).setdefault('units', [])
    existing_units = {u['name'] for u in base['systemd']['units']}
    for unit in role.get('systemd', {}).get('units', []):
        if unit['name'] not in existing_units:
            base['systemd']['units'].append(unit)

json.dump(base, open('${OUTPUT_FILE}', 'w'), indent=2)
" 2>&1
else
    # Fallback: just use the base config (role config not merged)
    echo "WARNING: python3 not available, using base config only (role not merged)" >&2
    cp "${BASE_IGN_FILE}" "${OUTPUT_FILE}"
fi

# Clean up temp files
rm -f "${BASE_IGN_FILE}" "${ROLE_IGN_FILE}"

# ---------------------------------------------------------------------------
# Validate the output
# ---------------------------------------------------------------------------

if command -v ignition-validate >/dev/null 2>&1; then
    log "Validating output..."
    if ignition-validate "${OUTPUT_FILE}"; then
        log "Validation passed."
    else
        echo "ERROR: ignition-validate failed for ${OUTPUT_FILE}" >&2
        exit 1
    fi
else
    echo "WARNING: ignition-validate not found, skipping validation" >&2
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo "Generated: ${OUTPUT_FILE}"
echo "  Host:    ${HOSTNAME}"
echo "  Role:    ${ROLE_VALUE}"
echo "  IP:      ${IP_ADDRESS}"
echo "  Size:    $(wc -c < "${OUTPUT_FILE}") bytes"
