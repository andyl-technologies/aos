# Records exact public-command evidence for an RFC-0020 manual flight.
# Invoke this file with the AOS-built Bash exposed as $CONFIG_SHELL.

set -eu
umask 077

fail() {
  echo "campaign manual flight recorder: $*" >&2
  exit 1
}

require_file() {
  test -f "$1" || fail "required file is missing: $1"
}

validate_id() {
  case "$1" in
    "" | *[!a-z0-9-]* | -* | *-)
      fail "identifier must use lowercase letters, digits, and interior hyphens: $1"
      ;;
  esac
}

validate_root() {
  test -d "$1" || fail "evidence root does not exist: $1"
  require_file "$1/flight-manifest.json"
  test "$(stat -c '%a' "$1")" = 700 || fail "evidence root must have mode 0700: $1"
}

require_unsealed() {
  test ! -e "$1/SHA256SUMS" || fail "evidence root is already sealed: $1"
  test ! -e "$1/BUNDLE-ID" || fail "evidence root is already sealed: $1"
}

declared_secret_found() {
  evidence_file=$1
  redactions=${CAMPAIGN_FLIGHT_REDACTIONS:-}
  test -n "$redactions" || return 1
  require_file "$redactions"

  while IFS= read -r secret || test -n "$secret"; do
    test -n "$secret" || fail "redaction file contains an empty secret"
    if grep -F -q -- "$secret" "$evidence_file"; then
      return 0
    fi
  done < "$redactions"
  return 1
}

redact_or_fail() {
  evidence_file=$1
  if declared_secret_found "$evidence_file"; then
    printf '%s\n' '[redacted: declared secret detected; rerun with a public redacted surface]' \
      > "$evidence_file"
    return 1
  fi
  return 0
}

init_flight() {
  root=$1
  manifest=$2
  test ! -e "$root" || fail "evidence root already exists: $root"
  require_file "$manifest"
  jq -e '
    def nonempty: type == "string" and length > 0;
    def sha256: type == "string" and test("^sha256:[0-9a-f]{64}$");
    def roles: ["driver", "independent-reviewer", "campaign-model-owner",
      "qemu-boundary-owner", "storage-owner", "guest-api-owner", "operations-owner"];
    def artifacts: ["runbook", "campaign-snapshots", "exact-reproduction",
      "thin-reproduction", "operational-telemetry", "resource-audit",
      "automated-gate-results", "final-result"];
    def result_fields: ["observed-result", "operator-task-checklist", "claim-checklist",
      "automated-gate-results", "defects", "documentation-changes", "resource-audit"];
    type == "object" and
    (keys | sort) == (["acceptance_state", "authorized_fault_actions", "budget", "flight_id",
      "gate", "intended_claims", "layer", "participants", "planned_duration_hours", "policy",
      "provenance", "required_artifacts", "required_result_fields", "runbook", "scenario",
      "schema", "seed", "sign_offs", "starting_store_state"] | sort) and
    .schema == "crucible.campaign-manual-flight-manifest.v1" and
    (.gate == "gate:campaign-operator-acceptance" or .gate == "gate:campaign-dogfood") and
    .acceptance_state == "in-progress" and
    (.flight_id | nonempty) and (.runbook | nonempty) and
    (.layer | nonempty) and
    (.intended_claims | type == "array" and length > 0 and all(.[]; nonempty)) and
    (.planned_duration_hours | type == "number") and
    (if .gate == "gate:campaign-operator-acceptance"
      then .planned_duration_hours >= 4 and .planned_duration_hours <= 8
      else .planned_duration_hours >= 24
    end) and
    (.participants | type == "object") and
    (.participants | keys | sort) ==
      (if .gate == "gate:campaign-dogfood"
       then ["driver", "handoff-operator", "independent-reviewer", "observers", "release-owner"]
       else ["driver", "independent-reviewer", "observers"]
       end | sort) and
    (.participants.driver.name | nonempty) and
    .participants.driver.implemented_feature == false and
    (.participants["independent-reviewer"].name | nonempty) and
    .participants["independent-reviewer"].can_challenge == true and
    .participants.driver.name != .participants["independent-reviewer"].name and
    (.participants.observers | type == "array" and all(.[]; nonempty)) and
    (if .gate == "gate:campaign-dogfood"
     then (.participants["handoff-operator"].name | nonempty) and
       (.participants["release-owner"].name | nonempty)
     else true
     end) and
    (.provenance | keys | sort) == (["build-id", "host-profile", "plugin-identity",
      "product-artifact-identities", "qemu-identity", "source-revision", "source-tree",
      "store-profile"] | sort) and
    (.provenance["build-id"] | nonempty) and
    (.provenance["source-revision"] | nonempty) and
    (.provenance["source-tree"] | nonempty) and
    (.provenance["qemu-identity"] | nonempty) and
    (.provenance["plugin-identity"] | nonempty) and
    (.provenance["product-artifact-identities"] |
      type == "array" and length > 0 and all(.[]; nonempty)) and
    (.provenance["host-profile"] | nonempty) and
    (.provenance["store-profile"] | nonempty) and
    (.scenario | nonempty) and (.policy | nonempty) and (.seed | nonempty) and
    (.budget | type == "object" and length > 0) and
    (.starting_store_state | nonempty) and
    (.authorized_fault_actions | type == "array" and all(.[]; nonempty)) and
    .required_artifacts == artifacts and
    .required_result_fields == result_fields and
    .sign_offs.required_roles == roles and
    .sign_offs.unsigned_result == "blocked" and
    (.sign_offs.authorized_public_keys | keys | sort) == (roles | sort) and
    ([.sign_offs.authorized_public_keys[]] | all(.[]; sha256)) and
    ([.sign_offs.authorized_public_keys[]] | unique | length) == (roles | length)
  ' "$manifest" > /dev/null || fail "flight manifest does not satisfy the v1 input contract"

  install -d -m 700 "$root" "$root/commands" "$root/artifacts"
  install -m 600 "$manifest" "$root/flight-manifest.json"
  redact_or_fail "$root/flight-manifest.json" || fail "flight manifest contained a declared secret"
  : > "$root/command-journal.jsonl"
  chmod 600 "$root/command-journal.jsonl"
}

record_command() {
  root=$1
  step=$2
  expected_exit=$3
  shift 3
  test "$1" = -- || fail "record requires -- before the command"
  shift
  test "$#" -gt 0 || fail "record requires a command"
  validate_root "$root"
  require_unsealed "$root"
  validate_id "$step"
  case "$expected_exit" in
    zero | nonzero | any) ;;
    *) fail "expected exit must be zero, nonzero, or any" ;;
  esac

  step_root="$root/commands/$step"
  test ! -e "$step_root" || fail "step already exists: $step"
  install -d -m 700 "$step_root"
  started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  started_epoch=$(date -u +%s)
  jq -n --args '$ARGS.positional' -- "$@" > "$step_root/argv.json"

  set +e
  "$@" > "$step_root/stdout" 2> "$step_root/stderr"
  exit_status=$?
  set -e
  ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  ended_epoch=$(date -u +%s)
  duration_seconds=$((ended_epoch - started_epoch))

  redacted=false
  for evidence_file in "$step_root/argv.json" "$step_root/stdout" "$step_root/stderr"; do
    if ! redact_or_fail "$evidence_file"; then
      redacted=true
    fi
  done

  exit_matched=false
  case "$expected_exit:$exit_status" in
    zero:0 | nonzero:[1-9]* | any:*) exit_matched=true ;;
  esac
  if test "$redacted" = true; then
    exit_matched=false
  fi

  argv_sha256=$(sha256sum "$step_root/argv.json" | cut -d ' ' -f 1)
  stdout_sha256=$(sha256sum "$step_root/stdout" | cut -d ' ' -f 1)
  stderr_sha256=$(sha256sum "$step_root/stderr" | cut -d ' ' -f 1)
  jq -n \
    --arg step "$step" \
    --arg expected_exit "$expected_exit" \
    --argjson exit_status "$exit_status" \
    --argjson exit_matched "$exit_matched" \
    --arg started_at "$started_at" \
    --arg ended_at "$ended_at" \
    --argjson duration_seconds "$duration_seconds" \
    --arg argv_sha256 "sha256:$argv_sha256" \
    --arg stdout_sha256 "sha256:$stdout_sha256" \
    --arg stderr_sha256 "sha256:$stderr_sha256" \
    '{schema:"crucible.campaign-command-record.v1", step:$step,
      expected_exit:$expected_exit, exit_status:$exit_status,
      exit_matched:$exit_matched, started_at:$started_at, ended_at:$ended_at,
      duration_seconds:$duration_seconds, argv_sha256:$argv_sha256,
      stdout_sha256:$stdout_sha256, stderr_sha256:$stderr_sha256}' \
    > "$step_root/result.json"
  chmod 600 "$step_root"/*
  jq -c . "$step_root/result.json" >> "$root/command-journal.jsonl"

  test "$exit_matched" = true || fail "step $step did not match its exit/redaction contract"
}

capture_artifact() {
  root=$1
  artifact=$2
  source=$3
  validate_root "$root"
  require_unsealed "$root"
  validate_id "$artifact"
  require_file "$source"
  destination="$root/artifacts/$artifact"
  test ! -e "$destination" || fail "artifact already exists: $artifact"
  install -m 600 "$source" "$destination"
  redact_or_fail "$destination" || fail "artifact $artifact contained a declared secret"
}

seal_flight() {
  root=$1
  validate_root "$root"
  require_unsealed "$root"
  test -s "$root/command-journal.jsonl" || fail "command journal is empty"
  jq -s -e '
    length > 0 and all(.[];
      .schema == "crucible.campaign-command-record.v1" and .exit_matched == true)
  ' "$root/command-journal.jsonl" > /dev/null \
    || fail "command journal contains an invalid or unmatched result"

  while IFS= read -r artifact; do
    require_file "$root/artifacts/$artifact"
    test -s "$root/artifacts/$artifact" || fail "required artifact is empty: $artifact"
  done < <(jq -r '.required_artifacts[]' "$root/flight-manifest.json")
  jq -e '
    def nonempty: type == "string" and length > 0;
    def outcome: . == "pass" or . == "fail" or . == "blocked" or . == "observation";
    def checklist: type == "array" and length > 0 and all(.[];
      (keys | sort) == ["evidence", "id", "outcome"] and
      (.id | nonempty) and (.outcome | outcome) and (.evidence | nonempty));
    type == "object" and
    (keys | sort) == (["automated-gate-results", "claim-checklist", "defects",
      "documentation-changes", "observed-result", "operator-task-checklist",
      "resource-audit", "schema", "sign-off-status"] | sort) and
    .schema == "crucible.campaign-manual-flight-result.v1" and
    (.["observed-result"] | outcome) and
    (.["operator-task-checklist"] | checklist) and
    (.["claim-checklist"] | checklist) and
    (.["automated-gate-results"] | type == "array" and length > 0 and all(.[];
      (keys | sort) == ["evidence", "gate", "outcome"] and
      (.gate | nonempty) and (.outcome | outcome) and (.evidence | nonempty))) and
    (.defects | type == "array" and all(.[];
      (keys | sort) == ["disposition", "evidence", "id"] and
      (.id | nonempty) and (.evidence | nonempty) and
      (.disposition == "resolved" or .disposition == "release-blocking" or
        .disposition == "deferred-nonblocking"))) and
    (.["documentation-changes"] | type == "array" and length > 0 and all(.[]; nonempty)) and
    (.["resource-audit"] | type == "object" and
      .complete == true and (.["unexplained-resources"] | type == "array")) and
    .["sign-off-status"] == "pending"
  ' "$root/artifacts/final-result" > /dev/null \
    || fail "final result does not satisfy the v1 evidence contract"

  secret_found=false
  while IFS= read -r -d '' evidence_file; do
    if ! redact_or_fail "$evidence_file"; then
      secret_found=true
    fi
  done < <(find "$root" -type f -print0)
  test "$secret_found" = false || fail "evidence bundle contained a declared secret"

  (
    cd "$root"
    find . -type f ! -path './attestations/*' ! -path ./SHA256SUMS ! -path ./BUNDLE-ID -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 sha256sum
  ) > "$root/SHA256SUMS"
  bundle_sha256=$(sha256sum "$root/SHA256SUMS" | cut -d ' ' -f 1)
  printf 'sha256:%s\n' "$bundle_sha256" > "$root/BUNDLE-ID"
  chmod 600 "$root/SHA256SUMS" "$root/BUNDLE-ID"
}

verify_flight() {
  root=$1
  validate_root "$root"
  require_file "$root/SHA256SUMS"
  require_file "$root/BUNDLE-ID"

  (
    cd "$root"
    sha256sum -c SHA256SUMS > /dev/null
  ) || fail "evidence checksum verification failed"

  verification_manifest=$(mktemp "${TMPDIR:-/tmp}/campaign-flight-verify.XXXXXX")
  trap 'rm -f "$verification_manifest"' EXIT
  (
    cd "$root"
    find . -type f ! -path './attestations/*' ! -path ./SHA256SUMS ! -path ./BUNDLE-ID -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 sha256sum
  ) > "$verification_manifest"
  cmp "$root/SHA256SUMS" "$verification_manifest" > /dev/null \
    || fail "evidence file inventory does not match checksum manifest"
  rm -f "$verification_manifest"
  trap - EXIT

  expected="sha256:$(sha256sum "$root/SHA256SUMS" | cut -d ' ' -f 1)"
  test "$(cat "$root/BUNDLE-ID")" = "$expected" || fail "bundle identity does not match checksum manifest"
  verify_attestations "$root"
  printf '%s\n' "$expected"
}

write_attestation_statement() {
  root=$1
  role=$2
  signer=$3
  public_key=$4
  validate_root "$root"
  require_file "$root/SHA256SUMS"
  require_file "$root/BUNDLE-ID"
  validate_id "$role"
  test -n "$signer" || fail "attestation signer must be nonempty"
  require_file "$public_key"

  public_key_sha256="sha256:$(sha256sum "$public_key" | cut -d ' ' -f 1)"
  authorized_key=$(jq -er --arg role "$role" \
    '.sign_offs.authorized_public_keys[$role]' "$root/flight-manifest.json") \
    || fail "attestation role is not required by the flight manifest: $role"
  test "$authorized_key" = "$public_key_sha256" \
    || fail "public key is not authorized for attestation role $role"
  bundle_id=$(cat "$root/BUNDLE-ID")
  result_identity="sha256:$(sha256sum "$root/artifacts/final-result" | cut -d ' ' -f 1)"
  jq -cS -n \
    --arg bundle_id "$bundle_id" \
    --arg role "$role" \
    --arg signer "$signer" \
    --arg public_key_sha256 "$public_key_sha256" \
    --arg result_identity "$result_identity" \
    '{schema:"crucible.campaign-manual-flight-attestation-statement.v1",
      bundle_id:$bundle_id, role:$role, signer:$signer,
      public_key_sha256:$public_key_sha256, result_identity:$result_identity}'
}

create_attestation_statement() {
  root=$1
  role=$2
  signer=$3
  public_key=$4
  output=$5
  test ! -e "$output" || fail "attestation statement already exists: $output"
  write_attestation_statement "$root" "$role" "$signer" "$public_key" > "$output"
  chmod 600 "$output"
}

attest_flight() {
  root=$1
  role=$2
  signer=$3
  public_key=$4
  statement=$5
  signature=$6
  require_file "$statement"
  require_file "$signature"

  expected_statement=$(mktemp "${TMPDIR:-/tmp}/campaign-flight-statement.XXXXXX")
  trap 'rm -f "$expected_statement"' EXIT
  write_attestation_statement "$root" "$role" "$signer" "$public_key" \
    > "$expected_statement"
  cmp "$expected_statement" "$statement" > /dev/null \
    || fail "attestation statement does not match its canonical role, signer, key, and result"

  openssl=${CAMPAIGN_FLIGHT_OPENSSL:-}
  test -n "$openssl" || fail "CAMPAIGN_FLIGHT_OPENSSL must name the AOS-built openssl executable"
  test -x "$openssl" || fail "configured openssl is not executable: $openssl"
  "$openssl" pkeyutl -verify -pubin -inkey "$public_key" -sigfile "$signature" \
    -rawin -in "$statement" > /dev/null \
    || fail "detached attestation does not verify for role $role"

  install -d -m 700 "$root/attestations"
  stored_statement="$root/attestations/$role.statement.json"
  test ! -e "$stored_statement" || fail "attestation role is already recorded: $role"
  install -m 600 "$statement" "$stored_statement"
  install -m 600 "$public_key" "$root/attestations/$role.public.pem"
  install -m 600 "$signature" "$root/attestations/$role.signature"
  rm -f "$expected_statement"
  trap - EXIT
}

verify_attestations() {
  root=$1
  test -d "$root/attestations" || fail "flight has no detached attestations"
  openssl=${CAMPAIGN_FLIGHT_OPENSSL:-}
  test -n "$openssl" || fail "CAMPAIGN_FLIGHT_OPENSSL must name the AOS-built openssl executable"
  test -x "$openssl" || fail "configured openssl is not executable: $openssl"
  signature_digests=$(mktemp "${TMPDIR:-/tmp}/campaign-flight-signatures.XXXXXX")
  expected_statement=$(mktemp "${TMPDIR:-/tmp}/campaign-flight-statement.XXXXXX")
  trap 'rm -f "$signature_digests" "$expected_statement"' EXIT

  jq -r '.sign_offs.required_roles[]' "$root/flight-manifest.json" |
  while IFS= read -r role; do
    validate_id "$role"
    statement="$root/attestations/$role.statement.json"
    public_key="$root/attestations/$role.public.pem"
    signature="$root/attestations/$role.signature"
    require_file "$statement"
    require_file "$public_key"
    require_file "$signature"
    signer=$(jq -er '.signer | select(type == "string" and length > 0)' "$statement") \
      || fail "invalid attestation signer for role $role"
    write_attestation_statement "$root" "$role" "$signer" "$public_key" \
      > "$expected_statement"
    cmp "$expected_statement" "$statement" > /dev/null \
      || fail "attestation statement changed for role $role"
    "$openssl" pkeyutl -verify -pubin -inkey "$public_key" -sigfile "$signature" \
      -rawin -in "$statement" > /dev/null \
      || fail "detached attestation no longer verifies for role $role"
    signature_digest=$(sha256sum "$signature" | cut -d ' ' -f 1)
    if grep -F -x -q -- "$signature_digest" "$signature_digests"; then
      fail "detached signature is reused across independent roles: $role"
    fi
    printf '%s\n' "$signature_digest" >> "$signature_digests"
  done
  rm -f "$signature_digests" "$expected_statement"
  trap - EXIT
}

usage() {
  cat >&2 <<'USAGE'
usage:
  recorder init ROOT FLIGHT-MANIFEST.json
  recorder record ROOT STEP (zero|nonzero|any) -- COMMAND [ARG...]
  recorder capture ROOT ARTIFACT SOURCE
  recorder seal ROOT
  recorder statement ROOT ROLE SIGNER PUBLIC-KEY.pem OUTPUT.json
  recorder attest ROOT ROLE SIGNER PUBLIC-KEY.pem STATEMENT.json SIGNATURE
  recorder verify ROOT
USAGE
  exit 2
}

action=${1:-}
test -n "$action" || usage
shift
case "$action:$#" in
  init:2) init_flight "$@" ;;
  record:*) test "$#" -ge 5 || usage; record_command "$@" ;;
  capture:3) capture_artifact "$@" ;;
  seal:1) seal_flight "$@" ;;
  statement:5) create_attestation_statement "$@" ;;
  attest:6) attest_flight "$@" ;;
  verify:1) verify_flight "$@" ;;
  *) usage ;;
esac
