set -eu

fail() {
    printf 'campaign release acceptance: %s\n' "$1" >&2
    exit 1
}

field() {
    key=$1
    file=$2
    value=$(sed -n "s/^$key=//p" "$file")
    test "$(printf '%s\n' "$value" | grep -c . || true)" -eq 1 \
        || fail "$file must contain exactly one $key field"
    printf '%s\n' "$value"
}

digest_file() {
    sha256sum "$1" | sed 's/ .*//'
}

require_directory() {
    test -d "$1" && test ! -L "$1" \
        || fail "required input is not a non-symlink directory: $1"
}

require_file() {
    test -f "$1" && test ! -L "$1" && test -s "$1" \
        || fail "required input is not a nonempty regular non-symlink file: $1"
}

require_digest() {
    printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{64}$' \
        || fail "evidence digest is not lowercase SHA-256: $1"
}

require_gate_result() {
    gate_path=$1
    expected_gate=$2
    require_directory "$gate_path"
    require_file "$gate_path/result"
    test "$(sed -n '1p' "$gate_path/result")" = PASS \
        || fail "$expected_gate executable result does not report PASS"
    test "$(field gate "$gate_path/result")" = "$expected_gate" \
        || fail "$expected_gate executable result names another gate"
    digest_file "$gate_path/result"
}

verify_e2e_evidence() {
    fleet_gate=$1
    require_directory "$fleet_gate"
    require_file "$fleet_gate/result"
    test "$(sed -n '1p' "$fleet_gate/result")" = PASS \
        || fail "e2e executable gate does not report PASS"
    test "$(field gate "$fleet_gate/result")" = gate:e2e-determinism \
        || fail "e2e executable result names another gate"
    test "$(field tcg_only "$fleet_gate/result")" = true \
        || fail "e2e executable gate did not use TCG only"
    test "$(field required_system_features "$fleet_gate/result")" = none \
        || fail "e2e executable gate requires an unsupported host feature"

    evidence="$fleet_gate/evidence"
    require_directory "$evidence"
    result="$evidence/result"
    manifest="$evidence/manifest.env"
    canonical="$evidence/canonical-results.tsv"
    artifact="$evidence/reproduction.crucible"
    journal="$evidence/command-journal.tsv"
    require_file "$result"
    require_file "$manifest"
    require_file "$canonical"
    require_file "$artifact"
    require_file "$journal"

    test "$(sed -n '1p' "$result")" = PASS \
        || fail "e2e native evidence does not report PASS"
    test "$(field gate "$result")" = gate:e2e-determinism \
        || fail "e2e native evidence names another gate"
    test "$(field schema "$result")" = crucible.e2e.native-gate-evidence.v1 \
        || fail "e2e native evidence schema is unsupported"
    test "$(field native_qemu_execution "$result")" = true \
        || fail "e2e native evidence did not execute QEMU"
    test "$(field live_qemu "$result")" = true \
        || fail "e2e native evidence is not live QEMU evidence"
    test "$(field tcg_only "$result")" = true \
        || fail "e2e native evidence did not use TCG only"
    test "$(field local_profile_replay "$result")" = true \
        || fail "e2e native evidence omitted local profile replay"
    test "$(field profile_matrix "$result")" \
        = quiet-single-core,randomized-worker-two-core,loaded-io-stall-four-core \
        || fail "e2e native evidence has the wrong profile matrix"
    for key in randomized_worker_scheduling wall_clock_jitter host_io_stall; do
        test "$(field "$key" "$result")" = true \
            || fail "e2e native evidence did not establish $key"
    done
    test "$(field varied_core_counts "$result")" = 1,2,4 \
        || fail "e2e native evidence has the wrong core-count matrix"
    test "$(field canonical_event_logs "$result")" = byte-identical \
        || fail "e2e event logs were not byte-identical"
    test "$(field final_fingerprints "$result")" = byte-identical \
        || fail "e2e final fingerprints were not byte-identical"
    test "$(field artifact_replay "$result")" \
        = different-machine-profile-byte-identical \
        || fail "e2e artifact did not reproduce under a different local profile"

    test "$(field schema "$manifest")" = crucible.e2e.native-gate-evidence.v1 \
        || fail "e2e manifest schema is unsupported"
    for key in \
        scenario_sha256 qemu_binary_sha256 qemu_identity_sha256 plugin_sha256 \
        kernel_sha256 root_image_sha256 canonical_results_sha256 \
        command_journal_sha256 reproduction_artifact_sha256
    do
        require_digest "$(field "$key" "$manifest")"
    done
    test "$(field profile_matrix "$manifest")" \
        = quiet-single-core,randomized-worker-two-core,loaded-io-stall-four-core \
        || fail "e2e manifest has the wrong profile matrix"
    test "$(field canonical_results_sha256 "$manifest")" = "$(digest_file "$canonical")" \
        || fail "e2e manifest does not bind canonical results"
    test "$(field command_journal_sha256 "$manifest")" = "$(digest_file "$journal")" \
        || fail "e2e manifest does not bind the command journal"
    test "$(field reproduction_artifact_sha256 "$manifest")" = "$(digest_file "$artifact")" \
        || fail "e2e manifest does not bind the reproduction artifact"
    test "$(field canonical_results_sha256 "$result")" = "$(digest_file "$canonical")" \
        || fail "e2e result does not bind canonical results"
    test "$(field reproduction_artifact_sha256 "$result")" = "$(digest_file "$artifact")" \
        || fail "e2e result does not bind the reproduction artifact"
    test "$(field manifest_sha256 "$result")" = "$(digest_file "$manifest")" \
        || fail "e2e result does not bind its exact closure manifest"

    printf '%s\t%s\n' "$(digest_file "$result")" "$(digest_file "$manifest")"
}

verify_e2e_binding() {
    fleet_gate=$1
    crucible_package=$2
    release_env=$3
    scenario=$4
    qemu_binary=$5
    plugin=$6
    kernel=$7
    root_image=$8
    manifest="$fleet_gate/evidence/manifest.env"

    for source in "$scenario" "$qemu_binary" "$plugin" "$kernel" "$root_image"; do
        require_file "$source"
    done
    require_file "$release_env"

    test "$(field crucible_package_identity "$manifest")" = "${crucible_package##*/}" \
        || fail "e2e evidence names another Crucible package"
    test "$(field qemu_path "$release_env")" = "$qemu_binary" \
        || fail "release manifest names another QEMU binary"
    test "$(field plugin_path "$release_env")" = "$plugin" \
        || fail "release manifest names another plugin"

    qemu_identity="${qemu_binary%/bin/*}/share/aos/crucible/qemu-build-identity.env"
    require_file "$qemu_identity"
    for binding in \
        "scenario_sha256:$scenario" \
        "qemu_binary_sha256:$qemu_binary" \
        "qemu_identity_sha256:$qemu_identity" \
        "plugin_sha256:$plugin" \
        "kernel_sha256:$kernel" \
        "root_image_sha256:$root_image"
    do
        key=${binding%%:*}
        source=${binding#*:}
        test "$(field "$key" "$manifest")" = "$(digest_file "$source")" \
            || fail "e2e evidence $key differs from its built input"
    done
}

verify_required_gates() {
    required_gates=$1
    expected_gates=$2
    result_sha256=$(require_gate_result "$required_gates" gate:campaign-required-gates)
    manifest="$required_gates/manifest.tsv"
    declared_gates="$required_gates/required-claim-gates.txt"
    require_file "$manifest"
    require_file "$declared_gates"
    require_file "$expected_gates"
    expected_claim_count=$(wc -l < "$expected_gates" | tr -d ' ')

    test "$(field required_claim_count "$required_gates/result")" -eq "$expected_claim_count" \
        || fail "required-gates aggregate has the wrong claim count"
    test "$(field all_required_claims_authenticated "$required_gates/result")" = true \
        || fail "required-gates aggregate did not authenticate every claim"
    test "$(field manifest_sha256 "$required_gates/result")" = "$(digest_file "$manifest")" \
        || fail "required-gates manifest digest does not match"
    test "$(field required_claim_gates_sha256 "$required_gates/result")" \
        = "$(digest_file "$declared_gates")" \
        || fail "required-gates inventory digest does not match"
    test "$(digest_file "$declared_gates")" = "$(digest_file "$expected_gates")" \
        || fail "required-gates inventory differs from the release contract"

    tab=$(printf '\t')
    test "$(sed -n '1p' "$manifest")" = "gate${tab}result_sha256" \
        || fail "$manifest has an unsupported schema"
    observed="$TMPDIR/campaign-release-required-gates"
    cut -f1 "$manifest" | sed -n '2,$p' > "$observed"
    test "$(digest_file "$observed")" = "$(digest_file "$expected_gates")" \
        || fail "$manifest does not contain the exact required gate inventory"
    sed -n '2,$p' "$manifest" | while IFS="$tab" read -r gate result_digest extra; do
        test -n "$gate" || fail "$manifest contains an empty gate"
        test -z "$extra" || fail "$manifest contains an unexpected field"
        require_digest "$result_digest"
        result_name=$(printf '%s\n' "$gate" | sed 's/:/-/')
        require_file "$required_gates/results/$result_name.result"
        test "$(digest_file "$required_gates/results/$result_name.result")" \
            = "$result_digest" \
            || fail "$manifest result digest does not match: $gate"
    done

    printf '%s\n' "$result_sha256"
}

verify_release_manifest() {
    crucible_package=$1
    release_manifest=$2
    shipped_env="$crucible_package/share/aos/crucible/release-manifest.env"
    shipped_json="$crucible_package/share/aos/crucible/release-manifest.json"
    require_file "$release_manifest/result"
    require_file "$shipped_env"
    require_file "$shipped_json"
    test "$(sed -n '1p' "$release_manifest/result")" = PASS \
        || fail "release manifest result does not report PASS"
    test "$(field release_manifest_env_sha256 "$release_manifest/result")" \
        = "$(digest_file "$shipped_env")" \
        || fail "release manifest env digest does not match"
    test "$(field release_manifest_json_sha256 "$release_manifest/result")" \
        = "$(digest_file "$shipped_json")" \
        || fail "release manifest JSON digest does not match"
    test "$(field crucible_package_store_path "$release_manifest/result")" \
        = "$crucible_package" \
        || fail "release manifest validated another Crucible package"
}

if test "$#" -eq 2 && test "$1" = --probe-e2e-evidence; then
    verify_e2e_evidence "$2" >/dev/null
    exit 0
fi

if test "$#" -eq 9 && test "$1" = --probe-e2e-binding; then
    verify_e2e_evidence "$2" >/dev/null
    verify_e2e_binding "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
    exit 0
fi

test "$#" -eq 15 || fail "expected fifteen release-acceptance inputs"

e2e_determinism=$1
gate_matrix=$2
operational_continuity=$3
finding_portability=$4
hot_fork_scaling=$5
required_gates=$6
crucible_package=$7
release_manifest=$8
release_acceptance_contract=$9
e2e_scenario=${10}
e2e_qemu_binary=${11}
e2e_plugin=${12}
e2e_kernel=${13}
e2e_root_image=${14}
output=${15}

verify_release_manifest "$crucible_package" "$release_manifest"
require_file "$release_acceptance_contract/result"
test "$(sed -n '1p' "$release_acceptance_contract/result")" = CONTRACT_VALIDATED \
    || fail "release acceptance contract validator did not succeed"
test "$(field gate "$release_acceptance_contract/result")" \
    = gate:campaign-release-acceptance-contract \
    || fail "release acceptance contract validator names another gate"
e2e_digests=$(verify_e2e_evidence "$e2e_determinism")
verify_e2e_binding \
    "$e2e_determinism" "$crucible_package" \
    "$crucible_package/share/aos/crucible/release-manifest.env" \
    "$e2e_scenario" "$e2e_qemu_binary" "$e2e_plugin" \
    "$e2e_kernel" "$e2e_root_image"
e2e_sha256=$(printf '%s\n' "$e2e_digests" | cut -f1)
e2e_manifest_sha256=$(printf '%s\n' "$e2e_digests" | cut -f2)
matrix_sha256=$(require_gate_result "$gate_matrix" gate:campaign-gate-matrix)
continuity_sha256=$(require_gate_result \
    "$operational_continuity" gate:campaign-operational-continuity)
portability_sha256=$(require_gate_result "$finding_portability" gate:campaign-replay)
scaling_sha256=$(require_gate_result "$hot_fork_scaling" gate:hot-fork-scaling)
required_gates_sha256=$(verify_required_gates \
    "$required_gates" "$release_acceptance_contract/required-claim-gates.txt")

mkdir -p "$output/evidence" "$output/executable" "$output/release-manifest"
cp -R "$e2e_determinism/evidence" "$output/evidence/e2e-determinism"
cp "$release_manifest/result" "$output/release-manifest/result"
cp "$crucible_package/share/aos/crucible/release-manifest.env" \
    "$output/release-manifest/release-manifest.env"
cp "$crucible_package/share/aos/crucible/release-manifest.json" \
    "$output/release-manifest/release-manifest.json"
cp "$gate_matrix/result" "$output/executable/campaign-gate-matrix.result"
cp "$operational_continuity/result" \
    "$output/executable/campaign-operational-continuity.result"
cp "$finding_portability/result" "$output/executable/campaign-replay.result"
cp "$hot_fork_scaling/result" "$output/executable/hot-fork-scaling.result"
cp -R "$required_gates" "$output/executable/campaign-required-gates"

release_contract_source="$release_acceptance_contract/campaign-release-acceptance-contract.toml"
require_file "$release_contract_source"
cat > "$output/release-acceptance.env" <<RESULT
schema=aos.crucible.campaign-release-acceptance.v2
gate=gate:campaign-release-acceptance
acceptance=pass
release_manifest_sha256=$(digest_file "$release_manifest/result")
release_manifest_env_sha256=$(digest_file "$crucible_package/share/aos/crucible/release-manifest.env")
release_manifest_json_sha256=$(digest_file "$crucible_package/share/aos/crucible/release-manifest.json")
release_acceptance_contract_sha256=$(digest_file "$release_contract_source")
e2e_evidence_result_sha256=$e2e_sha256
e2e_evidence_manifest_sha256=$e2e_manifest_sha256
campaign_gate_matrix_result_sha256=$matrix_sha256
campaign_operational_continuity_result_sha256=$continuity_sha256
campaign_finding_portability_result_sha256=$portability_sha256
hot_fork_scaling_result_sha256=$scaling_sha256
campaign_required_gates_result_sha256=$required_gates_sha256
RESULT

cat > "$output/result" <<RESULT
PASS
gate=gate:campaign-release-acceptance
acceptance=pass
manifest_sha256=$(digest_file "$output/release-acceptance.env")
e2e_evidence_retained=true
executable_gate_results_retained=true
release_manifest_retained=true
release_acceptance_contract_retained=true
ordinary_source_package_dependency=false
RESULT
