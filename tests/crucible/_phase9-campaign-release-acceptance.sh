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

require_file() {
    test -f "$1" && test ! -L "$1" && test -s "$1" \
        || fail "required input is not a nonempty regular non-symlink file: $1"
}

require_evidence_file() {
    evidence_root=$1
    relative=$2
    require_relative_path "$relative"

    current=$evidence_root
    remaining=$relative
    while test "$remaining" != "${remaining#*/}"; do
        component=${remaining%%/*}
        remaining=${remaining#*/}
        current="$current/$component"
        test ! -L "$current" \
            || fail "evidence path traverses a symlink: $relative"
        test -d "$current" \
            || fail "evidence path traverses a non-directory: $relative"
    done
    require_file "$current/$remaining"
    if test -n "${EVIDENCE_INVENTORY:-}"; then
        printf '%s\n' "$relative" >> "$EVIDENCE_INVENTORY"
    fi
}

verify_complete_evidence_tree() {
    evidence_root=$1
    inventory=$2
    authorized="$TMPDIR/campaign-release-authorized-evidence"
    sort -u "$inventory" > "$authorized"

    test -z "$(find "$evidence_root" -mindepth 1 -type l -print -quit)" \
        || fail "$evidence_root contains a symlink"
    test -z "$(find "$evidence_root" -mindepth 1 ! -type d ! -type f -print -quit)" \
        || fail "$evidence_root contains a nonregular entry"
    find "$evidence_root" -mindepth 1 -type f -exec bash -c '
        evidence_root=$1
        authorized=$2
        shift 2
        for path do
            relative=${path#"$evidence_root"/}
            grep -Fqx "$relative" "$authorized" \
                || exit 42
        done
    ' _ "$evidence_root" "$authorized" {} + \
        || fail "$evidence_root contains an unbound regular file"
}

require_digest() {
    value=$1
    printf '%s\n' "$value" | grep -Eq '^[0-9a-f]{64}$' \
        || fail "evidence digest is not lowercase SHA-256: $value"
}

record_unique_fingerprint() {
    fingerprint=$1
    fingerprints_file=$2
    printf '%s\n' "$fingerprint" | grep -Eq '^SHA256:[A-Za-z0-9+/=]+$' \
        || fail "trusted signing key fingerprint is invalid: $fingerprint"
    grep -Fqx "$fingerprint" "$fingerprints_file" \
        && fail "one trusted signing key is reused across required roles"
    printf '%s\n' "$fingerprint" >> "$fingerprints_file"
}

spec_values() {
    row_kind=$1
    spec=$2
    tab=$(printf '\t')
    sed -n "s/^${row_kind}${tab}//p" "$spec"
}

spec_value() {
    row_kind=$1
    spec=$2
    values=$(spec_values "$row_kind" "$spec")
    test "$(printf '%s\n' "$values" | grep -c . || true)" -eq 1 \
        || fail "$spec must contain exactly one $row_kind row"
    printf '%s\n' "$values"
}

require_relative_path() {
    relative=$1
    case "$relative" in
        ''|.|..|/*|../*|*/../*|*/..)
            fail "evidence path is not a safe relative path: $relative"
            ;;
    esac
}

verify_manifest_requirements() {
    evidence=$1
    spec=$2
    tab=$(printf '\t')

    while IFS="$tab" read -r row_kind first second extra; do
        case "$row_kind" in
            field)
                test -z "$extra" || fail "$spec contains an invalid field row"
                test "$(field "$first" "$evidence/manifest.env")" = "$second" \
                    || fail "$evidence manifest has the wrong $first value"
                ;;
            present)
                test -z "$second$extra" || fail "$spec contains an invalid present row"
                test -n "$(field "$first" "$evidence/manifest.env")" \
                    || fail "$evidence manifest has an empty $first value"
                ;;
            minimum)
                test -z "$extra" || fail "$spec contains an invalid minimum row"
                actual=$(field "$first" "$evidence/manifest.env")
                printf '%s\n' "$actual" | grep -Eq '^[0-9]+$' \
                    || fail "$evidence manifest has a nonnumeric $first value"
                test "$actual" -ge "$second" \
                    || fail "$evidence manifest does not meet minimum $first=$second"
                ;;
            maximum)
                test -z "$extra" || fail "$spec contains an invalid maximum row"
                actual=$(field "$first" "$evidence/manifest.env")
                printf '%s\n' "$actual" | grep -Eq '^[0-9]+$' \
                    || fail "$evidence manifest has a nonnumeric $first value"
                test "$actual" -le "$second" \
                    || fail "$evidence manifest exceeds maximum $first=$second"
                ;;
            different)
                test -z "$extra" || fail "$spec contains an invalid different row"
                test "$(field "$first" "$evidence/manifest.env")" \
                    != "$(field "$second" "$evidence/manifest.env")" \
                    || fail "$evidence manifest reuses $first as $second"
                ;;
        esac
    done < "$spec"
}

verify_command_journal() {
    evidence=$1
    spec=$2
    journal="$evidence/command-journal.tsv"
    tab=$(printf '\t')
    header=$(sed -n '1p' "$journal")
    test "$header" = "operation${tab}exit_status${tab}structured_output_path${tab}structured_output_sha256" \
        || fail "$journal has an unsupported schema"

    rows_file="$TMPDIR/campaign-release-journal-rows"
    operations_file="$TMPDIR/campaign-release-journal-operations"
    declared_operations_file="$TMPDIR/campaign-release-declared-operations"
    : > "$rows_file"
    : > "$operations_file"
    spec_values operation "$spec" > "$declared_operations_file"
    test -s "$declared_operations_file" \
        || fail "$spec declares no required operations"
    test "$(wc -l < "$declared_operations_file" | tr -d ' ')" \
        -eq "$(sort -u "$declared_operations_file" | wc -l | tr -d ' ')" \
        || fail "$spec declares a required operation more than once"
    rows=0
    sed -n '2,$p' "$journal" |
        while IFS="$tab" read -r operation exit_status relative expected_sha256 extra; do
            test -n "$operation" || fail "$journal contains an empty operation"
            printf '%s\n' "$operation" | grep -Eq '^[a-z0-9][a-z0-9._-]*$' \
                || fail "$journal contains an invalid operation: $operation"
            printf '%s\n' "$exit_status" | grep -Eq '^[0-9]+$' \
                || fail "$journal contains an invalid exit status: $exit_status"
            test "$exit_status" -eq 0 \
                || fail "$journal contains a nonzero exit status for $operation"
            grep -Fqx "$operation" "$declared_operations_file" \
                || fail "$journal contains undeclared operation: $operation"
            grep -Fqx "$operation" "$operations_file" \
                && fail "$journal contains duplicate operation: $operation"
            printf '%s\n' "$operation" >> "$operations_file"
            test -z "$extra" || fail "$journal contains an unexpected field"
            require_relative_path "$relative"
            require_digest "$expected_sha256"
            require_evidence_file "$evidence" "$relative"
            test "$(digest_file "$evidence/$relative")" = "$expected_sha256" \
                || fail "$journal structured output digest does not match: $relative"
            rows=$((rows + 1))
            printf '%s\n' "$rows" > "$rows_file"
        done
    test -s "$rows_file" \
        || fail "$journal contains no command records"

    while IFS= read -r required_operation; do
            test "$(grep -Fxc "$required_operation" "$operations_file" || true)" -eq 1 \
                || fail "$journal omits required operation: $required_operation"
        done < "$declared_operations_file"
    spec_values forbidden_operation "$spec" |
        while IFS= read -r forbidden_operation; do
            if sed -n '2,$p' "$journal" | cut -f1 | grep -Fqx "$forbidden_operation"; then
                fail "$journal uses forbidden recovery operation: $forbidden_operation"
            fi
        done
}

verify_artifact_manifest() {
    evidence=$1
    spec=$2
    artifact_manifest="$evidence/artifact-manifest.tsv"
    tab=$(printf '\t')
    header=$(sed -n '1p' "$artifact_manifest")
    test "$header" = "relative_path${tab}sha256" \
        || fail "$artifact_manifest has an unsupported schema"

    rows_file="$TMPDIR/campaign-release-artifact-rows"
    paths_file="$TMPDIR/campaign-release-artifact-paths"
    : > "$rows_file"
    : > "$paths_file"
    rows=0
    sed -n '2,$p' "$artifact_manifest" |
        while IFS="$tab" read -r relative expected_sha256 extra; do
            test -z "$extra" || fail "$artifact_manifest contains an unexpected field"
            require_relative_path "$relative"
            grep -Fqx "$relative" "$paths_file" \
                && fail "$artifact_manifest lists one artifact more than once: $relative"
            printf '%s\n' "$relative" >> "$paths_file"
            require_digest "$expected_sha256"
            require_evidence_file "$evidence" "artifacts/$relative"
            test "$(digest_file "$evidence/artifacts/$relative")" = "$expected_sha256" \
                || fail "$artifact_manifest payload digest does not match: $relative"
            rows=$((rows + 1))
            printf '%s\n' "$rows" > "$rows_file"
        done
    test -s "$rows_file" \
        || fail "$artifact_manifest contains no retained artifacts"

    spec_values artifact "$spec" |
        while IFS= read -r required_pattern; do
            matched=false
            while IFS= read -r relative; do
                case "$required_pattern" in
                    *'*'*)
                        prefix=${required_pattern%%\**}
                        suffix=${required_pattern#*\*}
                        case "$relative" in
                            "$prefix"*"$suffix") matched=true ;;
                        esac
                        ;;
                    *)
                        test "$relative" != "$required_pattern" || matched=true
                        ;;
                esac
            done < "$paths_file"
            test "$matched" = true \
                || fail "$artifact_manifest omits required artifact: $required_pattern"
        done
}

verify_resource_audit() {
    evidence=$1
    spec=$2
    audit="$evidence/resource-audit.tsv"
    tab=$(printf '\t')
    test "$(sed -n '1p' "$audit")" = "resource${tab}status" \
        || fail "$audit has an unsupported schema"

    resources_file="$TMPDIR/campaign-release-resources"
    : > "$resources_file"
    sed -n '2,$p' "$audit" |
        while IFS="$tab" read -r resource status extra; do
            test -n "$resource" || fail "$audit contains an empty resource"
            test -z "$extra" || fail "$audit contains an unexpected field"
            test "$status" = clean || fail "$audit reports non-clean resource: $resource"
            grep -Fqx "$resource" "$resources_file" \
                && fail "$audit lists one resource more than once: $resource"
            printf '%s\n' "$resource" >> "$resources_file"
        done
    test -s "$resources_file" || fail "$audit contains no resource records"

    spec_values resource "$spec" |
        while IFS= read -r required_resource; do
            grep -Fqx "$required_resource" "$resources_file" \
                || fail "$audit omits required resource: $required_resource"
        done
}

verify_injection_records() {
    evidence=$1
    spec=$2
    test "$(spec_values injection "$spec" | grep -c . || true)" -gt 0 || return 0

    records="$evidence/injection-records.tsv"
    require_evidence_file "$evidence" injection-records.tsv
    tab=$(printf '\t')
    test "$(sed -n '1p' "$records")" \
        = "injection${tab}status${tab}backend_scope${tab}prior_state_path${tab}prior_state_sha256${tab}observables_path${tab}observables_sha256${tab}recovery_path${tab}recovery_sha256" \
        || fail "$records has an unsupported schema"
    injections_file="$TMPDIR/campaign-release-injections"
    : > "$injections_file"
    sed -n '2,$p' "$records" |
        while IFS="$tab" read -r \
            injection status backend_scope \
            prior_state_path prior_state_sha256 \
            observables_path observables_sha256 \
            recovery_path recovery_sha256 extra
        do
            test -n "$injection" || fail "$records contains an empty injection"
            test -z "$extra" || fail "$records contains an unexpected field"
            test "$status" = pass || fail "$records reports non-passing injection: $injection"
            spec_values injection "$spec" | grep -Fqx "$injection" \
                || fail "$records names undeclared injection: $injection"
            expected_backend_scope=$(spec_values injection_backend "$spec" \
                | sed -n "s/^$injection${tab}//p")
            test "$(printf '%s\n' "$expected_backend_scope" | grep -c . || true)" -eq 1 \
                || fail "$spec does not define exactly one backend scope for $injection"
            test "$backend_scope" = "$expected_backend_scope" \
                || fail "$records reports the wrong backend scope for $injection"
            verify_injection_payload() {
                relative=$1
                expected_sha256=$2
                require_relative_path "$relative"
                require_digest "$expected_sha256"
                require_evidence_file "$evidence" "$relative"
                test "$(digest_file "$evidence/$relative")" = "$expected_sha256" \
                    || fail "$records payload digest does not match: $relative"
            }
            verify_injection_payload "$prior_state_path" "$prior_state_sha256"
            verify_injection_payload "$observables_path" "$observables_sha256"
            verify_injection_payload "$recovery_path" "$recovery_sha256"
            grep -Fqx "$injection" "$injections_file" \
                && fail "$records lists one injection more than once: $injection"
            printf '%s\n' "$injection" >> "$injections_file"
        done

    spec_values injection "$spec" |
        while IFS= read -r required_injection; do
            grep -Fqx "$required_injection" "$injections_file" \
                || fail "$records omits required injection: $required_injection"
        done
}

verify_manual_evidence() {
    evidence=$1
    expected_gate=$2
    expected_release_manifest_sha256=$3
    expected_release_manifest_env_sha256=$4
    expected_release_manifest_json_sha256=$5
    spec=$6
    trusted_allowed_signers=$7

    inventory_suffix=$(printf '%s' "$expected_gate" | tr -c 'A-Za-z0-9' '-')
    EVIDENCE_INVENTORY="$TMPDIR/campaign-release-evidence-$inventory_suffix"
    export EVIDENCE_INVENTORY
    : > "$EVIDENCE_INVENTORY"

    for relative in \
        manifest.env \
        result \
        command-journal.tsv \
        artifact-manifest.tsv \
        resource-audit.tsv
    do
        require_evidence_file "$evidence" "$relative"
    done

    test "$(field schema "$evidence/manifest.env")" \
        = "aos.crucible.campaign-manual-evidence.v1" \
        || fail "$expected_gate evidence schema is unsupported"
    test "$(field gate "$evidence/manifest.env")" = "$expected_gate" \
        || fail "$expected_gate evidence names another gate"
    test "$(field acceptance "$evidence/manifest.env")" = pass \
        || fail "$expected_gate evidence is not accepted"
    test "$(field release_manifest_sha256 "$evidence/manifest.env")" \
        = "$expected_release_manifest_sha256" \
        || fail "$expected_gate evidence is bound to another release manifest"
    test "$(field release_manifest_env_sha256 "$evidence/manifest.env")" \
        = "$expected_release_manifest_env_sha256" \
        || fail "$expected_gate evidence is bound to another shipped release manifest env"
    test "$(field release_manifest_json_sha256 "$evidence/manifest.env")" \
        = "$expected_release_manifest_json_sha256" \
        || fail "$expected_gate evidence is bound to another shipped release manifest JSON"
    expected_contract_sha256=$(spec_value contract_sha256 "$spec")
    test "$(field manual_contract_sha256 "$evidence/manifest.env")" \
        = "$expected_contract_sha256" \
        || fail "$expected_gate evidence is bound to another manual contract"
    expected_release_acceptance_contract_sha256=$(
        spec_value release_acceptance_contract_sha256 "$spec"
    )
    test "$(field release_acceptance_contract_sha256 "$evidence/manifest.env")" \
        = "$expected_release_acceptance_contract_sha256" \
        || fail "$expected_gate evidence is bound to another release acceptance contract"
    test "$(field result_sha256 "$evidence/manifest.env")" \
        = "$(digest_file "$evidence/result")" \
        || fail "$expected_gate result digest does not match"
    test "$(field command_journal_sha256 "$evidence/manifest.env")" \
        = "$(digest_file "$evidence/command-journal.tsv")" \
        || fail "$expected_gate command journal digest does not match"
    test "$(field artifact_manifest_sha256 "$evidence/manifest.env")" \
        = "$(digest_file "$evidence/artifact-manifest.tsv")" \
        || fail "$expected_gate artifact manifest digest does not match"
    test "$(field resource_audit_sha256 "$evidence/manifest.env")" \
        = "$(digest_file "$evidence/resource-audit.tsv")" \
        || fail "$expected_gate resource audit digest does not match"
    if test "$(spec_values injection "$spec" | grep -c . || true)" -gt 0; then
        require_evidence_file "$evidence" injection-records.tsv
        test "$(field injection_records_sha256 "$evidence/manifest.env")" \
            = "$(digest_file "$evidence/injection-records.tsv")" \
            || fail "$expected_gate injection records digest does not match"
    fi
    verify_manifest_requirements "$evidence" "$spec"
    verify_command_journal "$evidence" "$spec"
    verify_artifact_manifest "$evidence" "$spec"
    verify_resource_audit "$evidence" "$spec"
    verify_injection_records "$evidence" "$spec"
    test "$(sed -n '1p' "$evidence/result")" = PASS \
        || fail "$expected_gate result does not report PASS"
    test "$(field gate "$evidence/result")" = "$expected_gate" \
        || fail "$expected_gate result names another gate"
    test "$(field acceptance "$evidence/result")" = pass \
        || fail "$expected_gate result is not accepted"

    manifest_sha256=$(digest_file "$evidence/manifest.env")
    signer_identities_file="$TMPDIR/campaign-release-signers"
    signer_fingerprints_file="$TMPDIR/campaign-release-signer-fingerprints"
    signer_bindings_file=$8
    signer_count_file="$TMPDIR/campaign-release-signer-count"
    : > "$signer_identities_file"
    : > "$signer_fingerprints_file"
    : > "$signer_count_file"
    signer_count=0
    spec_values signer_role "$spec" |
        while IFS= read -r role; do
        sign_off="$evidence/sign-offs/$role.env"
        signature="$evidence/sign-offs/$role.sig"
        require_evidence_file "$evidence" "sign-offs/$role.env"
        require_evidence_file "$evidence" "sign-offs/$role.sig"
        test "$(field schema "$sign_off")" \
            = "aos.crucible.campaign-manual-sign-off.v1" \
            || fail "$expected_gate $role sign-off schema is unsupported"
        test "$(field role "$sign_off")" = "$role" \
            || fail "$expected_gate sign-off has the wrong role"
        test "$(field decision "$sign_off")" = pass \
            || fail "$expected_gate $role did not approve"
        test "$(field manifest_sha256 "$sign_off")" = "$manifest_sha256" \
            || fail "$expected_gate $role signed another manifest"
        signer_identity=$(field signer_identity "$sign_off")
        printf '%s\n' "$signer_identity" | grep -Eq '^[A-Za-z0-9._@+-]{1,128}$' \
            || fail "$expected_gate $role signer identity is invalid"
        grep -Fqx "$signer_identity" "$signer_identities_file" \
            && fail "$expected_gate reuses one signer identity across roles"
        printf '%s\n' "$signer_identity" >> "$signer_identities_file"
        signer_count=$((signer_count + 1))
        printf '%s\n' "$signer_count" > "$signer_count_file"

        verification_output=$(ssh-keygen -Y verify \
            -f "$trusted_allowed_signers" \
            -I "$signer_identity" \
            -n crucible-campaign-manual-evidence \
            -s "$signature" \
            < "$sign_off" 2>&1) \
            || fail "$expected_gate $role detached signature is invalid"
        signer_fingerprint=$(printf '%s\n' "$verification_output" \
            | sed -n 's/.* key \(SHA256:[A-Za-z0-9+\/=]*\)$/\1/p')
        test "$(printf '%s\n' "$signer_fingerprint" | grep -c . || true)" -eq 1 \
            || fail "$expected_gate $role signature did not resolve one trusted key fingerprint"
        record_unique_fingerprint "$signer_fingerprint" "$signer_fingerprints_file"
        printf '%s\t%s\t%s\t%s\n' \
            "$expected_gate" "$role" "$signer_identity" "$signer_fingerprint" \
            >> "$signer_bindings_file"
        done
    test -s "$signer_count_file" \
        || fail "$expected_gate evidence declares no sign-off roles"
    test "$(cat "$signer_count_file")" -ge 3 \
        || fail "$expected_gate evidence has fewer than three distinct signers"

    verify_complete_evidence_tree "$evidence" "$EVIDENCE_INVENTORY"

    digest_file "$evidence/result"
}

require_gate_result() {
    gate_path=$1
    expected_gate=$2
    require_file "$gate_path/result"
    test "$(sed -n '1p' "$gate_path/result")" = PASS \
        || fail "$expected_gate executable result does not report PASS"
    test "$(field gate "$gate_path/result")" = "$expected_gate" \
        || fail "$expected_gate executable result names another gate"
    digest_file "$gate_path/result"
}

verify_required_gates() {
    required_gates=$1
    expected_gates=$2
    result_sha256=$(require_gate_result \
        "$required_gates" gate:campaign-required-gates)
    manifest="$required_gates/manifest.tsv"
    declared_gates="$required_gates/required-claim-gates.txt"
    require_file "$manifest"
    require_file "$declared_gates"
    require_file "$expected_gates"
    expected_claim_count=$(wc -l < "$expected_gates" | tr -d ' ')

    test "$(field required_claim_count "$required_gates/result")" -eq "$expected_claim_count" \
        || fail "required-gates aggregate does not authenticate $expected_claim_count claims"
    test "$(field all_required_claims_authenticated "$required_gates/result")" = true \
        || fail "required-gates aggregate did not authenticate every claim"
    test "$(field manifest_sha256 "$required_gates/result")" \
        = "$(digest_file "$manifest")" \
        || fail "required-gates aggregate manifest digest does not match"
    test "$(field required_claim_gates_sha256 "$required_gates/result")" \
        = "$(digest_file "$declared_gates")" \
        || fail "required-gates aggregate claim inventory digest does not match"
    test "$(digest_file "$declared_gates")" = "$(digest_file "$expected_gates")" \
        || fail "required-gates aggregate differs from the release contract"

    tab=$(printf '\t')
    test "$(sed -n '1p' "$manifest")" = "gate${tab}result_sha256" \
        || fail "$manifest has an unsupported schema"
    observed_gates="$TMPDIR/campaign-release-required-gates"
    : > "$observed_gates"
    cut -f1 "$manifest" | sed -n '2,$p' > "$observed_gates"
    test "$(digest_file "$observed_gates")" = "$(digest_file "$expected_gates")" \
        || fail "$manifest does not contain the exact required gate inventory"
    test -d "$required_gates/results" \
        && test ! -L "$required_gates/results" \
        || fail "required-gates aggregate has no regular results directory"
    test -z "$(find "$required_gates/results" -mindepth 1 -type l -print -quit)" \
        || fail "required-gates aggregate results contain a symlink"
    test -z "$(find "$required_gates/results" -mindepth 1 ! -type f -print -quit)" \
        || fail "required-gates aggregate results contain a nonregular entry"
    test "$(find "$required_gates/results" -mindepth 1 -type f | wc -l | tr -d ' ')" -eq "$expected_claim_count" \
        || fail "required-gates aggregate does not retain exactly $expected_claim_count results"

    : > "$observed_gates"
    sed -n '2,$p' "$manifest" |
        while IFS="$tab" read -r gate result_digest extra; do
            test -n "$gate" || fail "$manifest contains an empty gate"
            test -z "$extra" || fail "$manifest contains an unexpected field"
            printf '%s\n' "$gate" | grep -Eq '^gate:[a-z0-9][a-z0-9._-]*$' \
                || fail "$manifest contains an invalid gate: $gate"
            require_digest "$result_digest"
            grep -Fqx "$gate" "$observed_gates" \
                && fail "$manifest lists one gate more than once: $gate"
            printf '%s\n' "$gate" >> "$observed_gates"
            result_name=$(printf '%s\n' "$gate" | sed 's/:/-/')
            require_file "$required_gates/results/$result_name.result"
            test "$(digest_file "$required_gates/results/$result_name.result")" \
                = "$result_digest" \
                || fail "$manifest result digest does not match: $gate"
        done
    test "$(wc -l < "$observed_gates" | tr -d ' ')" -eq "$expected_claim_count" \
        || fail "$manifest does not contain exactly $expected_claim_count required gates"

    printf '%s\n' "$result_sha256"
}

verify_release_manifest() {
    crucible_package=$1
    release_manifest=$2
    shipped_manifest_env="$crucible_package/share/aos/crucible/release-manifest.env"
    shipped_manifest_json="$crucible_package/share/aos/crucible/release-manifest.json"
    require_file "$release_manifest/result"
    require_file "$shipped_manifest_env"
    require_file "$shipped_manifest_json"
    test "$(sed -n '1p' "$release_manifest/result")" = PASS \
        || fail "release manifest result does not report PASS"
    for key in \
        crucible_source_store_hash \
        qemu_atomic_patch_hash \
        qemu_build_id \
        shmem_abi \
        guest_host_protocol_abi \
        rpc_abi
    do
        test -n "$(field "$key" "$release_manifest/result")" \
            || fail "release manifest result has an empty $key"
    done
    test "$(field cargo_deps "$release_manifest/result")" = fetchCargoVendor \
        || fail "release manifest does not bind the current Cargo dependency source"
    test "$(field cargo_deps_vendored "$release_manifest/result")" = true \
        || fail "release manifest does not require vendored Cargo dependencies"
    test "$(field timestamp_policy "$release_manifest/result")" \
        = no-wall-clock-timestamps \
        || fail "release manifest permits wall-clock timestamps"
    test "$(field host_path_policy "$release_manifest/result")" = no-host-paths \
        || fail "release manifest permits host paths"
    test "$(field crucible_package_store_path "$release_manifest/result")" \
        = "$crucible_package" \
        || fail "release manifest check validated another Crucible package"
    test "$(field release_manifest_env_sha256 "$release_manifest/result")" \
        = "$(digest_file "$shipped_manifest_env")" \
        || fail "release manifest check summary is not bound to the shipped env manifest"
    test "$(field release_manifest_json_sha256 "$release_manifest/result")" \
        = "$(digest_file "$shipped_manifest_json")" \
        || fail "release manifest check summary is not bound to the shipped JSON manifest"

    test "$(field crucible_source_store_hash "$shipped_manifest_env")" \
        = "$(field crucible_source_store_hash "$release_manifest/result")" \
        || fail "shipped release manifest names another Crucible source"
    test "$(field qemu_atomic_patch_hash "$shipped_manifest_env")" \
        = "$(field qemu_atomic_patch_hash "$release_manifest/result")" \
        || fail "shipped release manifest names another QEMU patch"
    test "$(field qemu_build_id "$shipped_manifest_env")" \
        = "$(field qemu_build_id "$release_manifest/result")" \
        || fail "shipped release manifest names another QEMU build"
}

if test "$#" -eq 3 && test "$1" = --probe-evidence-file; then
    require_evidence_file "$2" "$3"
    exit 0
fi
if test "$#" -eq 2 && test "$1" = --probe-distinct-fingerprints; then
    fingerprints_file=$2
    observed="$TMPDIR/campaign-release-probe-fingerprints"
    : > "$observed"
    while IFS= read -r fingerprint; do
        record_unique_fingerprint "$fingerprint" "$observed"
    done < "$fingerprints_file"
    exit 0
fi
if test "$#" -eq 3 && test "$1" = --probe-command-journal; then
    EVIDENCE_INVENTORY="$TMPDIR/campaign-release-probe-inventory"
    export EVIDENCE_INVENTORY
    : > "$EVIDENCE_INVENTORY"
    verify_command_journal "$2" "$3"
    exit 0
fi
if test "$#" -eq 3 && test "$1" = --probe-manifest-requirements; then
    verify_manifest_requirements "$2" "$3"
    exit 0
fi
if test "$#" -eq 3 && test "$1" = --probe-required-gates; then
    verify_required_gates "$2" "$3" > /dev/null
    exit 0
fi
if test "$#" -eq 3 && test "$1" = --probe-evidence-tree; then
    verify_complete_evidence_tree "$2" "$3"
    exit 0
fi

test "$#" -eq 18 || fail "expected eighteen release-acceptance inputs"

operator_evidence=$1
operator_spec=$2
destructive_evidence=$3
destructive_spec=$4
dogfood_evidence=$5
dogfood_spec=$6
e2e_evidence=$7
e2e_spec=$8
gate_matrix=$9
operational_continuity=${10}
finding_portability=${11}
hot_fork_scaling=${12}
required_gates=${13}
crucible_package=${14}
release_manifest=${15}
release_acceptance_contract=${16}
trusted_allowed_signers=${17}
output=${18}

verify_release_manifest "$crucible_package" "$release_manifest"
require_file "$release_acceptance_contract/result"
require_file "$trusted_allowed_signers"
test "$(sed -n '1p' "$release_acceptance_contract/result")" = CONTRACT_VALIDATED \
    || fail "release acceptance contract validator did not succeed"
test "$(field gate "$release_acceptance_contract/result")" \
    = gate:campaign-release-acceptance \
    || fail "release acceptance contract validator names another gate"
test "$(field acceptance "$release_acceptance_contract/result")" = not-evaluated \
    || fail "release acceptance contract validator claims an acceptance result"
release_manifest_sha256=$(digest_file "$release_manifest/result")
release_manifest_env_sha256=$(digest_file \
    "$crucible_package/share/aos/crucible/release-manifest.env")
release_manifest_json_sha256=$(digest_file \
    "$crucible_package/share/aos/crucible/release-manifest.json")
release_acceptance_contract_result_sha256=$(digest_file "$release_acceptance_contract/result")
release_acceptance_contract_sha256=$(spec_value release_acceptance_contract_sha256 "$operator_spec")
test "$(digest_file "$release_acceptance_contract/campaign-release-acceptance-contract.toml")" \
    = "$release_acceptance_contract_sha256" \
    || fail "release acceptance contract source and evidence specs differ"
operator_contract_sha256=$(spec_value contract_sha256 "$operator_spec")
destructive_contract_sha256=$(spec_value contract_sha256 "$destructive_spec")
dogfood_contract_sha256=$(spec_value contract_sha256 "$dogfood_spec")
e2e_contract_sha256=$(spec_value contract_sha256 "$e2e_spec")
for spec in \
    "$destructive_spec" \
    "$dogfood_spec" \
    "$e2e_spec"
do
    test "$(spec_value release_acceptance_contract_sha256 "$spec")" \
        = "$release_acceptance_contract_sha256" \
        || fail "manual evidence specs name different release acceptance contracts"
done

signer_key_bindings="$TMPDIR/campaign-release-signer-key-bindings.tsv"
printf 'gate\trole\tidentity\tkey_fingerprint\n' > "$signer_key_bindings"
operator_sha256=$(verify_manual_evidence \
    "$operator_evidence" gate:campaign-operator-acceptance "$release_manifest_sha256" \
    "$release_manifest_env_sha256" "$release_manifest_json_sha256" \
    "$operator_spec" \
    "$trusted_allowed_signers" "$signer_key_bindings")
destructive_sha256=$(verify_manual_evidence \
    "$destructive_evidence" gate:campaign-destructive-recovery "$release_manifest_sha256" \
    "$release_manifest_env_sha256" "$release_manifest_json_sha256" \
    "$destructive_spec" \
    "$trusted_allowed_signers" "$signer_key_bindings")
dogfood_sha256=$(verify_manual_evidence \
    "$dogfood_evidence" gate:campaign-dogfood "$release_manifest_sha256" \
    "$release_manifest_env_sha256" "$release_manifest_json_sha256" \
    "$dogfood_spec" \
    "$trusted_allowed_signers" "$signer_key_bindings")
e2e_sha256=$(verify_manual_evidence \
    "$e2e_evidence" gate:e2e-determinism "$release_manifest_sha256" \
    "$release_manifest_env_sha256" "$release_manifest_json_sha256" \
    "$e2e_spec" \
    "$trusted_allowed_signers" "$signer_key_bindings")

operator_manifest_sha256=$(digest_file "$operator_evidence/manifest.env")
destructive_manifest_sha256=$(digest_file "$destructive_evidence/manifest.env")
dogfood_manifest_sha256=$(digest_file "$dogfood_evidence/manifest.env")
e2e_manifest_sha256=$(digest_file "$e2e_evidence/manifest.env")

matrix_sha256=$(require_gate_result "$gate_matrix" gate:campaign-gate-matrix)
continuity_sha256=$(require_gate_result \
    "$operational_continuity" gate:campaign-operational-continuity)
portability_sha256=$(require_gate_result "$finding_portability" gate:campaign-replay)
scaling_sha256=$(require_gate_result "$hot_fork_scaling" gate:hot-fork-scaling)
required_gates_sha256=$(verify_required_gates \
    "$required_gates" "$release_acceptance_contract/required-claim-gates.txt")

mkdir -p "$output/evidence" "$output/executable" "$output/release-manifest"
cp -R "$operator_evidence" "$output/evidence/operator"
cp -R "$destructive_evidence" "$output/evidence/destructive-recovery"
cp -R "$dogfood_evidence" "$output/evidence/dogfood"
cp -R "$e2e_evidence" "$output/evidence/e2e-determinism"
cp "$trusted_allowed_signers" "$output/trusted-allowed-signers"
cp "$signer_key_bindings" "$output/signer-key-bindings.tsv"
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
cp "$required_gates/result" "$output/executable/campaign-required-gates.result"
cp "$required_gates/manifest.tsv" \
    "$output/executable/campaign-required-gates-manifest.tsv"
cp "$required_gates/required-claim-gates.txt" \
    "$output/executable/campaign-required-claim-gates.txt"
cp -R "$required_gates/results" \
    "$output/executable/campaign-required-gate-results"

cat > "$output/release-acceptance.env" <<RESULT
schema=aos.crucible.campaign-release-acceptance.v1
gate=gate:campaign-release-acceptance
acceptance=pass
release_manifest_sha256=$release_manifest_sha256
release_manifest_env_sha256=$release_manifest_env_sha256
release_manifest_json_sha256=$release_manifest_json_sha256
release_acceptance_contract_sha256=$release_acceptance_contract_sha256
release_acceptance_contract_result_sha256=$release_acceptance_contract_result_sha256
trusted_allowed_signers_sha256=$(digest_file "$trusted_allowed_signers")
signer_key_bindings_sha256=$(digest_file "$signer_key_bindings")
operator_contract_sha256=$operator_contract_sha256
destructive_recovery_contract_sha256=$destructive_contract_sha256
dogfood_contract_sha256=$dogfood_contract_sha256
e2e_determinism_contract_sha256=$e2e_contract_sha256
campaign_gate_matrix_result_sha256=$matrix_sha256
campaign_operational_continuity_result_sha256=$continuity_sha256
campaign_finding_portability_result_sha256=$portability_sha256
hot_fork_scaling_result_sha256=$scaling_sha256
campaign_required_gates_result_sha256=$required_gates_sha256
campaign_required_gates_manifest_sha256=$(digest_file "$required_gates/manifest.tsv")
campaign_required_gates_inventory_sha256=$(digest_file "$required_gates/required-claim-gates.txt")
operator_evidence_result_sha256=$operator_sha256
operator_evidence_manifest_sha256=$operator_manifest_sha256
destructive_recovery_evidence_result_sha256=$destructive_sha256
destructive_recovery_evidence_manifest_sha256=$destructive_manifest_sha256
dogfood_evidence_result_sha256=$dogfood_sha256
dogfood_evidence_manifest_sha256=$dogfood_manifest_sha256
e2e_determinism_evidence_result_sha256=$e2e_sha256
e2e_determinism_evidence_manifest_sha256=$e2e_manifest_sha256
RESULT

cat > "$output/result" <<RESULT
PASS
gate=gate:campaign-release-acceptance
acceptance=pass
manifest_sha256=$(digest_file "$output/release-acceptance.env")
manual_evidence_retained=true
manual_contracts_retained=true
executable_gate_results_retained=true
release_manifest_retained=true
release_acceptance_contract_retained=true
ordinary_source_package_dependency=false
RESULT
