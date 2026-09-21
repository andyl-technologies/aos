# Native hostile-host and cross-host runner for gate:e2e-determinism.
#
# Invoke this file with the AOS-built bash supplied by the fleet derivation.
# `run-gate` executes the automated hostile machine-profile matrix and retains
# raw CLI output, canonical comparisons, artifact digests, and closure identity.
# `run-host` additionally binds that evidence to an operator-supplied physical
# host attestation.
# `verify-cross-host` accepts only two independently produced bundles whose
# physical identities differ and whose canonical results and artifacts match.

set -eu

fail() {
    echo "crucible e2e native runner: $*" >&2
    exit 1
}

require_file() {
    test -f "$1" || fail "required file is absent: $1"
}

require_directory() {
    test -d "$1" || fail "required directory is absent: $1"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "required command is absent: $1"
}

field() {
    field_name="$1"
    field_file="$2"
    value="$(sed -n "s/^${field_name}=//p" "$field_file")"
    test -n "$value" || fail "${field_file} omits ${field_name}"
    test "$(grep -c "^${field_name}=" "$field_file")" -eq 1 \
        || fail "${field_file} repeats ${field_name}"
    printf '%s\n' "$value"
}

digest_file() {
    require_file "$1"
    sha256sum "$1" | cut -d ' ' -f 1
}

allowed_cpus() {
    allowed="$(sed -n 's/^Cpus_allowed_list:[[:space:]]*//p' /proc/self/status)"
    test -n "$allowed" || fail "cannot read the allowed CPU set"

    old_ifs="$IFS"
    IFS=,
    for group in $allowed; do
        case "$group" in
            *-*)
                first="${group%%-*}"
                last="${group#*-}"
                cpu="$first"
                while test "$cpu" -le "$last"; do
                    printf '%s\n' "$cpu"
                    cpu=$((cpu + 1))
                done
                ;;
            *)
                printf '%s\n' "$group"
                ;;
        esac
    done
    IFS="$old_ifs"
}

start_host_pressure() {
    pressure_directory="$1"
    pressure_cpus="$2"
    cpu_workers="$3"
    io_workers="$4"
    worker_seed="$5"

    : > "$pressure_directory/pids"
    : > "$pressure_directory/status"
    pressure_cpu_count="$(printf '%s\n' "$pressure_cpus" | tr , '\n' | wc -l)"
    worker=0
    while test "$worker" -lt "$cpu_workers"; do
        cpu_slot=$(((worker_seed + worker * 17) % pressure_cpu_count + 1))
        worker_cpu="$(printf '%s\n' "$pressure_cpus" | cut -d , -f "$cpu_slot")"
        taskset -c "$worker_cpu" yes > /dev/null &
        printf '%s\tcpu\t-\n' "$!" >> "$pressure_directory/pids"
        worker=$((worker + 1))
    done

    worker=0
    while test "$worker" -lt "$io_workers"; do
        cpu_slot=$(((worker_seed + worker * 29 + 1) % pressure_cpu_count + 1))
        worker_cpu="$(printf '%s\n' "$pressure_cpus" | cut -d , -f "$cpu_slot")"
        completion="$pressure_directory/io-pressure-$worker.fdatasync-complete"
        (
            taskset -c "$worker_cpu" dd \
                if=/dev/zero \
                of="$pressure_directory/io-pressure-$worker" \
                bs=1048576 \
                count=1024 \
                conv=fdatasync \
                status=none
            : > "$completion"
        ) &
        printf '%s\tio\t%s\n' "$!" "$completion" >> "$pressure_directory/pids"
        worker=$((worker + 1))
    done
}

stop_host_pressure() {
    pressure_directory="$1"
    if test ! -f "$pressure_directory/pids"; then
        return
    fi
    while IFS="$(printf '\t')" read -r pid worker_kind completion; do
        if grep -q "^$pid"$'\tcompleted\t' "$pressure_directory/status"; then
            continue
        fi
        if ! kill "$pid" 2>/dev/null; then
            test "$worker_kind" = "io" && test -f "$completion" \
                || fail "$worker_kind pressure worker $pid exited before controlled stop"
        fi
    done < "$pressure_directory/pids"
    while IFS="$(printf '\t')" read -r pid worker_kind completion; do
        if grep -q "^$pid"$'\tcompleted\t' "$pressure_directory/status"; then
            continue
        fi
        set +e
        wait "$pid"
        status="$?"
        set -e
        if test "$status" -lt 128; then
            test "$worker_kind" = "io" && test "$status" -eq 0 && test -f "$completion" \
                || fail "$worker_kind pressure worker $pid stopped with unexpected status $status"
        fi
        printf '%s\tstopped\t%s\t%s\n' "$pid" "$worker_kind" "$status" \
            >> "$pressure_directory/status"
    done < "$pressure_directory/pids"
}

validate_host_pressure_started() {
    pressure_directory="$1"
    expected_workers="$2"
    actual_workers="$(wc -l < "$pressure_directory/pids")"
    test "$actual_workers" -eq "$expected_workers" \
        || fail "host pressure launched $actual_workers workers, expected $expected_workers"
    while IFS="$(printf '\t')" read -r pid worker_kind completion; do
        kill -0 "$pid" 2>/dev/null \
            || fail "$worker_kind pressure worker $pid exited before the workload started"
    done < "$pressure_directory/pids"
}

validate_host_pressure_overlap() {
    pressure_directory="$1"
    while IFS="$(printf '\t')" read -r pid worker_kind completion; do
        if test "$worker_kind" = "io" && test -f "$completion"; then
            set +e
            wait "$pid"
            status="$?"
            set -e
            test "$status" -eq 0 \
                || fail "I/O pressure worker $pid failed during the workload"
            printf '%s\tcompleted\t%s\t%s\n' "$pid" "$worker_kind" "$status" \
                >> "$pressure_directory/status"
            continue
        fi
        if kill -0 "$pid" 2>/dev/null; then
            printf '%s\tongoing\t%s\t0\n' "$pid" "$worker_kind" \
                >> "$pressure_directory/status"
            continue
        fi

        set +e
        wait "$pid"
        status="$?"
        set -e
        test "$status" -eq 0 \
            || fail "$worker_kind pressure worker $pid failed during the workload"
        if test "$worker_kind" = "io"; then
            test -f "$completion" \
                || fail "I/O pressure worker $pid exited without completing fdatasync"
        else
            fail "CPU pressure worker $pid exited before the workload completed"
        fi
        printf '%s\tcompleted\t%s\t%s\n' "$pid" "$worker_kind" "$status" \
            >> "$pressure_directory/status"
    done < "$pressure_directory/pids"
}

extract_unique_reduction_field() {
    reduction_log="$1"
    field_name="$2"
    values="$(
        grep '"kind":"independent_reduction"' "$reduction_log" \
            | grep -o "${field_name}=[^ ]*" \
            | sort -u
    )"
    test -n "$values" || fail "$reduction_log has no $field_name evidence"
    test "$(printf '%s\n' "$values" | wc -l)" -eq 1 \
        || fail "$reduction_log diverges in $field_name"
    printf '%s\n' "${values#"${field_name}"=}"
}

validate_reduction_profile() {
    reduction_log="$1"
    profile_name="$2"
    workers="$3"
    cores="$4"
    clock_skew_ms="$5"
    clock_coarsening_ms="$6"
    clock_backstep_every="$7"
    host_io_stall_ms="$8"
    deadline_backstep_applied="$9"
    run_zero_seed="${10}"
    run_one_seed="${11}"

    for run_index in 0 1; do
        if test "$run_index" -eq 0; then
            scheduling_seed="$run_zero_seed"
        else
            scheduling_seed="$run_one_seed"
        fi
        expected="run=$run_index profile=$profile_name workers=$workers cores=$cores"
        expected="$expected scheduling_seed=$scheduling_seed"
        expected_tail="clock_skew_ms=$clock_skew_ms clock_coarsening_ms=$clock_coarsening_ms"
        expected_tail="$expected_tail clock_backstep_every=$clock_backstep_every"
        expected_tail="$expected_tail deadline_backstep_applied=$deadline_backstep_applied"
        expected_tail="$expected_tail host_io_stall_ms=$host_io_stall_ms"
        matches="$(
            grep '"kind":"independent_reduction"' "$reduction_log" \
                | grep -F "$expected" \
                | grep -c "$expected_tail"
        )"
        test "$matches" -eq 1 \
            || fail "$reduction_log omitted exact $profile_name run $run_index dimensions"
    done
}

validate_verify_preemption() {
    reduction_log="$1"
    preemption_rows="$(
        grep '"node":"host","kind":"bounded_scheduler_preemption"' "$reduction_log" || true
    )"
    test -n "$preemption_rows" \
        || fail "$reduction_log omitted authenticated hostile-profile preemption evidence"
    test "$(printf '%s\n' "$preemption_rows" | wc -l)" -eq 6 \
        || fail "$reduction_log did not emit exactly six hostile-profile preemption rows"
    if printf '%s\n' "$preemption_rows" | grep -q 'profile=quiet-single-core'; then
        fail "$reduction_log emitted preemption evidence for the baseline profile"
    fi

    for profile_name in loaded-single-core reordered-two-core loaded-many-core; do
        for run_index in 0 1; do
            matches="$(
                printf '%s\n' "$preemption_rows" \
                    | grep -F "run=$run_index profile=$profile_name " \
                    | grep 'applied=true pending_quantum_certified=true' \
                    | grep -c 'perturbations=[1-9][0-9]* requested_stopped_ms=[1-9][0-9]*' \
                    || true
            )"
            test "$matches" -eq 1 \
                || fail "$reduction_log omitted exact preemption evidence for $profile_name run $run_index"
        done
    done
}

validate_host_attestation() {
    attestation="$1"
    host_id="$2"
    require_file "$attestation"
    test "$(field schema "$attestation")" = "crucible.e2e.physical-host-attestation.v1" \
        || fail "physical-host attestation schema is unsupported"
    test "$(field physical_host_id "$attestation")" = "$host_id" \
        || fail "physical-host attestation identity does not match"
    test "$(field physical_host_kind "$attestation")" = "physical" \
        || fail "physical-host attestation does not identify physical hardware"
    test "$(field operator_attested "$attestation")" = "true" \
        || fail "physical-host attestation is not operator-confirmed"
}

validate_host_sign_off() {
    sign_off="$1"
    expected_role="$2"
    host_id="$3"
    validate_operator_identity="$4"
    require_file "$sign_off"
    test "$(field schema "$sign_off")" = "crucible.e2e.host-sign-off.v1" \
        || fail "host sign-off schema is unsupported"
    test "$(field role "$sign_off")" = "$expected_role" \
        || fail "host sign-off has the wrong role"
    test "$(field physical_host_id "$sign_off")" = "$host_id" \
        || fail "host sign-off physical identity does not match"
    operator_identity="$(field operator_identity "$sign_off")"
    printf '%s\n' "$operator_identity" \
        | grep -Eq '^[0-9a-f]{64}$' \
        || fail "host sign-off operator identity must be a lowercase SHA-256 digest"
    test "$(field accepted "$sign_off")" = "true" \
        || fail "host operator did not accept the evidence"
    if test "$validate_operator_identity" = "print"; then
        printf '%s\n' "$operator_identity"
    fi
}

validate_release_sign_off() {
    sign_off="$1"
    producer_host="$2"
    reproducer_host="$3"
    require_file "$sign_off"
    test "$(field schema "$sign_off")" = "crucible.e2e.release-sign-off.v1" \
        || fail "release sign-off schema is unsupported"
    test "$(field role "$sign_off")" = "release_owner" \
        || fail "release sign-off has the wrong role"
    test "$(field producer_physical_host_id "$sign_off")" = "$producer_host" \
        || fail "release sign-off names the wrong producer host"
    test "$(field reproducer_physical_host_id "$sign_off")" = "$reproducer_host" \
        || fail "release sign-off names the wrong reproducer host"
    operator_identity="$(field operator_identity "$sign_off")"
    printf '%s\n' "$operator_identity" \
        | grep -Eq '^[0-9a-f]{64}$' \
        || fail "release-owner identity must be a lowercase SHA-256 digest"
    test "$(field accepted "$sign_off")" = "true" \
        || fail "release owner did not accept the evidence"
}

validate_command_journal() {
    journal="$1"
    require_file "$journal"
    test "$(sed -n '1p' "$journal")" \
        = "$(printf 'operation\tprofile\texit_status\tstructured_output')" \
        || fail "$journal has an unsupported command-journal schema"
    test "$(grep -c "^populate-store.*$(printf '\t')0$(printf '\t')profiles/.*/store-populate.log$" "$journal")" -eq 3 \
        || fail "$journal does not record three successful store materializations"
    test "$(grep -c "^verify.*$(printf '\t')0$(printf '\t')profiles/.*/verify.jsonl$" "$journal")" -eq 3 \
        || fail "$journal does not record three successful verify commands"
    test "$(grep -c "^replay.*$(printf '\t')0$(printf '\t')replay.jsonl$" "$journal")" -eq 1 \
        || fail "$journal does not record one successful replay command"
}

run_profile() {
    profile_name="$1"
    profile_cpus="$2"
    cpu_workers="$3"
    io_workers="$4"
    launch_jitter="$5"
    worker_seed="$6"
    host_output="$7"

    profile_output="$host_output/profiles/$profile_name"
    pressure_directory="$profile_output/pressure"
    profile_store="$profile_output/store"
    profile_artifacts="$profile_output/artifacts"
    mkdir -p "$pressure_directory" "$profile_store" "$profile_artifacts"

    cat > "$profile_output/profile.env" <<PROFILE
schema=crucible.e2e.native-host-profile.v1
profile=$profile_name
cpu_set=$profile_cpus
cpu_workers=$cpu_workers
io_workers=$io_workers
launch_jitter=$launch_jitter
worker_placement_seed=$worker_seed
PROFILE

    set +e
    "$CRUCIBLE/bin/crucible-e2e-determinism-scenario" \
        --populate-store "$profile_store" \
        > "$profile_output/store-populate.log"
    populate_status="$?"
    set -e
    printf 'populate-store\t%s\t%s\tprofiles/%s/store-populate.log\n' \
        "$profile_name" "$populate_status" "$profile_name" \
        >> "$host_output/command-journal.tsv"
    test "$populate_status" -eq 0 || fail "$profile_name store materialization failed"

    sleep "$launch_jitter"
    start_host_pressure \
        "$pressure_directory" \
        "$profile_cpus" \
        "$cpu_workers" \
        "$io_workers" \
        "$worker_seed"
    trap 'stop_host_pressure "$pressure_directory"' EXIT HUP INT TERM
    validate_host_pressure_started \
        "$pressure_directory" \
        "$((cpu_workers + io_workers))"

    set +e
    CRUCIBLE_ROOT_IMAGE="$CRUCIBLE_E2E_ROOT_IMAGE" \
    CRUCIBLE_KERNEL_CMDLINE="$CRUCIBLE_E2E_KERNEL_CMDLINE" \
    taskset -c "$profile_cpus" \
        "$CRUCIBLE/bin/crucible" \
            --backend qemu \
            --seed "$CRUCIBLE_E2E_SEED" \
            --store "$profile_store" \
            --artifact-dir "$profile_artifacts" \
            --format jsonl \
            verify "$CRUCIBLE_E2E_SCENARIO" \
            --runs 2 \
            --adversarial \
            --bisect \
            > "$profile_output/verify.jsonl"
    verify_status="$?"
    set -e

    validate_host_pressure_overlap "$pressure_directory"
    stop_host_pressure "$pressure_directory"
    trap - EXIT HUP INT TERM

    printf 'verify\t%s\t%s\tprofiles/%s/verify.jsonl\n' \
        "$profile_name" "$verify_status" "$profile_name" \
        >> "$host_output/command-journal.tsv"
    test "$verify_status" -eq 0 || fail "$profile_name verify command failed"

    verify_log="$profile_output/verify.jsonl"
    grep -q '"kind":"final_outcome".*subcommand=verify status=passed' "$verify_log" \
        || fail "$profile_name did not complete successfully"
    reductions="$(grep -c '"kind":"independent_reduction"' "$verify_log")"
    test "$reductions" -eq 8 \
        || fail "$profile_name produced $reductions reductions, expected exactly 8"
    validate_reduction_profile \
        "$verify_log" quiet-single-core 1 1 0 1 255 0 false \
        104372001767425 11400624225579269140
    validate_reduction_profile \
        "$verify_log" loaded-single-core 1 1 3 2 3 1 true \
        104372001767441 11400624225579269124
    validate_reduction_profile \
        "$verify_log" reordered-two-core 2 2 -2 3 2 2 true \
        104372001767458 11400624225579269175
    validate_reduction_profile \
        "$verify_log" loaded-many-core 4 4 5 4 2 3 true \
        104372001767492 11400624225579269201
    validate_verify_preemption "$verify_log"
    positive_samples="$(
        grep '"kind":"independent_reduction"' "$verify_log" \
            | grep -c 'samples=[1-9][0-9]*'
    )"
    test "$positive_samples" -eq "$reductions" \
        || fail "$profile_name omitted live fingerprint samples"
    applied_effects="$(
        grep '"kind":"independent_reduction"' "$verify_log" \
            | grep -c 'effect_applied=[1-9][0-9]*'
    )"
    test "$applied_effects" -eq "$reductions" \
        || fail "$profile_name omitted live fault effects"

    canonical_log="$(extract_unique_reduction_field "$verify_log" canonical_log)"
    fingerprint="$(extract_unique_reduction_field "$verify_log" fingerprint)"
    artifact="$(extract_unique_reduction_field "$verify_log" artifact)"
    printf '%s\n' "$artifact" \
        | grep -Eq '^crucible-hash:[0-9a-f]{64}$' \
        || fail "$profile_name emitted an unavailable or malformed artifact digest"
    artifact_records="$(
        grep '"kind":"independent_reduction"' "$verify_log" \
            | grep -c 'artifact=crucible-hash:[0-9a-f]\{64\}'
    )"
    test "$artifact_records" -eq "$reductions" \
        || fail "$profile_name omitted a reduction artifact digest"
    printf '%s\t%s\t%s\n' "$profile_name" "$canonical_log" "$fingerprint" \
        >> "$host_output/canonical-results.tsv"

    set -- "$profile_artifacts"/repro-passed-reduction-*.crucible
    test "$#" -eq "$reductions" \
        || fail "$profile_name did not retain one artifact for every reduction"
    : > "$profile_output/reduction-artifacts.sha256"
    baseline_artifact=
    for reduction_artifact in "$@"; do
        require_file "$reduction_artifact"
        printf '%s\t%s\n' \
            "${reduction_artifact##*/}" \
            "$(digest_file "$reduction_artifact")" \
            >> "$profile_output/reduction-artifacts.sha256"
        case "${reduction_artifact##*/}" in
            repro-passed-reduction-0-*.crucible)
                test -z "$baseline_artifact" \
                    || fail "$profile_name retained multiple reduction-0 artifacts"
                baseline_artifact="$reduction_artifact"
                ;;
        esac
    done
    test "$(cut -f 2 "$profile_output/reduction-artifacts.sha256" | sort -u | wc -l)" -eq 1 \
        || {
            cat "$profile_output/reduction-artifacts.sha256" >&2
            fail "$profile_name reduction artifact bytes diverged"
        }
    test -n "$baseline_artifact" \
        || fail "$profile_name omitted the reduction-0 artifact"
    cp "$baseline_artifact" "$profile_output/reproduction.crucible"
}

require_native_gate_inputs() {
    : "${CRUCIBLE:?CRUCIBLE package root is required}"
    : "${CRUCIBLE_QEMU:?CRUCIBLE_QEMU is required}"
    : "${CRUCIBLE_PLUGIN:?CRUCIBLE_PLUGIN is required}"
    : "${CRUCIBLE_KERNEL:?CRUCIBLE_KERNEL is required}"
    : "${CRUCIBLE_E2E_ROOT_IMAGE:?CRUCIBLE_E2E_ROOT_IMAGE is required}"
    : "${CRUCIBLE_E2E_KERNEL_CMDLINE:?CRUCIBLE_E2E_KERNEL_CMDLINE is required}"
    : "${CRUCIBLE_E2E_SCENARIO:?CRUCIBLE_E2E_SCENARIO is required}"
    : "${CRUCIBLE_E2E_SEED:=0xe2e}"

    for required in taskset sha256sum cut grep sed sort tr wc cmp dd yes sleep; do
        require_command "$required"
    done
    for required in \
        "$CRUCIBLE/bin/crucible" \
        "$CRUCIBLE/bin/crucible-e2e-determinism-scenario" \
        "$CRUCIBLE_QEMU" \
        "$CRUCIBLE_PLUGIN" \
        "$CRUCIBLE_KERNEL" \
        "$CRUCIBLE_E2E_ROOT_IMAGE" \
        "$CRUCIBLE_E2E_SCENARIO"
    do
        require_file "$required"
    done
}

run_gate() {
    test "$#" -eq 1 || fail "run-gate requires one output directory"
    gate_output="$1"
    test ! -e "$gate_output" || fail "gate output already exists: $gate_output"
    require_native_gate_inputs

    mkdir -p "$gate_output/profiles"
    : > "$gate_output/canonical-results.tsv"
    printf 'operation\tprofile\texit_status\tstructured_output\n' \
        > "$gate_output/command-journal.tsv"

    allowed_cpu_file="$gate_output/allowed-cpus"
    allowed_cpus > "$allowed_cpu_file"
    first_cpu="$(sed -n '1p' "$allowed_cpu_file")"
    second_cpu="$(sed -n '2p' "$allowed_cpu_file")"
    third_cpu="$(sed -n '3p' "$allowed_cpu_file")"
    fourth_cpu="$(sed -n '4p' "$allowed_cpu_file")"
    test -n "$fourth_cpu" || fail "native gate requires at least four allowed host CPUs"
    one_cpu="$first_cpu"
    two_cpus="$first_cpu,$second_cpu"
    four_cpus="$first_cpu,$second_cpu,$third_cpu,$fourth_cpu"

    run_profile quiet-single-core "$one_cpu" 0 0 0.001 65537 "$gate_output"
    run_profile randomized-worker-two-core "$two_cpus" 3 0 0.013 104729 "$gate_output"
    run_profile loaded-io-stall-four-core "$four_cpus" 7 2 0.029 130363 "$gate_output"

    cut -f 2- "$gate_output/canonical-results.tsv" \
        | sort -u > "$gate_output/canonical-identities.tsv"
    if test "$(wc -l < "$gate_output/canonical-identities.tsv")" -ne 1; then
        cat "$gate_output/canonical-results.tsv" >&2
        fail "canonical log or fingerprint changed across native machine profiles"
    fi

    artifact_digests="$gate_output/reproduction-artifacts.sha256"
    : > "$artifact_digests"
    for profile_name in \
        quiet-single-core \
        randomized-worker-two-core \
        loaded-io-stall-four-core
    do
        profile_artifact="$gate_output/profiles/$profile_name/reproduction.crucible"
        printf '%s\t%s\n' "$profile_name" "$(digest_file "$profile_artifact")" \
            >> "$artifact_digests"
    done
    if test "$(cut -f 2 "$artifact_digests" | sort -u | wc -l)" -ne 1; then
        cat "$artifact_digests" >&2
        fail "reproduction artifact changed across native machine profiles"
    fi

    source_artifact="$gate_output/profiles/quiet-single-core/reproduction.crucible"
    cp "$source_artifact" "$gate_output/reproduction.crucible"
    replay_store="$gate_output/replay-store"
    mkdir -p "$replay_store"
    test -z "$(ls -A "$replay_store")"

    replay_pressure="$gate_output/replay-pressure"
    mkdir -p "$replay_pressure"
    sleep 0.029
    start_host_pressure "$replay_pressure" "$four_cpus" 7 2 196613
    trap 'stop_host_pressure "$replay_pressure"' EXIT HUP INT TERM
    validate_host_pressure_started "$replay_pressure" 9

    set +e
    CRUCIBLE_ROOT_IMAGE="$CRUCIBLE_E2E_ROOT_IMAGE" \
    CRUCIBLE_KERNEL_CMDLINE="$CRUCIBLE_E2E_KERNEL_CMDLINE" \
        taskset -c "$four_cpus" \
        "$CRUCIBLE/bin/crucible" \
            --backend qemu \
            --store "$replay_store" \
            --artifact-dir "$gate_output" \
            --format jsonl \
            replay --bounded-scheduler-preemption "$source_artifact" \
            > "$gate_output/replay.jsonl"
    replay_status="$?"
    set -e
    validate_host_pressure_overlap "$replay_pressure"
    stop_host_pressure "$replay_pressure"
    trap - EXIT HUP INT TERM
    printf 'replay\tquiet-to-loaded-four-core\t%s\treplay.jsonl\n' "$replay_status" \
        >> "$gate_output/command-journal.tsv"
    test "$replay_status" -eq 0 || fail "different-profile artifact replay failed"
    grep -q '"kind":"replay_live_qemu".*validation=passed.*reproduced_status=passed.*reproduced_outcome=passed' \
        "$gate_output/replay.jsonl" \
        || fail "different-profile replay did not reproduce the live result"
    replay_preemptions="$(
        grep '"node":"host","kind":"bounded_scheduler_preemption"' \
            "$gate_output/replay.jsonl" || true
    )"
    test "$(printf '%s\n' "$replay_preemptions" | sed '/^$/d' | wc -l)" -eq 1 \
        || fail "different-profile replay did not emit exactly one bounded-preemption row"
    printf '%s\n' "$replay_preemptions" \
        | grep 'applied=true pending_quantum_certified=true' \
        | grep -q 'perturbations=[1-9][0-9]* requested_stopped_ms=[1-9][0-9]*' \
        || fail "different-profile replay omitted applied bounded host preemption"
    grep -q '"kind":"final_outcome".*subcommand=replay status=passed' \
        "$gate_output/replay.jsonl" \
        || fail "different-profile replay did not complete successfully"
    validate_command_journal "$gate_output/command-journal.tsv"

    qemu_root="${CRUCIBLE_QEMU%/bin/*}"
    qemu_identity="$qemu_root/share/aos/crucible/qemu-build-identity.env"
    require_file "$qemu_identity"
    cat > "$gate_output/manifest.env" <<MANIFEST
schema=crucible.e2e.native-gate-evidence.v1
crucible_package_identity=${CRUCIBLE##*/}
scenario_sha256=$(digest_file "$CRUCIBLE_E2E_SCENARIO")
qemu_binary_sha256=$(digest_file "$CRUCIBLE_QEMU")
qemu_identity_sha256=$(digest_file "$qemu_identity")
plugin_sha256=$(digest_file "$CRUCIBLE_PLUGIN")
kernel_sha256=$(digest_file "$CRUCIBLE_KERNEL")
root_image_sha256=$(digest_file "$CRUCIBLE_E2E_ROOT_IMAGE")
canonical_results_sha256=$(digest_file "$gate_output/canonical-results.tsv")
command_journal_sha256=$(digest_file "$gate_output/command-journal.tsv")
reproduction_artifact_sha256=$(digest_file "$gate_output/reproduction.crucible")
profile_matrix=quiet-single-core,randomized-worker-two-core,loaded-io-stall-four-core
producer_profile=quiet-single-core
reproducer_profile=loaded-io-stall-four-core
randomized_worker_scheduling=true
wall_clock_jitter=true
host_io_stall=true
varied_core_counts=1,2,4
live_qemu=true
tcg_only=true
MANIFEST

    cat > "$gate_output/result" <<RESULT
PASS
gate=gate:e2e-determinism
schema=crucible.e2e.native-gate-evidence.v1
native_qemu_execution=true
canonical_event_logs=byte-identical
final_fingerprints=byte-identical
artifact_replay=different-machine-profile-byte-identical
retained_diagnostics=profiles,pressure-status,canonical-results.tsv,canonical-identities.tsv,reproduction-artifacts.sha256,replay.jsonl,manifest.env
RESULT
}

run_host() {
    test "$#" -eq 1 || fail "run-host requires one output directory"
    host_output="$1"
    test ! -e "$host_output" || fail "host output already exists: $host_output"

    : "${CRUCIBLE:?CRUCIBLE package root is required}"
    : "${CRUCIBLE_QEMU:?CRUCIBLE_QEMU is required}"
    : "${CRUCIBLE_PLUGIN:?CRUCIBLE_PLUGIN is required}"
    : "${CRUCIBLE_KERNEL:?CRUCIBLE_KERNEL is required}"
    : "${CRUCIBLE_E2E_ROOT_IMAGE:?CRUCIBLE_E2E_ROOT_IMAGE is required}"
    : "${CRUCIBLE_E2E_KERNEL_CMDLINE:?CRUCIBLE_E2E_KERNEL_CMDLINE is required}"
    : "${CRUCIBLE_E2E_SCENARIO:?CRUCIBLE_E2E_SCENARIO is required}"
    : "${CRUCIBLE_E2E_PHYSICAL_HOST_ID:?CRUCIBLE_E2E_PHYSICAL_HOST_ID is required}"
    : "${CRUCIBLE_E2E_PHYSICAL_ATTESTATION:?CRUCIBLE_E2E_PHYSICAL_ATTESTATION is required}"
    : "${CRUCIBLE_E2E_HOST_SIGN_OFF:?CRUCIBLE_E2E_HOST_SIGN_OFF is required}"
    : "${CRUCIBLE_E2E_SEED:=0xe2e}"

    echo "$CRUCIBLE_E2E_PHYSICAL_HOST_ID" \
        | grep -Eq '^[0-9a-f]{64}$' \
        || fail "physical-host identity must be a lowercase SHA-256 digest"
    validate_host_attestation \
        "$CRUCIBLE_E2E_PHYSICAL_ATTESTATION" \
        "$CRUCIBLE_E2E_PHYSICAL_HOST_ID"

    for required in taskset sha256sum cut grep sed sort tr wc cmp dd yes sleep; do
        require_command "$required"
    done
    for required in \
        "$CRUCIBLE/bin/crucible" \
        "$CRUCIBLE/bin/crucible-e2e-determinism-scenario" \
        "$CRUCIBLE_QEMU" \
        "$CRUCIBLE_PLUGIN" \
        "$CRUCIBLE_KERNEL" \
        "$CRUCIBLE_E2E_ROOT_IMAGE" \
        "$CRUCIBLE_E2E_SCENARIO"
    do
        require_file "$required"
    done

    mkdir -p "$host_output/profiles"
    : > "$host_output/canonical-results.tsv"
    printf 'operation\tprofile\texit_status\tstructured_output\n' \
        > "$host_output/command-journal.tsv"
    cp "$CRUCIBLE_E2E_PHYSICAL_ATTESTATION" "$host_output/physical-host-attestation.env"

    allowed_cpu_file="$host_output/allowed-cpus"
    allowed_cpus > "$allowed_cpu_file"
    first_cpu="$(sed -n '1p' "$allowed_cpu_file")"
    second_cpu="$(sed -n '2p' "$allowed_cpu_file")"
    third_cpu="$(sed -n '3p' "$allowed_cpu_file")"
    fourth_cpu="$(sed -n '4p' "$allowed_cpu_file")"
    test -n "$fourth_cpu" || fail "native matrix requires at least four allowed host CPUs"
    one_cpu="$first_cpu"
    two_cpus="$first_cpu,$second_cpu"
    four_cpus="$first_cpu,$second_cpu,$third_cpu,$fourth_cpu"

    run_profile quiet-single-core "$one_cpu" 0 0 0.001 65537 "$host_output"
    run_profile randomized-worker-two-core "$two_cpus" 3 0 0.013 104729 "$host_output"
    run_profile loaded-io-stall-four-core "$four_cpus" 7 2 0.029 130363 "$host_output"

    first_artifact="$host_output/profiles/quiet-single-core/reproduction.crucible"
    second_artifact="$host_output/profiles/randomized-worker-two-core/reproduction.crucible"
    third_artifact="$host_output/profiles/loaded-io-stall-four-core/reproduction.crucible"
    cmp "$first_artifact" "$second_artifact" \
        || fail "reproduction artifact changed under randomized worker scheduling"
    cmp "$first_artifact" "$third_artifact" \
        || fail "reproduction artifact changed under I/O pressure and varied cores"
    cp "$first_artifact" "$host_output/reproduction.crucible"

    if test -n "${CRUCIBLE_E2E_SOURCE_ARTIFACT:-}"; then
        require_file "$CRUCIBLE_E2E_SOURCE_ARTIFACT"
        source_artifact="$CRUCIBLE_E2E_SOURCE_ARTIFACT"
        reproduction_role="cross-host-reproducer"
    else
        source_artifact="$host_output/reproduction.crucible"
        reproduction_role="producer-and-local-reproducer"
    fi
    if test "$reproduction_role" = "cross-host-reproducer"; then
        host_sign_off_role="reproducer_host_operator"
    else
        host_sign_off_role="producer_host_operator"
    fi
    validate_host_sign_off \
        "$CRUCIBLE_E2E_HOST_SIGN_OFF" \
        "$host_sign_off_role" \
        "$CRUCIBLE_E2E_PHYSICAL_HOST_ID" \
        validate
    cp "$CRUCIBLE_E2E_HOST_SIGN_OFF" "$host_output/sign-off.env"

    replay_store="$host_output/replay-store"
    mkdir -p "$replay_store"
    set +e
    CRUCIBLE_ROOT_IMAGE="$CRUCIBLE_E2E_ROOT_IMAGE" \
    CRUCIBLE_KERNEL_CMDLINE="$CRUCIBLE_E2E_KERNEL_CMDLINE" \
        taskset -c "$four_cpus" \
        "$CRUCIBLE/bin/crucible" \
            --backend qemu \
            --store "$replay_store" \
            --artifact-dir "$host_output" \
            --format jsonl \
            replay --bounded-scheduler-preemption "$source_artifact" \
            > "$host_output/replay.jsonl"
    replay_status="$?"
    set -e
    printf 'replay\t%s\t%s\treplay.jsonl\n' \
        "$reproduction_role" "$replay_status" \
        >> "$host_output/command-journal.tsv"
    test "$replay_status" -eq 0 || fail "artifact replay command failed"
    grep -q '"kind":"replay_live_qemu".*validation=passed.*reproduced_status=passed.*reproduced_outcome=passed' \
        "$host_output/replay.jsonl" \
        || fail "artifact replay did not reproduce the live result"
    grep -q '"kind":"final_outcome".*subcommand=replay status=passed' \
        "$host_output/replay.jsonl" \
        || fail "artifact replay did not complete successfully"

    qemu_root="${CRUCIBLE_QEMU%/bin/*}"
    qemu_identity="$qemu_root/share/aos/crucible/qemu-build-identity.env"
    require_file "$qemu_identity"
    cat > "$host_output/manifest.env" <<MANIFEST
schema=crucible.e2e.native-host-evidence.v1
physical_host_id=$CRUCIBLE_E2E_PHYSICAL_HOST_ID
physical_host_attestation_sha256=$(digest_file "$host_output/physical-host-attestation.env")
reproduction_role=$reproduction_role
host_sign_off_sha256=$(digest_file "$host_output/sign-off.env")
crucible_package_identity=${CRUCIBLE##*/}
scenario_sha256=$(digest_file "$CRUCIBLE_E2E_SCENARIO")
qemu_binary_sha256=$(digest_file "$CRUCIBLE_QEMU")
qemu_identity_sha256=$(digest_file "$qemu_identity")
plugin_sha256=$(digest_file "$CRUCIBLE_PLUGIN")
kernel_sha256=$(digest_file "$CRUCIBLE_KERNEL")
root_image_sha256=$(digest_file "$CRUCIBLE_E2E_ROOT_IMAGE")
canonical_results_sha256=$(digest_file "$host_output/canonical-results.tsv")
command_journal_sha256=$(digest_file "$host_output/command-journal.tsv")
produced_artifact_sha256=$(digest_file "$host_output/reproduction.crucible")
replayed_artifact_sha256=$(digest_file "$source_artifact")
profile_matrix=quiet-single-core,randomized-worker-two-core,loaded-io-stall-four-core
randomized_worker_scheduling=true
wall_clock_jitter=true
host_io_stall=true
varied_core_counts=1,2,4
live_qemu=true
tcg_only=true
MANIFEST
}

verify_cross_host() {
    test "$#" -eq 4 \
        || fail "verify-cross-host requires producer, reproducer, release sign-off, and output"
    producer="$1"
    reproducer="$2"
    release_sign_off="$3"
    comparison="$4"
    test ! -e "$comparison" || fail "comparison output already exists: $comparison"
    require_directory "$producer"
    require_directory "$reproducer"
    require_file "$producer/manifest.env"
    require_file "$reproducer/manifest.env"
    require_file "$producer/physical-host-attestation.env"
    require_file "$reproducer/physical-host-attestation.env"
    require_file "$producer/sign-off.env"
    require_file "$reproducer/sign-off.env"
    require_file "$producer/command-journal.tsv"
    require_file "$reproducer/command-journal.tsv"
    require_file "$producer/canonical-results.tsv"
    require_file "$reproducer/canonical-results.tsv"
    require_file "$producer/reproduction.crucible"
    require_file "$reproducer/reproduction.crucible"
    require_file "$producer/replay.jsonl"
    require_file "$reproducer/replay.jsonl"
    for profile in quiet-single-core randomized-worker-two-core loaded-io-stall-four-core; do
        require_file "$producer/profiles/$profile/store-populate.log"
        require_file "$reproducer/profiles/$profile/store-populate.log"
        require_file "$producer/profiles/$profile/verify.jsonl"
        require_file "$reproducer/profiles/$profile/verify.jsonl"
    done

    test "$(field schema "$producer/manifest.env")" = "crucible.e2e.native-host-evidence.v1" \
        || fail "producer evidence schema is unsupported"
    test "$(field schema "$reproducer/manifest.env")" = "crucible.e2e.native-host-evidence.v1" \
        || fail "reproducer evidence schema is unsupported"
    producer_host="$(field physical_host_id "$producer/manifest.env")"
    reproducer_host="$(field physical_host_id "$reproducer/manifest.env")"
    test "$producer_host" != "$reproducer_host" \
        || fail "cross-host evidence uses one physical-host identity"
    validate_host_attestation "$producer/physical-host-attestation.env" "$producer_host"
    validate_host_attestation "$reproducer/physical-host-attestation.env" "$reproducer_host"
    producer_operator="$(
        validate_host_sign_off \
            "$producer/sign-off.env" producer_host_operator "$producer_host" print
    )"
    reproducer_operator="$(
        validate_host_sign_off \
            "$reproducer/sign-off.env" reproducer_host_operator "$reproducer_host" print
    )"
    validate_release_sign_off "$release_sign_off" "$producer_host" "$reproducer_host"
    release_operator="$(field operator_identity "$release_sign_off")"
    test "$producer_operator" != "$reproducer_operator" \
        || fail "producer and reproducer sign-offs use one operator identity"
    test "$producer_operator" != "$release_operator" \
        || fail "producer and release sign-offs use one operator identity"
    test "$reproducer_operator" != "$release_operator" \
        || fail "reproducer and release sign-offs use one operator identity"
    test "$(field canonical_results_sha256 "$release_sign_off")" \
        = "$(digest_file "$producer/canonical-results.tsv")" \
        || fail "release sign-off names the wrong canonical result"
    test "$(field reproduction_artifact_sha256 "$release_sign_off")" \
        = "$(digest_file "$producer/reproduction.crucible")" \
        || fail "release sign-off names the wrong reproduction artifact"
    test "$(field producer_manifest_sha256 "$release_sign_off")" \
        = "$(digest_file "$producer/manifest.env")" \
        || fail "release sign-off names the wrong producer manifest"
    test "$(field reproducer_manifest_sha256 "$release_sign_off")" \
        = "$(digest_file "$reproducer/manifest.env")" \
        || fail "release sign-off names the wrong reproducer manifest"
    test "$(digest_file "$producer/sign-off.env")" \
        = "$(field host_sign_off_sha256 "$producer/manifest.env")" \
        || fail "producer host sign-off digest does not match"
    test "$(digest_file "$reproducer/sign-off.env")" \
        = "$(field host_sign_off_sha256 "$reproducer/manifest.env")" \
        || fail "reproducer host sign-off digest does not match"
    validate_command_journal "$producer/command-journal.tsv"
    validate_command_journal "$reproducer/command-journal.tsv"
    test "$(digest_file "$producer/command-journal.tsv")" \
        = "$(field command_journal_sha256 "$producer/manifest.env")" \
        || fail "producer command-journal digest does not match"
    test "$(digest_file "$reproducer/command-journal.tsv")" \
        = "$(field command_journal_sha256 "$reproducer/manifest.env")" \
        || fail "reproducer command-journal digest does not match"
    test "$(digest_file "$producer/physical-host-attestation.env")" \
        = "$(field physical_host_attestation_sha256 "$producer/manifest.env")" \
        || fail "producer physical-host attestation digest does not match"
    test "$(digest_file "$reproducer/physical-host-attestation.env")" \
        = "$(field physical_host_attestation_sha256 "$reproducer/manifest.env")" \
        || fail "reproducer physical-host attestation digest does not match"
    test "$(field physical_host_attestation_sha256 "$producer/manifest.env")" \
        != "$(field physical_host_attestation_sha256 "$reproducer/manifest.env")" \
        || fail "cross-host evidence repeats one physical-host attestation"
    test "$(field reproduction_role "$reproducer/manifest.env")" = "cross-host-reproducer" \
        || fail "second host did not replay the first host artifact"
    test "$(digest_file "$producer/canonical-results.tsv")" \
        = "$(field canonical_results_sha256 "$producer/manifest.env")" \
        || fail "producer canonical-results digest does not match"
    test "$(digest_file "$reproducer/canonical-results.tsv")" \
        = "$(field canonical_results_sha256 "$reproducer/manifest.env")" \
        || fail "reproducer canonical-results digest does not match"
    test "$(digest_file "$producer/reproduction.crucible")" \
        = "$(field produced_artifact_sha256 "$producer/manifest.env")" \
        || fail "producer reproduction-artifact digest does not match"
    test "$(digest_file "$reproducer/reproduction.crucible")" \
        = "$(field produced_artifact_sha256 "$reproducer/manifest.env")" \
        || fail "reproducer reproduction-artifact digest does not match"

    for required_value in \
        randomized_worker_scheduling \
        wall_clock_jitter \
        host_io_stall \
        live_qemu \
        tcg_only
    do
        test "$(field "$required_value" "$producer/manifest.env")" = "true" \
            || fail "producer did not exercise $required_value"
        test "$(field "$required_value" "$reproducer/manifest.env")" = "true" \
            || fail "reproducer did not exercise $required_value"
    done
    test "$(field varied_core_counts "$producer/manifest.env")" = "1,2,4" \
        || fail "producer did not exercise the required core-count matrix"
    test "$(field varied_core_counts "$reproducer/manifest.env")" = "1,2,4" \
        || fail "reproducer did not exercise the required core-count matrix"

    for identity in \
        crucible_package_identity \
        scenario_sha256 \
        qemu_binary_sha256 \
        qemu_identity_sha256 \
        plugin_sha256 \
        kernel_sha256 \
        root_image_sha256 \
        produced_artifact_sha256
    do
        test "$(field "$identity" "$producer/manifest.env")" \
            = "$(field "$identity" "$reproducer/manifest.env")" \
            || fail "cross-host evidence differs in $identity"
    done
    test "$(field produced_artifact_sha256 "$producer/manifest.env")" \
        = "$(field replayed_artifact_sha256 "$reproducer/manifest.env")" \
        || fail "second host replayed a different artifact"
    cmp "$producer/canonical-results.tsv" "$reproducer/canonical-results.tsv" \
        || fail "canonical live results differ across physical hosts"

    mkdir -p "$comparison"
    cp "$producer/canonical-results.tsv" "$comparison/canonical-results.tsv"
    cp "$release_sign_off" "$comparison/release-sign-off.env"
    printf 'operation\tprofile\texit_status\tstructured_output\n' \
        > "$comparison/command-journal.tsv"
    printf 'verify-cross-host\tproducer-to-reproducer\t0\tresult\n' \
        >> "$comparison/command-journal.tsv"
    cat > "$comparison/result" <<RESULT
PASS
gate=gate:e2e-determinism
schema=crucible.e2e.cross-host-evidence.v1
producer_physical_host_id=$producer_host
reproducer_physical_host_id=$reproducer_host
canonical_results_sha256=$(digest_file "$comparison/canonical-results.tsv")
reproduction_artifact_sha256=$(field produced_artifact_sha256 "$producer/manifest.env")
physical_cross_host_reproduction=true
randomized_worker_scheduling=true
wall_clock_jitter=true
host_io_stall=true
varied_core_counts=1,2,4
live_qemu=true
tcg_only=true
RESULT
}

case "${1:-}" in
    run-gate)
        shift
        run_gate "$@"
        ;;
    run-host)
        shift
        run_host "$@"
        ;;
    verify-cross-host)
        shift
        verify_cross_host "$@"
        ;;
    *)
        fail "usage: runner {run-gate OUTPUT | run-host OUTPUT | verify-cross-host PRODUCER REPRODUCER RELEASE_SIGN_OFF OUTPUT}"
        ;;
esac
