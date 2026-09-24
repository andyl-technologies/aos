# Compares production hot forks with thin replay and exact restore using real QEMU worlds.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.qemuHotForkEquivalenceVm",
  taskIds ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  guest = import ./_nginx-curl-http-200-guest.nix {
    inherit pkgs;
    hotForkEquivalence = true;
  };
  scenario = pkgs.writeTextFile {
    name = "crucible-e2e-determinism-scenario";
    destination = "/scenario.toml";
    text = builtins.readFile ./fixtures/e2e-determinism.scenario.toml;
  };
  flight = pkgs.mkDerivation {
    pname = "crucible-qemu-hot-fork-equivalence-flight";
    version = "0";
    src = source;
    buildDeps = [
      pkgs.coreutils
      pkgs.jq
      pkgs.openssl
      pkgs.pkg-config
      pkgs.protobuf
      pkgs.rust
      pkgs.sed
    ];
    runtimeDeps = [pkgs.openssl];
    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "build";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          cargo test --frozen --offline --release --no-run \
            --message-format=json-render-diagnostics \
            --manifest-path crates/Cargo.toml \
            --target-dir "$TMPDIR/target" \
            -p crucible-daemon --lib > "$TMPDIR/messages.jsonl"
          binary=$(jq -r \
            'select(.reason == "compiler-artifact" and .target.name == "crucible_daemon" and .profile.test == true and .executable != null) | .executable' \
            "$TMPDIR/messages.jsonl")
          test -f "$binary"
          mkdir -p "$out/bin"
          cp "$binary" "$out/bin/crucible-daemon-hot-fork-equivalence-flight"
        '';
      }
    ];
  };
  cgroupRoot =
    if campaignComposition == null
    then "/sys/fs/cgroup/crucible"
    else "/sys/fs/cgroup/crucible-phase9-hot-fork-equivalence";
  resultPath =
    if campaignComposition == null
    then "/tmp/hot-fork-equivalence-result"
    else "$out/result";
  runtimeInputs = [
    pkgs.coreutils
    pkgs.e2fsprogs
    pkgs.grep
    pkgs.util-linux
  ];
  runtimeScript = ''
    set -eu
    cleanup_attempt_mount() {
      ${pkgs.util-linux}/bin/umount /tmp/attempts > /dev/null 2>&1 || true
    }
    trap cleanup_attempt_mount EXIT HUP INT TERM

    for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL; do
      ${pkgs.grep}/bin/grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
    done
    mkdir -p /sys/fs/cgroup
    ${lib.optionalString (campaignComposition == null) "${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup"}
    echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
    mkdir ${cgroupRoot}
    echo '+cpu +memory +pids' > ${cgroupRoot}/cgroup.subtree_control
    for lane in \
      equivalence-checkpoint-source \
      equivalence-replay-genesis \
      equivalence-replay-oracle-reference equivalence-replay-oracle-template \
      equivalence-thin-reference \
      equivalence-execution-source equivalence-execution-target \
      equivalence-exact-reference \
      equivalence-exact-template-source equivalence-exact-template-target \
      single-checkpoint-source single-thin-reference \
      single-replay-genesis \
      single-replay-oracle-reference single-replay-oracle-template \
      single-execution-source single-execution-target \
      single-exact-reference \
      single-exact-template-source single-exact-template-target \
      preparation-failure-source; do
      mkdir "${cgroupRoot}/$lane"
      echo '+cpu +memory +pids' \
        > "${cgroupRoot}/$lane/cgroup.subtree_control"
    done

    truncate -s 8G /tmp/attempts.img
    ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project \
      -E quotatype=prjquota /tmp/attempts.img
    mkdir /tmp/attempts
    ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts
    mkdir -m 700 /tmp/attempts/run /tmp/run-state /tmp/artifacts /tmp/checkpoints
    for lane in \
      equivalence-checkpoint-source \
      equivalence-replay-genesis \
      equivalence-replay-oracle-reference equivalence-replay-oracle-template \
      equivalence-thin-reference \
      equivalence-execution-source equivalence-execution-target \
      equivalence-exact-reference \
      equivalence-exact-template-source equivalence-exact-template-target \
      single-checkpoint-source single-thin-reference \
      single-replay-genesis \
      single-replay-oracle-reference single-replay-oracle-template \
      single-execution-source single-execution-target \
      single-exact-reference \
      single-exact-template-source single-exact-template-target \
      preparation-failure-source; do
      mkdir -m 700 "/tmp/attempts/run/$lane"
    done
    ${pkgs.crucible}/bin/crucible-e2e-determinism-scenario \
      --populate-store /tmp/artifacts

    for kernel in ${pkgs.linux}/boot/vmlinuz-*; do
      export CRUCIBLE_ATOMIC_WORLD_KERNEL="$kernel"
    done
    export CRUCIBLE_ATOMIC_WORLD_QEMU=${pkgs.qemu-crucible}/bin/qemu-system-x86_64
    export CRUCIBLE_ATOMIC_WORLD_PLUGIN=${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
    export CRUCIBLE_ATOMIC_WORLD_ROOT=${guest}/root.ext4
    export CRUCIBLE_ATOMIC_WORLD_SCENARIO=${scenario}/scenario.toml
    export CRUCIBLE_ATOMIC_WORLD_ARTIFACTS=/tmp/artifacts
    export CRUCIBLE_ATOMIC_WORLD_CGROUP=${cgroupRoot}
    export CRUCIBLE_ATOMIC_WORLD_STORAGE=/tmp/attempts/run
    export CRUCIBLE_ATOMIC_WORLD_RUN_STATE=/tmp/run-state
    export CRUCIBLE_ATOMIC_WORLD_CHECKPOINTS=/tmp/checkpoints
    export CRUCIBLE_ATOMIC_WORLD_UID=65534
    export CRUCIBLE_ATOMIC_WORLD_GID=65534

    run_case() {
      name="$1"
      log="/tmp/$name.log"
      if listing=$(${flight}/bin/crucible-daemon-hot-fork-equivalence-flight \
        --ignored --exact "$name" --list 2>&1); then
        :
      else
        printf '%s\n' "$listing" >&2
        exit 1
      fi
      count=$(printf '%s\n' "$listing" \
        | ${pkgs.grep}/bin/grep -Fxc "$name: test" || true)
      if [ "$count" -ne 1 ]; then
        printf '%s\n' "$listing" >&2
        echo "expected exactly one library test named $name, found $count" >&2
        exit 1
      fi

      if ! ${pkgs.coreutils}/bin/timeout -k 30 1800 \
        ${flight}/bin/crucible-daemon-hot-fork-equivalence-flight \
        --ignored --exact "$name" --nocapture > "$log" 2>&1; then
        cat "$log"
        ${pkgs.util-linux}/bin/dmesg | tail -n 60
        exit 1
      fi
      cat "$log"
      summary_count=$(${pkgs.grep}/bin/grep -Ec \
        '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+(\.[0-9]+)?s$' \
        "$log" || true)
      [ "$summary_count" -eq 1 ]
    }

    # Libtest attaches a test's first printed marker to its status prefix.
    require_case_marker() {
      case_name="$1"
      marker="$2"
      case_log="/tmp/$case_name.log"
      standalone_count=$(${pkgs.grep}/bin/grep -Fxc "$marker" "$case_log" || true)
      prefixed_count=$(${pkgs.grep}/bin/grep -Fxc \
        "test $case_name ... $marker" "$case_log" || true)
      if [ "$((standalone_count + prefixed_count))" -ne 1 ]; then
        echo "expected one exact marker for $case_name: $marker" >&2
        return 1
      fi
    }

    equivalence_case=qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_hot_fork_matches_thin_and_exact_from_execution_and_exact_templates
    run_case "$equivalence_case"
    for evidence in \
      'application_http_status=200' \
      'inactive_world_reactivation=true' \
      'shared_cause=network,block,node' \
      'ninep_fault_injection=true' \
      'locked_fault_replay_evidence_match=true' \
      'pre_event_queue_and_volatile_cache=true' \
      'pre_event_exact_restore=true' \
      'shared_effect_state_transition=true' \
      'child_boundary_matches_capture=true' \
      'child_suffix_matches_exact_restore=true' \
      'child_suffix_matches_genesis_replay=true' \
      'concurrent_live_children=2'; do
      require_case_marker "$equivalence_case" "$evidence"
    done
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::equivalence::production_single_node_hot_fork_matches_thin_and_exact
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_source_preparation_failure_exposes_no_template

    printf '%s\n' \
      'PASS' \
      'gate=gate:hot-fork-equivalence' \
      'factory=production-whole-world' \
      'template_origins=execution,exact-restore' \
      'reference_tiers=thin-replay,exact-checkpoint' \
      'child_boundary_matches_capture=true' \
      'child_suffix_matches_exact_restore=true' \
      'child_suffix_matches_genesis_replay=true' \
      'concurrent_live_children=2' \
      'application_http_status=200' \
      'inactive_world_reactivation=true' \
      'shared_cause=network,block,node' \
      'ninep_fault_injection=true' \
      'locked_fault_replay_evidence_match=true' \
      'pre_event_queue_and_volatile_cache=true' \
      'pre_event_exact_restore=true' \
      'shared_effect_state_transition=true' \
      'topologies=single-node,multi-node' \
      'state=network,block,ninep,guest-choice,measurement,signal,permanent-failure' \
      'failures=source-preparation' \
      'check=${attrPath}' \
      'tasks=${builtins.concatStringsSep "," taskIds}' \
      > ${resultPath}
    cat ${resultPath}
    ${pkgs.util-linux}/bin/umount /tmp/attempts
    trap - EXIT HUP INT TERM
  '';
  authoritativeGate = testing.mkVMTest {
    name = "crucible-qemu-hot-fork-equivalence";
    memory = 8192;
    rootfsDeps = [
      flight
      guest
      scenario
      pkgs.crucible
      pkgs.qemu-crucible
      pkgs.crucible-qemu-plugin
      pkgs.linux
      pkgs.e2fsprogs
      pkgs.coreutils
      pkgs.util-linux
      pkgs.grep
    ];
    testScript = runtimeScript;
  };
in
  if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing runtimeInputs runtimeScript;
      inherit (campaignComposition) mode system;
      gateName = "gate:hot-fork-equivalence";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "hot-fork-equivalence";
      runtimeClosures = [
        flight
        guest
        scenario
        pkgs.crucible
        pkgs.qemu-crucible
        pkgs.crucible-qemu-plugin
        pkgs.linux
      ];
      # Three 30-minute cases plus a bounded 30-minute boot, setup, and
      # evidence-retention margin.
      timeout = 7200;
      memoryMiB = 8192;
      varSizeMiB = 16384;
    }
  else authoritativeGate
