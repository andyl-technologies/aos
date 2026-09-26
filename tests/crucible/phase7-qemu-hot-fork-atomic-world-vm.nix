# Exercises the daemon's complete production world-fork transaction with real QEMU children.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.gates.worldForkAtomicity",
  taskIds ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  guest = import ./_nginx-curl-http-200-guest.nix {inherit pkgs;};
  scenario = pkgs.writeTextFile {
    name = "crucible-e2e-determinism-scenario";
    destination = "/scenario.toml";
    text = builtins.readFile ./fixtures/e2e-determinism.scenario.toml;
  };
  flight = pkgs.mkDerivation {
    pname = "crucible-qemu-hot-fork-atomic-world-flight";
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
          cp "$binary" "$out/bin/crucible-daemon-atomic-world-flight"
        '';
      }
    ];
  };
  cgroupRoot =
    if campaignComposition == null
    then "/sys/fs/cgroup/crucible"
    else "/sys/fs/cgroup/crucible-phase9-hot-fork-atomic-world";
  resultPath =
    if campaignComposition == null
    then "/tmp/atomic-world-result"
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
      source target \
      fork-failure-source fork-failure-target \
      adoption-failure-source adoption-failure-target \
      cleanup-retry-source cleanup-retry-target \
      publication-failure-source publication-failure-target \
      isolation-omission-source isolation-omission-target \
      isolation-alias-source isolation-alias-target; do
      mkdir "${cgroupRoot}/$lane"
      echo '+cpu +memory +pids' \
        > "${cgroupRoot}/$lane/cgroup.subtree_control"
    done

    truncate -s 8G /tmp/attempts.img
    ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project \
      -E quotatype=prjquota /tmp/attempts.img
    mkdir /tmp/attempts
    ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts
    mkdir -m 700 /tmp/attempts/run /tmp/run-state /tmp/artifacts
    for lane in \
      source target \
      fork-failure-source fork-failure-target \
      adoption-failure-source adoption-failure-target \
      cleanup-retry-source cleanup-retry-target \
      publication-failure-source publication-failure-target \
      isolation-omission-source isolation-omission-target \
      isolation-alias-source isolation-alias-target; do
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
    export CRUCIBLE_ATOMIC_WORLD_UID=65534
    export CRUCIBLE_ATOMIC_WORLD_GID=65534

    run_case() {
      name="$1"
      log="/tmp/$name.log"
      if listing=$(${flight}/bin/crucible-daemon-atomic-world-flight \
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
        ${flight}/bin/crucible-daemon-atomic-world-flight \
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

    atomic_case=qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically
    run_case "$atomic_case"
    require_case_marker "$atomic_case" \
      'native_resource_isolation=memfd,eventfd,writable-qcow2-root,serial'
    require_case_marker "$atomic_case" 'native_temp_files_isolated=true'
    require_case_marker "$atomic_case" \
      'ambient_outputs_rejected=pidfile,export-socket'
    require_case_marker "$atomic_case" \
      'native_running_sibling_mutation_isolated=true'
    require_case_marker "$atomic_case" \
      'native_isolation_scopes=network-device,native-9p-device,writable-qcow2-root,serial,pidfile,export-socket,temp-files,native-running-sibling-mutation'
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_exposes_no_world_when_second_real_fork_fails
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_exposes_no_world_when_second_real_adoption_fails
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_keeps_source_private_until_target_cleanup_retries
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_keeps_source_private_across_repository_publication_retry
    negative_case=qemu_hot_fork_world_factory::tests::native_acceptance::isolation_negative::production_factory_rejects_the_complete_isolation_negative_matrix_before_readiness
    omission_case=qemu_hot_fork_world_factory::tests::native_acceptance::isolation_native_negative::production_factory_rejects_missing_child_file_with_live_qemu_source
    alias_case=qemu_hot_fork_world_factory::tests::native_acceptance::isolation_native_negative::production_factory_rejects_aliased_child_files_with_live_qemu_source
    run_case "$negative_case"
    run_case "$omission_case"
    run_case "$alias_case"
    for marker in \
      'native_real_resource_omission=child-vmstate-destination' \
      'native_real_resource_omission_nodes=2' \
      'native_real_resource_omission_rejected_before=child-readiness,world-publication' \
      'native_real_resource_omission_source_unchanged=true'; do
      require_case_marker "$omission_case" "$marker"
    done
    for marker in \
      'native_real_resource_alias=child-vmstate-destination' \
      'native_real_resource_alias_nodes=2' \
      'native_real_resource_alias_rejected_before=child-readiness,world-publication' \
      'native_real_resource_alias_source_unchanged=true'; do
      require_case_marker "$alias_case" "$marker"
    done
    for marker in \
      'native_negative_isolation_matrix=private-ring-omitted,qmp-control-aliased,console-diagnostics-aliased,writable-disk-backing-aliased,network-omitted,ninep-aliased,host-continuation-identity-aliased' \
      'native_negative_isolation_rejected_before=child-readiness,resume,world-publication' \
      'native_negative_isolation_source_unchanged=true'; do
      require_case_marker "$negative_case" "$marker"
    done

    final_audit_case=qemu_hot_fork_world_factory::tests::native_acceptance::final_audit::production_hot_fork_resource_roots_are_clean_after_packaged_flights
    run_case "$final_audit_case"
    for marker in \
      'final_attempt_processes=0' \
      'final_qemu_processes=0' \
      'final_attempt_descriptors=0' \
      'final_attempt_process_memory_bytes=0' \
      'final_attempt_storage_entries=0' \
      'final_store_verified_objects=2'; do
      require_case_marker "$final_audit_case" "$marker"
    done

    printf '%s\n' \
      'PASS' \
      'gate=gate:world-fork-atomicity' \
      'factory=production-whole-world' \
      'source=two-running-one-permanently-failed' \
      'io=block,ninep' \
      'native_resource_isolation=memfd,eventfd,writable-qcow2-root,serial' \
      'native_temp_files_isolated=true' \
      'ambient_outputs_rejected=pidfile,export-socket' \
      'native_running_sibling_mutation_isolated=true' \
      'native_isolation_scopes=network-device,native-9p-device,writable-qcow2-root,serial,pidfile,export-socket,temp-files,native-running-sibling-mutation' \
      'native_negative_isolation_matrix=private-ring-omitted,qmp-control-aliased,console-diagnostics-aliased,writable-disk-backing-aliased,network-omitted,ninep-aliased,host-continuation-identity-aliased' \
      'native_negative_isolation_rejected_before=child-readiness,resume,world-publication' \
      'native_negative_isolation_source_unchanged=true' \
      'native_real_resource_omission=child-vmstate-destination' \
      'native_real_resource_omission_nodes=2' \
      'native_real_resource_omission_rejected_before=child-readiness,world-publication' \
      'native_real_resource_omission_source_unchanged=true' \
      'native_real_resource_alias=child-vmstate-destination' \
      'native_real_resource_alias_nodes=2' \
      'native_real_resource_alias_rejected_before=child-readiness,world-publication' \
      'native_real_resource_alias_source_unchanged=true' \
      'failures=fork,adoption,target-cleanup,repository-publication' \
      'final_resource_audit=process,descriptors,memory,attempt-storage,content-store' \
      'check=${attrPath}' \
      'tasks=${builtins.concatStringsSep "," taskIds}' \
      > ${resultPath}
    cat ${resultPath}
    ${pkgs.util-linux}/bin/umount /tmp/attempts
    trap - EXIT HUP INT TERM
  '';
  authoritativeGate = testing.mkVMTest {
    name = "crucible-qemu-hot-fork-atomic-world";
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
      gateName = "gate:world-fork-atomicity";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "hot-fork-atomic-world";
      runtimeClosures = [
        flight
        guest
        scenario
        pkgs.crucible
        pkgs.qemu-crucible
        pkgs.crucible-qemu-plugin
        pkgs.linux
      ];
      # Five 30-minute cases plus a bounded 30-minute boot, setup, and
      # evidence-retention margin.
      timeout = 10800;
      memoryMiB = 8192;
      varSizeMiB = 16384;
    }
  else authoritativeGate
