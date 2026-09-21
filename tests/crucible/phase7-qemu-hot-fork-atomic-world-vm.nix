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
  scenario = ./fixtures/e2e-determinism.scenario.toml;
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
      publication-failure-source publication-failure-target; do
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
      publication-failure-source publication-failure-target; do
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
    export CRUCIBLE_ATOMIC_WORLD_SCENARIO=${scenario}
    export CRUCIBLE_ATOMIC_WORLD_ARTIFACTS=/tmp/artifacts
    export CRUCIBLE_ATOMIC_WORLD_CGROUP=${cgroupRoot}
    export CRUCIBLE_ATOMIC_WORLD_STORAGE=/tmp/attempts/run
    export CRUCIBLE_ATOMIC_WORLD_RUN_STATE=/tmp/run-state
    export CRUCIBLE_ATOMIC_WORLD_UID=65534
    export CRUCIBLE_ATOMIC_WORLD_GID=65534

    run_case() {
      name="$1"
      log="/tmp/$name.log"
      if ! ${pkgs.coreutils}/bin/timeout -k 30 1800 \
        ${flight}/bin/crucible-daemon-atomic-world-flight \
        --ignored --exact "$name" --nocapture > "$log" 2>&1; then
        cat "$log"
        ${pkgs.util-linux}/bin/dmesg | tail -n 60
        exit 1
      fi
      cat "$log"
      ${pkgs.grep}/bin/grep -Fxq "test $name ... ok" "$log"
      ${pkgs.grep}/bin/grep -Fq \
        'test result: ok. 1 passed; 0 failed; 0 ignored;' "$log"
    }

    run_case qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically
    ${pkgs.grep}/bin/grep -Fxq \
      'native_resource_isolation=memfd,eventfd,writable-qcow2-root,serial' \
      /tmp/qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically.log
    ${pkgs.grep}/bin/grep -Fxq \
      'native_temp_files_isolated=true' \
      /tmp/qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically.log
    ${pkgs.grep}/bin/grep -Fxq \
      'ambient_outputs_rejected=pidfile,export-socket' \
      /tmp/qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically.log
    ${pkgs.grep}/bin/grep -Fxq \
      'native_running_sibling_mutation_isolated=true' \
      /tmp/qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically.log
    ${pkgs.grep}/bin/grep -Fxq \
      'native_isolation_scopes=network-device,native-9p-device,writable-qcow2-root,serial,pidfile,export-socket,temp-files,native-running-sibling-mutation' \
      /tmp/qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically.log
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_exposes_no_world_when_second_real_fork_fails
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_exposes_no_world_when_second_real_adoption_fails
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_keeps_source_private_until_target_cleanup_retries
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_keeps_source_private_across_repository_publication_retry
    run_case qemu_hot_fork_world_factory::tests::native_acceptance::isolation_negative::production_factory_rejects_the_complete_isolation_negative_matrix_before_readiness
    ${pkgs.grep}/bin/grep -Fxq \
      'native_negative_isolation_matrix=private-ring-omitted,qmp-control-aliased,console-diagnostics-aliased,writable-disk-backing-aliased,network-omitted,ninep-aliased,host-continuation-identity-aliased' \
      /tmp/qemu_hot_fork_world_factory::tests::native_acceptance::isolation_negative::production_factory_rejects_the_complete_isolation_negative_matrix_before_readiness.log
    ${pkgs.grep}/bin/grep -Fxq \
      'native_negative_isolation_rejected_before=child-readiness,resume,world-publication' \
      /tmp/qemu_hot_fork_world_factory::tests::native_acceptance::isolation_negative::production_factory_rejects_the_complete_isolation_negative_matrix_before_readiness.log
    ${pkgs.grep}/bin/grep -Fxq \
      'native_negative_isolation_source_unchanged=true' \
      /tmp/qemu_hot_fork_world_factory::tests::native_acceptance::isolation_negative::production_factory_rejects_the_complete_isolation_negative_matrix_before_readiness.log

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
      'failures=fork,adoption,target-cleanup,repository-publication' \
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
