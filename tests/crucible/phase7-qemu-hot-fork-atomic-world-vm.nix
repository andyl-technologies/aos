# Exercises the daemon's complete production world-fork transaction with real QEMU children.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.qemuHotForkAtomicWorldVm",
  taskIds ? [],
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
  testing = import ../../lib/testing {inherit pkgs lib;};
in
  testing.mkVMTest {
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
    testScript = ''
      set -eu
      cleanup_attempt_mount() {
        ${pkgs.util-linux}/bin/umount /tmp/attempts > /dev/null 2>&1 || true
      }
      trap cleanup_attempt_mount EXIT HUP INT TERM

      for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL; do
        ${pkgs.grep}/bin/grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
      done
      mkdir -p /sys/fs/cgroup
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/crucible
      echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control
      for lane in \
        source target \
        fork-failure-source fork-failure-target \
        adoption-failure-source adoption-failure-target \
        publication-failure-source publication-failure-target; do
        mkdir "/sys/fs/cgroup/crucible/$lane"
        echo '+cpu +memory +pids' \
          > "/sys/fs/cgroup/crucible/$lane/cgroup.subtree_control"
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
      export CRUCIBLE_ATOMIC_WORLD_CGROUP=/sys/fs/cgroup/crucible
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
        ${pkgs.grep}/bin/grep -Fq 'test result: ok.' "$log"
      }

      run_case qemu_hot_fork_world_factory::tests::native_acceptance::production_factory_forks_complete_live_world_atomically
      run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_exposes_no_world_when_second_real_fork_fails
      run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_exposes_no_world_when_second_real_adoption_fails
      run_case qemu_hot_fork_world_factory::tests::native_acceptance::failures::production_factory_keeps_source_private_until_publication_cleanup_retries

      printf '%s\n' \
        'PASS' \
        'factory=production-whole-world' \
        'source=two-running-one-permanently-failed' \
        'io=block,ninep' \
        'failures=fork,adoption,publication' \
        'check=${attrPath}' \
        'tasks=${builtins.concatStringsSep "," taskIds}' \
        > /tmp/atomic-world-result
      cat /tmp/atomic-world-result
      ${pkgs.util-linux}/bin/umount /tmp/attempts
      trap - EXIT HUP INT TERM
    '';
  }
