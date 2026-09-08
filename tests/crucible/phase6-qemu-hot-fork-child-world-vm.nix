# Forks several independent retained templates into children that are alive
# together, inside a disposable VM that owns cgroup-v2 and project quotas, and
# holds each child's executed quantum to its exact-restore and genesis-replay
# oracles. The sources exchange no traffic: this is the coexistence half of a
# whole-world fork, not the daemon's atomic world assembly.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.qemuHotForkChildWorldVm",
  taskIds ? [],
  nodeCount ? 2,
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  probe = pkgs.mkDerivation {
    pname = "crucible-qemu-live-hot-fork-child-world";
    version = "0";
    src = source;
    buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];
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
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          cargo build --frozen --offline --release \
            --manifest-path crates/Cargo.toml --target-dir "$TMPDIR/target" \
            -p crucible-qemu --example crucible-qemu-live-hot-fork-child-world
          mkdir -p "$out/bin"
          cp "$TMPDIR/target/release/examples/crucible-qemu-live-hot-fork-child-world" "$out/bin/"
        '';
      }
    ];
  };
  testing = import ../../lib/testing {inherit pkgs lib;};

  # Every source, its child, and one oracle at a time map a 128 MiB guest;
  # the quota image lives on the VM's tmpfs.
  guestMemoryMiB = 128;
in
  testing.mkVMTest {
    name = "crucible-qemu-hot-fork-child-world-${builtins.toString nodeCount}";
    memory = 4096 + nodeCount * 12 * guestMemoryMiB;
    rootfsDeps = [
      probe
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
      # This init and all controller/mount changes run in the disposable VM.
      for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL; do
        grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
      done
      mkdir -p /sys/fs/cgroup
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/crucible
      echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control
      truncate -s ${builtins.toString (3 + nodeCount)}G /tmp/attempts.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /tmp/attempts.img
      mkdir /tmp/attempts
      ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts
      # The allocator authenticates an exact-owner private directory, not the
      # filesystem root with its mke2fs-created lost+found directory.
      mkdir -m 700 /tmp/attempts/run
      probe_status=0
      ${pkgs.coreutils}/bin/timeout -k 5 ${builtins.toString (300 + 300 * nodeCount)} \
        ${probe}/bin/crucible-qemu-live-hot-fork-child-world \
        ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
        ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
        ${pkgs.linux}/boot/vmlinuz-* \
        ${pkgs.qemu-crucible}/share/qemu/bios-256k.bin \
        /sys/fs/cgroup/crucible /tmp/attempts/run ${builtins.toString nodeCount} \
        > /tmp/hot-fork-world-result || probe_status=$?
      cat /tmp/hot-fork-world-result
      if [ "$probe_status" -ne 0 ]; then
        echo "probe exited with status $probe_status"
        ${pkgs.util-linux}/bin/dmesg | tail -n 40
      fi
      [ "$probe_status" -eq 0 ]
      grep -Fxq PASS /tmp/hot-fork-world-result
      grep -Fxq node_count=${builtins.toString nodeCount} /tmp/hot-fork-world-result
      grep -Fxq children_alive_together=${builtins.toString nodeCount} /tmp/hot-fork-world-result
      grep -Fxq every_child_matches_exact_restore=true /tmp/hot-fork-world-result
      grep -Fxq every_child_matches_genesis_replay=true /tmp/hot-fork-world-result
      printf '%s\n' 'check=${attrPath}' \
        'tasks=${builtins.concatStringsSep "," taskIds}' >> /tmp/hot-fork-world-result
      ${pkgs.util-linux}/bin/umount /tmp/attempts
    '';
  }
