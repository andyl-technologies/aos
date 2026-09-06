# Forks one real retained template into a child that adopts a child-private
# VMState copy, inside a disposable VM that owns cgroup-v2 and project quotas.
# This is the first positive hot-fork execution flight; it does not prove
# whole-world adoption, disk overlays, or parent/child guest equivalence.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.qemuHotForkChildVm",
  taskIds ? [],
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  probe = pkgs.mkDerivation {
    pname = "crucible-qemu-live-hot-fork-child-execution";
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
            -p crucible-qemu --example crucible-qemu-live-hot-fork-child-execution
          mkdir -p "$out/bin"
          cp "$TMPDIR/target/release/examples/crucible-qemu-live-hot-fork-child-execution" "$out/bin/"
        '';
      }
    ];
  };
  testing = import ../../lib/testing {inherit pkgs lib;};
  # The flight attaches a debugger to a child that stalls before its private
  # QMP greeting, so its QEMU keeps the symbol table: only DWARF is removed,
  # which is what would otherwise pull the compiler into the closure.
  qemuWithSymbols = pkgs.qemu-crucible.overrideAttrs (prev: {
    dontStrip = "1";
    phases =
      prev.phases
      ++ [
        {
          name = "stripDebugKeepSymbols";
          script = ''
            find "$out/bin" -type f -exec strip --strip-debug {} \;
          '';
        }
      ];
  });
  # The plugin keeps its local symbols too, so a core's plugin frames resolve.
  pluginWithSymbols = pkgs.crucible-qemu-plugin.overrideAttrs {dontStrip = "1";};
in
  testing.mkVMTest {
    name = "crucible-qemu-hot-fork-child-execution";
    memory = 3072;
    rootfsDeps = [
      probe
      qemuWithSymbols
      pkgs.gdb
      pluginWithSymbols
      pkgs.linux
      pkgs.e2fsprogs
      pkgs.coreutils
      pkgs.util-linux
      pkgs.grep
    ];
    testScript = ''
      set -eu
      # This init and all controller/mount changes run in the disposable VM.
      for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL COREDUMP; do
        grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
      done
      # A child that dies by signal leaves a core the debugger can read after
      # the fact; the child changed credentials, so dumping needs the
      # root-owned mode with an absolute pattern.
      mkdir -m 1777 /tmp/cores
      echo '/tmp/cores/core.%e.%p' > /proc/sys/kernel/core_pattern
      echo 2 > /proc/sys/fs/suid_dumpable
      ulimit -c unlimited
      mkdir -p /sys/fs/cgroup
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/crucible
      echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control
      truncate -s 3G /tmp/attempts.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /tmp/attempts.img
      mkdir /tmp/attempts
      ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts
      # The allocator authenticates an exact-owner private directory, not the
      # filesystem root with its mke2fs-created lost+found directory.
      mkdir -m 700 /tmp/attempts/run
      # The probe's status is kept so a failure still prints the evidence
      # gathered below before the result checks end the test.
      probe_status=0
      CRUCIBLE_HOT_FORK_CHILD_DEBUGGER=${pkgs.gdb}/bin/gdb \
        ${pkgs.coreutils}/bin/timeout -k 5 600 \
        ${probe}/bin/crucible-qemu-live-hot-fork-child-execution \
        ${qemuWithSymbols}/bin/qemu-system-x86_64 \
        ${pluginWithSymbols}/lib/libcrucible_qemu_plugin.so \
        ${pkgs.linux}/boot/vmlinuz-* \
        ${qemuWithSymbols}/share/qemu/bios-256k.bin \
        /sys/fs/cgroup/crucible /tmp/attempts/run > /tmp/hot-fork-child-execution-result \
        || probe_status=$?
      cat /tmp/hot-fork-child-execution-result
      if [ "$probe_status" -ne 0 ]; then
        echo "probe exited with status $probe_status"
        echo "core settings: pattern=$(cat /proc/sys/kernel/core_pattern) \
          suid_dumpable=$(cat /proc/sys/fs/suid_dumpable) limit=$(ulimit -c)"
        ls -la /tmp/cores
        ${pkgs.util-linux}/bin/dmesg | tail -n 40
      fi
      for core in /tmp/cores/core.*; do
        [ -e "$core" ] || continue
        echo "core dump: $core"
        ${pkgs.gdb}/bin/gdb --nx --batch -ex 'set pagination off' \
          -ex 'thread apply all bt 24' \
          ${qemuWithSymbols}/bin/qemu-system-x86_64 "$core" || true
      done
      [ "$probe_status" -eq 0 ]
      grep -Fxq PASS /tmp/hot-fork-child-execution-result
      grep -Fxq child_boundary_matches_capture=true /tmp/hot-fork-child-execution-result
      grep -Fxq child_suffix_matches_exact_restore=true /tmp/hot-fork-child-execution-result
      printf '%s\n' 'check=${attrPath}' \
        'tasks=${builtins.concatStringsSep "," taskIds}' >> /tmp/hot-fork-child-execution-result
      ${pkgs.util-linux}/bin/umount /tmp/attempts
    '';
  }
