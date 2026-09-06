# Runs many hot-fork child lifecycles against one retained template inside a
# disposable VM that owns cgroup-v2 and project quotas, and holds the source
# to its baseline thread and descriptor counts throughout. The routine
# instance runs a few hundred lifecycles; the stress instance runs the ten
# thousand the RFC's Phase 6 stress task asks for and is built on demand.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.qemuHotForkChildStressVm",
  taskIds ? [],
  lifecycles ? 250,
  # When set, the source's private dirty memory may grow by at most this many
  # KiB between the sample at half the lifecycles and the final sample. The
  # source's heap settles within the first few hundred lifecycles, so the
  # long instance holds the second half flat while the routine instance,
  # which ends inside the warm-up, only reports.
  lateGrowthBoundKib ? null,
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  probe = pkgs.mkDerivation {
    pname = "crucible-qemu-live-hot-fork-child-stress";
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
            -p crucible-qemu --example crucible-qemu-live-hot-fork-child-stress
          mkdir -p "$out/bin"
          cp "$TMPDIR/target/release/examples/crucible-qemu-live-hot-fork-child-stress" "$out/bin/"
        '';
      }
    ];
  };
  testing = import ../../lib/testing {inherit pkgs lib;};

  # One lifecycle takes well under a second on the small firmware guest; the
  # budget leaves room for the source launch and a slow host.
  probeTimeoutSeconds = 300 + lifecycles;
in
  testing.mkVMTest {
    name = "crucible-qemu-hot-fork-child-stress-${builtins.toString lifecycles}";
    memory = 3072;
    rootfsDeps = [
      probe
      pkgs.qemu-crucible
      pkgs.crucible-qemu-plugin
      pkgs.linux
      pkgs.e2fsprogs
      pkgs.coreutils
      pkgs.util-linux
      pkgs.grep
      pkgs.gawk
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
      truncate -s 3G /tmp/attempts.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /tmp/attempts.img
      mkdir /tmp/attempts
      ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts
      # The allocator authenticates an exact-owner private directory, not the
      # filesystem root with its mke2fs-created lost+found directory.
      mkdir -m 700 /tmp/attempts/run
      probe_status=0
      ${pkgs.coreutils}/bin/timeout -k 5 ${builtins.toString probeTimeoutSeconds} \
        ${probe}/bin/crucible-qemu-live-hot-fork-child-stress \
        ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
        ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
        ${pkgs.linux}/boot/vmlinuz-* \
        ${pkgs.qemu-crucible}/share/qemu/bios-256k.bin \
        /sys/fs/cgroup/crucible /tmp/attempts/run ${builtins.toString lifecycles} \
        > /tmp/hot-fork-stress-result || probe_status=$?
      cat /tmp/hot-fork-stress-result
      if [ "$probe_status" -ne 0 ]; then
        echo "probe exited with status $probe_status"
        ${pkgs.util-linux}/bin/dmesg | tail -n 40
      fi
      [ "$probe_status" -eq 0 ]
      grep -Fxq PASS /tmp/hot-fork-stress-result
      grep -Fxq lifecycles=${builtins.toString lifecycles} /tmp/hot-fork-stress-result
      grep -Fxq source_threads_leaked=0 /tmp/hot-fork-stress-result
      grep -Fxq source_descriptors_leaked=0 /tmp/hot-fork-stress-result
      ${lib.optionalString (lateGrowthBoundKib != null) ''
        # Samples are `lifecycles:kib` pairs; the midpoint sample is the first
        # at or past half the lifecycles.
        late_growth=$(${pkgs.gawk}/bin/awk -F= '/^private_dirty_samples=/ {
          n = split($2, samples, ",")
          mid = 0
          for (i = 1; i <= n; i++) {
            split(samples[i], pair, ":")
            if (mid == 0 && pair[1] * 2 >= ${builtins.toString lifecycles}) mid = pair[2]
            last = pair[2]
          }
          print last - mid
        }' /tmp/hot-fork-stress-result)
        echo "source_private_dirty_late_growth_kib=$late_growth" >> /tmp/hot-fork-stress-result
        [ "$late_growth" -le ${builtins.toString lateGrowthBoundKib} ]
      ''}
      printf '%s\n' 'check=${attrPath}' \
        'tasks=${builtins.concatStringsSep "," taskIds}' >> /tmp/hot-fork-stress-result
      ${pkgs.util-linux}/bin/umount /tmp/attempts
    '';
  }
