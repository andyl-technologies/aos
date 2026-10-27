# Exercises actual closed-profile enforcement only in a disposable Linux VM.
{
  pkgs,
  lib,
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  probe = pkgs.mkDerivation {
    pname = "crucible-pure-worker-owner-flight";
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
          mkdir -p "$CARGO_HOME" .cargo "$out/bin"
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          cargo build --frozen --offline --release -j"$NIX_BUILD_CORES" \
            --manifest-path crates/Cargo.toml --target-dir "$TMPDIR/target" \
            -p crucible-host-resources --example crucible-pure-worker-owner-flight
          cp "$TMPDIR/target/release/examples/crucible-pure-worker-owner-flight" "$out/bin/"
          $CC -O2 -Wall -Wextra -Werror \
            -o "$out/bin/pure-worker-probe" ${../../pkgs/security/aos-landlock-worker-probe.c}
        '';
      }
    ];
  };
  runtimeClosure = (lib.build.closureInfo {inherit pkgs lib;}) {
    rootPaths = [probe pkgs.aos-landlock];
    pname = "crucible-pure-worker-probe-runtime";
  };
  testing = import ../../lib/testing {inherit pkgs lib;};
in
  testing.mkVMTest {
    name = "crucible-pure-worker-owner";
    memory = 768;
    # Rootfs-backed /var/lib holds the ext4 image; /tmp is intentionally unused.
    extraWritableMiB = 384;
    rootfsDeps = [
      probe
      pkgs.aos-landlock
      runtimeClosure
      pkgs.linux
      pkgs.e2fsprogs
      pkgs.coreutils
      pkgs.util-linux
      pkgs.grep
    ];
    testScript = ''
      set -eu
      for option in CFS_BANDWIDTH MEMCG CGROUP_PIDS QUOTA QFMT_V2 QUOTACTL SECURITY_LANDLOCK SECCOMP_FILTER; do
        grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
      done
      test "$(${pkgs.aos-landlock}/bin/aos-landlock --print-abi)" -ge 4
      mkdir -p /sys/fs/cgroup
      ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
      mkdir /sys/fs/cgroup/pure-worker-fixture
      echo '+cpu +memory +pids' > /sys/fs/cgroup/pure-worker-fixture/cgroup.subtree_control

      mkdir -p /var/lib/pure-worker-fixture
      truncate -s 256M /var/lib/pure-worker-fixture/attempts.img
      ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /var/lib/pure-worker-fixture/attempts.img
      mkdir /var/lib/pure-worker-fixture/attempts
      ${pkgs.util-linux}/bin/mount -o loop,prjquota /var/lib/pure-worker-fixture/attempts.img /var/lib/pure-worker-fixture/attempts
      mkdir -m 700 /var/lib/pure-worker-fixture/attempts/run
      printf secret > /var/lib/pure-worker-secret

      # Exact realized closure roots are actual read-only mounts, not manifest
      # permission claims. No broad /nix/store grant is passed to the worker.
      set --
      while IFS= read -r root; do
        ${pkgs.util-linux}/bin/mount --bind "$root" "$root"
        ${pkgs.util-linux}/bin/mount -o remount,bind,ro "$root"
        set -- "$@" "$root"
      done < ${runtimeClosure}/store-paths
      test "$#" -ge 1
      test "$#" -le 128
      ${pkgs.coreutils}/bin/timeout -k 5 100 \
        ${probe}/bin/crucible-pure-worker-owner-flight \
        ${pkgs.aos-landlock}/bin/aos-landlock ${probe}/bin/pure-worker-probe \
        /sys/fs/cgroup/pure-worker-fixture /var/lib/pure-worker-fixture/attempts/run \
        "$@" > /var/lib/pure-worker-fixture/result
      cat /var/lib/pure-worker-fixture/result
      grep -Fxq PASS /var/lib/pure-worker-fixture/result
      grep -Fxq same_pid_kernel_profile_and_waited_cleanup=true /var/lib/pure-worker-fixture/result
      grep -Fxq memory_cpu_network_clone_fd_filesystem_output_cancel_refusal=true /var/lib/pure-worker-fixture/result
      grep -Fxq sealed_same_original_completion_and_sticky_cancel=true /var/lib/pure-worker-fixture/result
      test ! -e /var/lib/pure-worker-escape
      ${pkgs.util-linux}/bin/umount /var/lib/pure-worker-fixture/attempts
    '';
  }
