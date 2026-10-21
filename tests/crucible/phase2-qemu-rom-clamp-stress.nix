{
  pkgs,
  lib,
  ackPollExperiment ? false,
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleBinaries workspaceTests;
  # Reuse the exact gate ROM's busy arithmetic/PIO loop. Only the guest output
  # is needed; this does not run the mapped install gate in place of QemuNode.
  firmwareGuest = (import ./phase2-qemu-live-whitebox-doorbell.nix {inherit pkgs lib;}).passthru.guest;
  flight = mkCrucibleBinaries {
    pname = "crucible-rom-clamp-stress-flight";
    builds = [
      (
        if ackPollExperiment
        then workspaceTests.apacheReleaseTestSupport
        else workspaceTests.apacheRelease
      )
    ];
    executables = {
      crucible-qemu-rom-clamp-stress = "build --release -p crucible-qemu ${lib.optionalString ackPollExperiment "--features test-support"} --example crucible-qemu-rom-clamp-stress";
    };
  };
  comparison = import ./phase2-qemu-rom-clamp-ack-poll.nix {inherit pkgs flight firmwareGuest;};
  testing = import ../../lib/testing {inherit pkgs lib;};
  vmTest = testing.mkVMTest {
    name =
      if ackPollExperiment
      then "crucible-qemu-rom-clamp-ack-poll"
      else "crucible-qemu-rom-clamp-stress";
    memory = 3072;
    rootfsDeps =
      [
        flight
        firmwareGuest
        pkgs.qemu-crucible
        pkgs.crucible-qemu-plugin
        pkgs.linux
        pkgs.e2fsprogs
        pkgs.coreutils
        pkgs.util-linux
        pkgs.grep
      ]
      ++ lib.optionals ackPollExperiment comparison.rootfsDeps;
    testScript =
      ''
        set -eu
        export TMPDIR=/tmp
        mkdir -p /sys/fs/cgroup
        ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
        echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
        mkdir /sys/fs/cgroup/crucible
        echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control

        truncate -s 2G /tmp/attempts.img
        ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project \
          -E quotatype=prjquota /tmp/attempts.img
        mkdir /tmp/attempts
        ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts
        mkdir -m 700 /tmp/attempts/run

        # The aggregate and legacy streams stay disabled in this isolated stress
        # flight. The node retains its original per-clamp acknowledgement guard.
        unset CRUCIBLE_CONTROL_CALLBACK_WITNESS CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN \
          CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS CRUCIBLE_TIME_OWNERSHIP_WITNESS
      ''
      + (
        if ackPollExperiment
        then comparison.testScript
        else ''
          if ! ${pkgs.coreutils}/bin/timeout -k 15 180 \
            ${flight}/bin/crucible-qemu-rom-clamp-stress \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            ${firmwareGuest}/whitebox-bios.bin \
            /sys/fs/cgroup/crucible /tmp/attempts/run \
            > /tmp/rom-clamp.result 2> /tmp/rom-clamp.log; then
            cat /tmp/rom-clamp.result >&2
            cat /tmp/rom-clamp.log >&2
            exit 1
          fi
          grep -Fxq PASS /tmp/rom-clamp.result
          grep -Fxq completed_quantum_clamps=20000 /tmp/rom-clamp.result
          grep -Fxq owned_cleanup=complete /tmp/rom-clamp.result
          echo CRUCIBLE_ROM_CLAMP_RESULT_BEGIN
          cat /tmp/rom-clamp.result
          echo CRUCIBLE_ROM_CLAMP_RESULT_END
        ''
      );
  };
in
  pkgs.mkDerivation {
    pname =
      if ackPollExperiment
      then "crucible-phase2-qemu-rom-clamp-ack-poll"
      else "crucible-phase2-qemu-rom-clamp-stress";
    version = "0";
    src = null;
    buildDeps =
      [pkgs.coreutils pkgs.grep pkgs.sed vmTest]
      ++ lib.optionals ackPollExperiment comparison.buildDeps;
    passthru = {inherit flight firmwareGuest vmTest;};
    phases = [
      {
        name = "retain-result";
        script =
          ''
            set -eu
            mkdir -p "$out"
            sed 's/\r$//' "${vmTest}/serial.log" > "$out/vm-serial.log"
            cp "${vmTest}/fc.log" "$out/vm-monitor.log"
          ''
          + (
            if ackPollExperiment
            then comparison.retainScript
            else ''
              test "$(grep -Fxc CRUCIBLE_ROM_CLAMP_RESULT_BEGIN "$out/vm-serial.log")" -eq 1
              test "$(grep -Fxc CRUCIBLE_ROM_CLAMP_RESULT_END "$out/vm-serial.log")" -eq 1
              sed -n '/^CRUCIBLE_ROM_CLAMP_RESULT_BEGIN$/,/^CRUCIBLE_ROM_CLAMP_RESULT_END$/ {
                /^CRUCIBLE_ROM_CLAMP_RESULT_/d
                p
              }' "$out/vm-serial.log" > "$out/result"
              grep -Fxq PASS "$out/result"
              grep -Fxq completed_quantum_clamps=20000 "$out/result"
            ''
          );
      }
    ];
  }
