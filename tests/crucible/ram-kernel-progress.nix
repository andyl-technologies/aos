# Actual kernel fault/instruction progress, independent of VM owner activation.
{
  pkgs,
  lib,
  attrPath,
}: let
  deviceProbe = import ./_ram-userfaultfd-device.nix {inherit pkgs;};
  evidence = [
    "userfaultfd_device_wrong_group=refused"
    "userfaultfd_device_wrong_mode=refused"
    "userfaultfd_device_full_kernel_missing=passed"
    "userfaultfd_device_full_kernel_wp=passed"
    "userfaultfd_device_runner_gid=29000"
    "userfaultfd_progress_one_slot_alternations=8"
    "userfaultfd_progress_one_slot_completion=not-retired"
    "userfaultfd_progress_two_page_result=retired-and-joined"
    "userfaultfd_progress_two_domain_one_slot_alternations=8-per-domain"
    "userfaultfd_progress_two_domain_one_slot_completion=neither-retired"
    "userfaultfd_progress_two_domain_retained_pairs=both-retired-and-joined"
    "userfaultfd_progress_scope=kernel-host-instruction-only"
  ];
  rootfs = (import ../../lib/testing/firecracker.nix {inherit pkgs lib;}).mkFirecrackerRootfs {
    pname = "crucible-kernel-instruction-progress";
    extraWritableMiB = 128;
    rootfsDeps = [deviceProbe pkgs.coreutils pkgs.grep];
    testScript = ''
      set -eu
      test "$(cat /proc/sys/vm/unprivileged_userfaultfd)" = 0
      ${deviceProbe}/bin/crucible-userfaultfd-device-probe > /var/progress.log 2>&1
      cat /var/progress.log
      test "$(cat /proc/sys/vm/unprivileged_userfaultfd)" = 0
      ${lib.concatMapStringsSep "\n" (marker: ''
          test "$(${pkgs.grep}/bin/grep -Fxc ${lib.escapeShellArg marker} /var/progress.log)" -eq 1
        '')
        evidence}
      echo PASS
      echo check=${attrPath}
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-kernel-instruction-progress";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.qemu];
    phases = [
      {
        name = "check-real-kernel-instruction-progress";
        script = ''
          set -eu
          mkdir -p "$out"
          cp ${rootfs} rootfs.img
          chmod u+w rootfs.img
          for image in ${pkgs.linux}/boot/vmlinuz-*; do
            kernel="$image"
          done
          test -n "$kernel"

          # Match the existing native RAM flight's outer resource/timeout
          # envelope. This component issues no guest or Source capability.
          set +e
          ${pkgs.coreutils}/bin/timeout -k 30 3000 \
            ${pkgs.qemu}/bin/qemu-system-x86_64 \
            -machine q35,accel=tcg -cpu max -smp 4 -m 4096 \
            -nodefaults -display none -serial stdio -monitor none -no-reboot \
            -kernel "$kernel" \
            -append "console=ttyS0 reboot=k panic=1 root=/dev/vda rw init=/init net.ifnames=0" \
            -drive file=rootfs.img,format=raw,if=virtio \
            > "$out/serial.raw.log" 2>&1
          status=$?
          set -e
          ${pkgs.coreutils}/bin/tr -d '\r' < "$out/serial.raw.log" > "$out/serial.log"
          cat "$out/serial.log"
          test "$status" -eq 0
          ${pkgs.grep}/bin/grep -Fxq TEST_RESULT:PASS "$out/serial.log"
          if ${pkgs.grep}/bin/grep -Fq TEST_RESULT:FAIL "$out/serial.log"; then
            exit 1
          fi
          ${lib.concatMapStringsSep "\n" (marker: ''
              test "$(${pkgs.grep}/bin/grep -Fxc ${lib.escapeShellArg marker} "$out/serial.log")" -eq 1
            '')
            evidence}
          {
            echo PASS
            echo check=${attrPath}
            ${pkgs.grep}/bin/grep -E '^userfaultfd_(device|progress)_[a-z_]+=' "$out/serial.log"
          } > "$out/result"
        '';
      }
    ];
    passthru = {inherit deviceProbe rootfs;};
  }
