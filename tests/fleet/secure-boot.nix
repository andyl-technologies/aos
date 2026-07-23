# tests/fleet/secure-boot.nix — Secure Boot enforcement, end to end.
#
# RFC-0006 phase 1. Proves the firmware actually ENFORCES Secure Boot
# against our own keys, using the real Setup-Mode → User-Mode enrollment
# path (no offline vars injection):
#
#   1. Boot the SB-signed image under the (SB-enabled) OVMF. No keys are
#      enrolled yet, so the firmware is in Setup Mode and boots the image
#      regardless of signature. Assert SetupMode=1, SecureBoot=0.
#   2. Enroll db → KEK → PK via efivarfs (`aos-sb-enroll`). Setting PK
#      exits Setup Mode. Assert SetupMode=0.
#   3. Reboot. The firmware now ENFORCES: it must load the db-signed UKI
#      and sd-boot. Assert the machine comes back, SecureBoot=1,
#      SetupMode=0, and bootctl reports "Secure Boot: enabled (user)".
#   4. NEGATIVE (load-bearing): tamper the UKI on the ESP and reboot. The
#      enforcing firmware must REFUSE it — the agent never returns and the
#      serial shows a firmware rejection.
#
# Single image-boot machine (server-secureboot: server + signed image +
# the bundled aos-test-agent package). This is the first CI proof that the
# sd-boot/UKI chain is signed AND that the firmware rejects tampering.
{
  pkgs,
  systems,
}: {
  name = "secure-boot";
  # Image boot + enroll + reboot-to-enforcing + a second (rejected)
  # reboot. Budgeted like the other image-boot tests plus two reboots.
  timeout = 1800;

  machines = {
    # The base image ships only ESP and root-a;
    # systemd-repart creates swap/var on first boot. /var is required for the
    # system to reach multi-user (identity + role activation persist there).
    target = {
      system = systems.server-secureboot;
      bootMode = "image";
      imageDiskMiB = 16384;
      packages = ["aos-test-agent"];
    };
  };

  testScript =
    # python
    ''
      SB_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

      def efivar_byte(name):
          # efivarfs entries are 4 attribute bytes followed by the data;
          # for SecureBoot/SetupMode the data is a single 0/1 byte.
          path = f"/sys/firmware/efi/efivars/{name}-{SB_GUID}"
          out = target.succeed(f"od -An -tu1 -j4 -N1 {path}").strip()
          return int(out)

      # ════ 1. First boot — SB-enabled OVMF, Setup Mode ═════════════════
      target.succeed("systemctl is-active multi-user.target")
      target.succeed("test -d /sys/firmware/efi/efivars")
      # efivarfs is built into the kernel (CONFIG_EFIVAR_FS=y), so systemd
      # mounts it early and the SB variables are visible.
      assert efivar_byte("SetupMode") == 1, "expected Setup Mode before enrollment"
      assert efivar_byte("SecureBoot") == 0, "SB should not be enforcing yet"

      # ════ 2. Enroll db → KEK → PK (guest-side, via efivarfs) ══════════
      # The aos-sb-enroll wrapper (a systemPackage) isn't on the test
      # agent's restricted PATH, so drive efi-updatevar directly by store
      # path — exactly what the wrapper does. db and KEK first (still in
      # Setup Mode), then PK (setting PK exits Setup Mode → enforcing).
      # efi-updatevar shells out to `mount -l`, so it needs util-linux on
      # PATH (the agent's PATH lacks mount). Drive it by store path — the
      # aos-sb-enroll wrapper isn't on the agent PATH. db and KEK first
      # (Setup Mode), then PK (setting PK exits Setup Mode → enforcing).
      eu = "PATH=${pkgs.util-linux}/bin:$PATH ${pkgs.efitools}/bin/efi-updatevar"
      keys = "${pkgs.secure-boot-test-keys}"
      for var, auth in (("db", "db.auth"), ("KEK", "KEK.auth"), ("PK", "PK.auth")):
          target.succeed(f"{eu} -f {keys}/{auth} {var} 2>&1")
      assert efivar_byte("SetupMode") == 0, "PK enrollment should exit Setup Mode"

      # ════ 3. Reboot into enforcing mode; signed UKI must load ═════════
      target.reboot()
      target.wait_until_succeeds("systemctl is-active multi-user.target", timeout=120)
      assert efivar_byte("SecureBoot") == 1, "Secure Boot should be enforcing"
      assert efivar_byte("SetupMode") == 0, "should remain in User Mode"
      # bootctl status exits non-zero on benign warnings while still
      # printing the SB state, so don't gate on its exit code.
      status = target.succeed("bootctl status 2>&1 || true")
      print("=== bootctl status ===\n" + status)
      assert "Secure Boot: enabled (user)" in status, (
          f"bootctl does not report enforcing user-mode SB:\n{status}"
      )

      # The booted UKI carries a db signature (sd-boot loaded it under
      # enforcement, the real proof). Remount /boot rw to tamper it;
      # `mount` needs util-linux on PATH (not on the agent PATH).
      mount = "${pkgs.util-linux}/bin/mount"
      # Ensure the ESP is actually mounted before flipping it rw. /boot is a
      # plain fstab vfat mount (modules/base/filesystems.nix) pulled by
      # local-fs.target, NOT a hard dependency of multi-user.target — under
      # load its fsck+mount can still be settling (or have transiently
      # failed) once we reach here, so a bare `remount,rw` races and dies
      # with "mount point not mounted". `systemctl start boot.mount` is
      # synchronous and idempotent: it joins an in-flight mount job or
      # re-drives a failed/inactive one, and surfaces a clear error if the
      # ESP genuinely cannot mount.
      target.succeed("systemctl start boot.mount")
      target.succeed(f"{mount} -o remount,rw /boot")
      uki = target.succeed("ls /boot/EFI/Linux/aos-*.efi | head -1").strip()
      print(f"UKI: {uki}")

      # ════ 4. NEGATIVE — tamper the UKI, reboot, expect rejection ══════
      # Overwrite a stretch in the middle of the PE so the Authenticode
      # signature no longer matches. Under enforcement the firmware must
      # refuse to load it.
      target.succeed(
          f"dd if=/dev/zero of={uki} bs=1 count=256 seek=8192 conv=notrunc"
      )
      target.succeed("sync")
      serial = target.reboot_expect_rejected(settle=120)
      # reboot_expect_rejected raises if the tampered image booted; if we
      # got here the firmware refused it. Surface the serial tail.
      print("=== post-tamper serial tail ===\n" + serial[-2000:])
    '';
}
