# tests/fleet/secure-boot-lockdown.nix — Kernel lockdown under Secure Boot.
#
# RFC-0006 phase 2. Phase 1 stops the firmware loading unsigned boot
# binaries; lockdown stops the running (signed) kernel from being turned
# into an unsigned-code loader. This boots the lockdown deployment kernel
# under enforcing SB and proves lockdown is active and enforcing:
#
#   1. Boot (Setup Mode) → enroll db/KEK/PK → reboot into enforcing SB
#      (same path as the secure-boot test; the image is signed).
#   2. The cmdline carries `lockdown=confidentiality`, and
#      /sys/kernel/security/lockdown reports it active.
#   3. A lockdown-forbidden operation (reading /dev/mem) is blocked —
#      direct proof the LSM is enforcing, not merely compiled in.
#   4. Best-effort: an unsigned/tampered module is rejected (the kernel
#      verifies the appended signature before symbol resolution).
#
# Uses the lockdown deployment kernel, so this is a heavy CI run (a full
# kernel rebuild) — kept separate from the phase-1 secure-boot test.
{
  lib,
  pkgs,
  systems,
}: {
  name = "secure-boot-lockdown";
  timeout = 1800;

  machines = {
    # Base image ships only ESP + root-a; on the RFC-0011 new path
    # systemd-repart creates swap/var on first boot. /var is required to reach
    # multi-user (see tests/fleet/secure-boot.nix).
    target = {
      system = systems.server-secureboot-lockdown;
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
          path = f"/sys/firmware/efi/efivars/{name}-{SB_GUID}"
          return int(target.succeed(f"od -An -tu1 -j4 -N1 {path}").strip())

      # ════ 1. Setup Mode → enroll → reboot into enforcing SB ═══════════
      target.succeed("systemctl is-active multi-user.target")
      assert efivar_byte("SetupMode") == 1, "expected Setup Mode before enrollment"
      # Enroll db → KEK → PK via efi-updatevar by store path (the
      # aos-sb-enroll wrapper isn't on the agent's restricted PATH).
      # efi-updatevar needs util-linux's `mount` on PATH.
      eu = "PATH=${pkgs.util-linux}/bin:$PATH ${pkgs.efitools}/bin/efi-updatevar"
      keys = "${pkgs.secure-boot-test-keys}"
      for var in ("db", "KEK", "PK"):
          target.succeed(f"{eu} -f {keys}/{var}.auth {var} 2>&1")
      assert efivar_byte("SetupMode") == 0, "PK enrollment should exit Setup Mode"
      target.reboot()
      target.wait_until_succeeds("systemctl is-active multi-user.target", timeout=120)
      assert efivar_byte("SecureBoot") == 1, "Secure Boot should be enforcing"

      # ════ 2. Lockdown engaged in confidentiality mode ════════════════
      cmdline = target.succeed("cat /proc/cmdline")
      assert "lockdown=confidentiality" in cmdline, (
          f"lockdown= missing from cmdline: {cmdline}"
      )
      lockdown = target.succeed("cat /sys/kernel/security/lockdown")
      print("=== /sys/kernel/security/lockdown ===\n" + lockdown)
      assert "[confidentiality]" in lockdown, (
          f"lockdown LSM not in confidentiality mode: {lockdown}"
      )

      # ════ 3. A lockdown-forbidden op is blocked (enforcement) ════════
      # Under confidentiality lockdown, reading kernel memory via /dev/mem
      # is denied — EPERM — even as root. This is direct proof the LSM is
      # enforcing rather than merely present.
      target.fail("dd if=/dev/mem of=/dev/null bs=1 count=1 2>/dev/null")

      # ════ 4. Best-effort: unsigned module rejected ═══════════════════
      # MODULE_SIG_FORCE + module.sig_enforce: a module whose appended
      # signature no longer verifies must be refused (the sig is checked
      # before symbol resolution, so this holds even for a module with
      # unmet deps). Skipped if modules are compressed (insmod can't load
      # a raw .ko then) — the lockdown + /dev/mem proofs above stand.
      ko = target.succeed(
          "find /lib/modules -name '*.ko' 2>/dev/null | head -1 || true"
      ).strip()
      if ko:
          sz = int(target.succeed(f"stat -c %s {ko}").strip())
          target.succeed(f"cp {ko} /tmp/bad.ko")
          # Zero a stretch inside the appended PKCS#7 signature region.
          target.succeed(
              f"dd if=/dev/zero of=/tmp/bad.ko bs=1 count=64 "
              f"seek={sz - 200} conv=notrunc 2>/dev/null"
          )
          out = target.fail("insmod /tmp/bad.ko 2>&1") or ""
          dmesg = target.succeed("dmesg | tail -40")
          blob = out + "\n" + dmesg
          assert any(
              m in blob
              for m in (
                  "Key was rejected",
                  "signature",
                  "unsigned module",
                  "module verification failed",
                  "Loading of unsigned",
              )
          ), f"insmod failed but not for a signature reason:\n{blob}"
          print("unsigned-module rejection confirmed")
      else:
          print("modules are compressed — skipping insmod check (lockdown proven above)")
    '';
}
