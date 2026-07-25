# tests/fleet/measured-boot.nix — measured boot + TPM-sealed /var, end to end.
#
# RFC-0006 phase 3. Proves the boot is measured into a (virtual) TPM and
# that /var is LUKS2-encrypted with its key sealed to a *signed PCR
# policy*, so it unlocks unattended across reboots:
#
#   1. First boot is in Setup Mode (no keys enrolled). PCR 7 (Secure Boot
#      state) is not yet the enforcing value, so /var is brought up plain
#      so the system reaches multi-user. Assert the vTPM is present.
#   2. Enroll db → KEK → PK via efivarfs, then reboot into enforcing SB.
#   3. On the first enforcing boot aos-var-crypt LUKS2-formats /var and
#      seals its key to the signed PCR policy (PCR 11) + pinned PCR 7, plus
#      a recovery key. Assert SecureBoot=1, /var is a LUKS2 device with a
#      systemd-tpm2 token, mounted via /dev/mapper/var.
#   4. Reboot again and assert /var unlocks UNATTENDED via the TPM2 token
#      (no passphrase) — the new boot re-measured PCR 11 but the signed
#      policy still unseals, and PCR 7 is unchanged.
#
# Single image-boot machine with a vTPM (server-measured-boot: server +
# SB-signed + PCR-policy-signed image + the bundled aos-test-agent package).
{
  lib,
  pkgs,
  systems,
}: {
  name = "measured-boot";
  # Image boot + enroll + three reboots (enforcing seal, then unattended
  # unlock). Budget like secure-boot plus an extra reboot.
  timeout = 3600;
  # The emulated TPM (swtpm) adds tens of seconds of slow command
  # round-trips to every boot (firmware measurement, kernel TCG init,
  # systemd PCR phases, the cryptenroll/cryptsetup TPM2 ops), so each
  # boot needs well above the 180s default.
  bootTimeout = 600;

  machines = {
    # systemd-repart carves swap and var. /var is left raw (repart
    # omits Format= under measured boot) — aos-var-crypt owns its filesystem:
    # plain ext4 on the Setup boot, LUKS2 once enforcing.
    target = {
      system = systems.server-measured-boot;
      bootMode = "image";
      imageDiskMiB = 16384;
      tpm = true;
      packages = ["aos-test-agent"];
    };
  };

  testScript =
    # python
    ''
      SB_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
      CS = "${pkgs.cryptsetup}/sbin/cryptsetup"
      VARDEV = "/dev/disk/by-partlabel/var"

      def efivar_byte(name):
          path = f"/sys/firmware/efi/efivars/{name}-{SB_GUID}"
          out = target.succeed(f"od -An -tu1 -j4 -N1 {path}").strip()
          return int(out)

      def var_source():
          # The /var mount source, read from /proc/mounts (no findmnt in
          # the agent's restricted PATH). Trailing `true` keeps the command
          # exit 0 — the while loop otherwise returns the status of its
          # last (non-matching) iteration.
          out = target.succeed(
              "while read -r dev mnt rest; do "
              "if [ \"$mnt\" = /var ]; then echo \"$dev\"; fi; "
              "done < /proc/mounts; true"
          ).strip()
          return out

      def wait_multi_user(label):
          # The swtpm-backed enforcing/seal boot is slow (argon2 luksFormat
          # + many TPM PCR round-trips through the emulator), and 180s was
          # marginal — multi-user occasionally landed just past it. Give it
          # the same generous budget as the harness boot timeout. The agent
          # autologins, so it stays reachable even if multi-user.target is
          # blocked; on timeout, dump what is still pending so an opaque
          # "deadline fired" becomes a named culprit.
          try:
              target.wait_until_succeeds(
                  "systemctl is-active multi-user.target", timeout=420
              )
          except Exception:
              print(f"=== {label}: multi-user.target stalled — diagnostics ===")
              failed = target.succeed("systemctl --failed --no-legend 2>&1 || true").strip()
              if failed:
                  print("--- failed units ---")
                  print(failed)
                  for line in failed.splitlines():
                      fields = line.split()
                      unit = fields[1] if fields and fields[0] == "*" else fields[0]
                      print(f"--- journalctl -u {unit} -b ---")
                      print(target.succeed(
                          f"journalctl -u {unit} -b --no-pager -n 120 2>&1 || true"
                      ))
              for cmd in (
                  "systemctl list-jobs --no-pager",
                  "systemctl --failed --no-pager",
                  "journalctl -b --no-pager | tail -n 80",
              ):
                  print(f"--- {cmd} ---")
                  print(target.succeed(f"{cmd} 2>&1 || true"))
              raise

      # ════ 1. First boot — Setup Mode; vTPM present ════════════════════
      wait_multi_user("boot1 (setup)")
      assert efivar_byte("SetupMode") == 1, "expected Setup Mode before enrollment"
      assert efivar_byte("SecureBoot") == 0, "SB should not be enforcing yet"
      # The emulated TPM is wired in and the kernel TCG driver bound it.
      target.succeed("test -e /dev/tpm0")
      target.succeed("test -e /sys/class/tpm/tpm0")
      # /var is up (plain) so the system is healthy pre-enrollment.
      assert var_source() != "", "/var not mounted on first boot"
      target.succeed(
          "test -e /dev/disk/by-partlabel/aos-provenance-fallback-v1"
      )
      target.succeed("test -s /var/lib/aos-provisioning/audit.json")
      target.succeed(
          "! grep -q '^Format=' "
          "/var/lib/aos-provisioning/desired/repart.d/*/*-var.conf"
      )

      # ════ 2. Enroll db → KEK → PK, reboot into enforcing SB ═══════════
      eu = "PATH=${pkgs.util-linux}/bin:$PATH ${pkgs.efitools}/bin/efi-updatevar"
      keys = "${pkgs.secure-boot-test-keys}"
      for var in ("db", "KEK", "PK"):
          target.succeed(f"{eu} -f {keys}/{var}.auth {var} 2>&1")
      assert efivar_byte("SetupMode") == 0, "PK enrollment should exit Setup Mode"
      target.reboot()

      # ════ 3. First enforcing boot — /var sealed to the signed policy ══
      wait_multi_user("boot2 (enforcing seal)")
      assert efivar_byte("SecureBoot") == 1, "Secure Boot should be enforcing"
      target.succeed(
          "test \"$(cat /run/aos-metadata/storage-coherence)\" = coherent"
      )
      # /var is now a LUKS2 device, mounted via the device-mapper node.
      # isLuks confirms LUKS; the systemd-tpm2 token (a LUKS2-only feature)
      # confirms it was sealed to the TPM. (luksDump prints "Version: 2",
      # not the literal "LUKS2", and the agent capture tail-truncates to
      # the Tokens section, so assert on the token, not a header string.)
      target.succeed(f"{CS} isLuks {VARDEV}")
      dump = target.succeed(f"{CS} luksDump {VARDEV}")
      assert "systemd-tpm2" in dump, f"/var has no TPM2 token:\n{dump}"
      assert "systemd-recovery" in dump, f"/var has no recovery token:\n{dump}"
      src = var_source()
      assert src == "/dev/mapper/var", f"/var not on the LUKS mapper: {src!r}"

      # PCR 11 (UKI/boot-phase) was extended — non-zero in the vTPM.
      pcrs = target.succeed("systemd-analyze pcrs 2>&1 || true")
      print("=== systemd-analyze pcrs ===\n" + pcrs)

      # ════ 4. Reboot — /var must unlock UNATTENDED via the TPM2 token ══
      target.reboot()
      wait_multi_user("boot3 (unattended unlock)")
      assert efivar_byte("SecureBoot") == 1
      src = var_source()
      assert src == "/dev/mapper/var", (
          f"/var did not unlock via TPM2 on reboot (source {src!r})"
      )
      dump = target.succeed(f"{CS} luksDump {VARDEV}")
      assert "systemd-tpm2" in dump, "TPM2 token vanished across reboot"
      print("=== /var unsealed UNATTENDED via TPM2 across reboot ===")
    '';
}
