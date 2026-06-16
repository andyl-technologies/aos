##! systems/server-measured-boot.nix — measured-boot test fixture (RFC-0006 phase 3)
##!
##! Builds on systems/server-secureboot.nix (so SB signing + enrollment
##! are already on) and additionally turns on measured boot: the UKI gets
##! a signed PCR policy, and first boot LUKS2-formats /var and seals its
##! key to a TPM2 token bound to that policy (PCR 11, signature-flexible)
##! plus PCR 7 (pinned by value). `tests/fleet/measured-boot.nix` boots
##! this image with a vTPM, enrolls SB keys, reboots into enforcing mode,
##! and asserts /var unlocks unattended via the TPM2 token across a reboot.
##!
##! All keys are the throwaway `secure-boot-test-keys`; production points
##! pcrPrivateKey at a release-time offline key (RFC-0006 key-custody.md).
##!
##! Auto-registers as `systems.server-measured-boot`.
{
  lib,
  pkgs,
  ...
}: {
  imports = [./server-secureboot.nix];

  aos.boot.secureBoot.measuredBoot = {
    enable = true;
    pcrPrivateKey = "${pkgs.secure-boot-test-keys}/pcr.key";
    pcrPublicKey = "${pkgs.secure-boot-test-keys}/pcr.pem";
  };

  # aos-var-crypt is the SOLE /var unlocker — disable the initrd's
  # automatic LUKS handling (systemd-cryptsetup-generator / gpt-auto) so
  # systemd doesn't race to auto-activate the sealed /var.
  aos.boot.kernelParams = ["rd.luks=0"];
}
