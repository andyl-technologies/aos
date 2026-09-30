##! Portable measured-boot policy shared with native provisioning evaluation.
{lib, ...}: {
  options.aos.boot.secureBoot.measuredBoot = {
    pcrPublicKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Path to the PCR-policy public key (PEM). The selected boot and
        persistent-state providers publish and enforce this policy.
        Required with pcrPrivateKey.
      '';
    };
    _effectivePcrPublicKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      readOnly = true;
      extensible = true;
      internal = true;
      description = "Public-only PCR policy key retained by the image.";
    };
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Measure boot into the TPM and seal `/var` encryption to a
        *signed PCR policy* (RFC-0006 phase 3). The UKI gets a signed
        PCR policy (`.pcrsig`/`.pcrpkey`), and first boot LUKS2-formats
        `/var` and enrolls a TPM2 token sealed to that policy plus a
        recovery key. Because the seal tracks the policy key — not a
        fixed PCR hash — any db-signed UKI unseals `/var` across OTA
        upgrades, while a tampered/unsigned UKI or an SB-state change
        does not. Requires `aos.boot.secureBoot.enable`.
      '';
    };
    signedPcrs = lib.mkOption {
      type = lib.types.str;
      default = "11";
      description = ''
        PCRs covered by the *signed* policy (flexible across UKIs that
        share the policy key). PCR 11 is the UKI/boot-phase measurement
        — the one that changes per UKI and that the signature blesses.
      '';
    };

    pinnedPcrs = lib.mkOption {
      type = lib.types.str;
      default = "7+12";
      description = ''
        PCRs bound by *value* (not the signature), in systemd's
        plus-separated PCR syntax. PCR 7 records Secure Boot state and PCR
        12 records boot inputs outside the embedded UKI command line.
        Changing either denies unattended `/var` unlock and requires the
        recovery key to replace the TPM enrollment.
      '';
    };

    recoveryKeyPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/aos-var-recovery.key";
      description = ''
        Where the first-boot sealing writes the generated LUKS recovery
        passphrase. MUST be off the encrypted volume it unlocks; the
        default is the `/run` tmpfs. A deployment is expected to escrow
        this off-machine (e.g. report it back through the provisioning
        metadata channel) — "escrowed somewhere recoverable, never on
        /var" is the hard requirement (RFC-0006 measured-boot.md).
      '';
    };
  };
}
