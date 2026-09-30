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
  };
}
