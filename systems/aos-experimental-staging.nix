##! systems/aos-experimental-staging.nix — Experimental artifacts for the staging Hub
{lib, ...}: {
  imports = [./aos-experimental.nix];

  # Destination identity is baked before signing so consumers use the same
  # deployment that publishes the immutable disk and OCI artifacts.
  aos.system.version = lib.mkForce "2026.9.0-dev.20260928.8";
  # The complete runtime payload exceeds 132 MiB on both Linux architectures.
  # Reserve initrd space before embedding it in the signed EFI payloads.
  aos.image.budgets.maxInitrdMiB = 160;
  # Arm embeds its uncompressed kernel alongside the complete runtime initrd.
  # The ESP retains both normal and recovery UKIs with filesystem headroom.
  aos.image.budgets.maxBootExecutableMiB = 224;
  aos.image.budgets.maxFirmwarePartitionMiB = 768;

  # Locale data and the complete libc utility interpreter increase the root
  # payload. Size staging partitions for that payload before external signing.
  aos.image.budgets.maxRootMiB = 768;
  aos.image.budgets.maxDownloadMiB = 1280;
  aos.image.budgets.maxConvertedDownloadMiB = 1792;
  aos.image.budgets.maxRecoveryBundleMiB = 1792;

  aos.release = {
    registryOrigin = "https://cdn.aos.staging.andyl.org";
    hubUrl = "https://aos.staging.andyl.org";
  };
}
