##! systems/aos-experimental.nix — Public experimental AOS disk and OCI artifacts
{pkgs, ...}: {
  imports = [./server.nix];

  aos.profiles.experimentalRelease.enable = true;

  # The finalized x86_64 logical disk compresses to 817 MiB with the release
  # zstd settings, above the 768 MiB budget inherited from systems/edge.nix.
  # Image finalization is the only step that enforces this budget.
  aos.image.budgets.maxDownloadMiB = 1024;

  # The converted disk formats exceed the compressed raw image budget.
  # Arm exports carry the full recovery ESP and the larger root payload. The
  # finalized x86_64 formats measure 920-933 MiB (qcow2, VMDK, VHD).
  aos.image.budgets.maxConvertedDownloadMiB =
    if pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64"
    then 1792
    else 1024;

  # Recovery archives include the root and both normal and recovery UKIs.
  # The finalized Arm archive measures 1003 MiB; x86_64 carries smaller UKIs
  # but keeps the same headroom over its last measured payload.
  aos.image.budgets.maxRecoveryBundleMiB =
    if pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64"
    then 1792
    else 1280;

  # The experimental images are canonical release artifacts: the Nix build emits
  # an unsigned assembly and `aos maintain release step finalize-image` applies Secure Boot,
  # module, and PCR-policy signatures through the registry's signer adapter.
  # Only public trust inputs appear here; see andyl-experimental-authorities/README.md.
  aos.profiles.canonicalRelease = {
    enable = true;
    publicAuthorities = {
      secureBootCertificate = "${./andyl-experimental-authorities/db.crt}";
      moduleSigningCertificate = "${./andyl-experimental-authorities/modsign.crt}";
      pcrPolicyKey = "${./andyl-experimental-authorities/pcr.pem}";
      firmwareEnrollment = "${./andyl-experimental-authorities/enrollment}";
    };
  };

  # Public half of the dedicated experimental registry root. The private half
  # is operator state and must never enter this repository.
  aos.release.trustKeys = [
    "andyl-experimental:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIPYTer3cRwGWxUbdiEA2FRYkWlY9YmSHkCRyZEKtCXp4"
  ];
}
