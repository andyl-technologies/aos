##! systems/aos-testing.nix — Public experimental AOS disk and OCI artifacts
{pkgs, ...}: {
  imports = [./server.nix];

  aos.profiles.testingRelease.enable = true;

  # The converted disk formats exceed the compressed raw image budget.
  aos.image.budgets.maxConvertedDownloadMiB =
    if pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64"
    then 1024
    else 896;

  # Recovery archives include the root and both normal and recovery UKIs.
  aos.image.budgets.maxRecoveryBundleMiB =
    if pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64"
    then 1280
    else 1024;

  # The experimental images are canonical release artifacts: the Nix build emits
  # an unsigned assembly and `aos release finalize-image` applies Secure Boot,
  # module, and PCR-policy signatures through the registry's signer adapter.
  # Only public trust inputs appear here; see andyl-testing-authorities/README.md.
  aos.profiles.canonicalRelease = {
    enable = true;
    publicAuthorities = {
      secureBootCertificate = "${./andyl-testing-authorities/db.crt}";
      moduleSigningCertificate = "${./andyl-testing-authorities/modsign.crt}";
      pcrPolicyKey = "${./andyl-testing-authorities/pcr.pem}";
      firmwareEnrollment = "${./andyl-testing-authorities/enrollment}";
    };
  };

  # Public half of the dedicated experimental registry root. The private half
  # is operator state and must never enter this repository.
  aos.release.trustKeys = [
    "andyl-testing:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAAID1J77zx10Z/VmgFa5qab2phnJEJ2JEp8mS2HnBAnzbH"
  ];
}
