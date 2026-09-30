##! systems/aos-testing-staging.nix — Testing artifacts for the staging Hub
{lib, pkgs, ...}: {
  imports = [./aos-testing.nix];

  # Destination identity is baked before signing so consumers use the same
  # deployment that publishes the immutable disk and OCI artifacts.
  aos.system.version = lib.mkForce "2026.9.0-dev.20260928.8";
  # The current Arm initrd is 142 MiB. Reserve space for the complete CLI
  # payload while retaining the existing independent UKI and ESP capacities.
  aos.image.budgets.maxInitrdMiB =
    if pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64"
    then 160
    else 132;

  aos.release = {
    registryOrigin = "https://cdn.aos.staging.andyl.org";
    hubUrl = "https://aos.staging.andyl.org";
  };
}
