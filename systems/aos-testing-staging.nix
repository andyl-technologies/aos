##! systems/aos-testing-staging.nix — Testing artifacts for the staging Hub
{lib, ...}: {
  imports = [./aos-testing.nix];

  # Destination identity is baked before signing so consumers use the same
  # deployment that publishes the immutable disk and OCI artifacts.
  aos.system.version = lib.mkForce "2026.9.0-dev.20260928.8";
  aos.release = {
    registryOrigin = "https://cdn.aos.staging.andyl.org";
    hubUrl = "https://aos.staging.andyl.org";
  };
}
