##! Source-backed admission of the daemon payload for lifecycle qualification.
{pkgs, ...}: {
  imports = [../../systems/server-test.nix];
  aos.packages.nix-daemon = {
    package = pkgs.nix-daemon;
    bundle = true;
  };
}
