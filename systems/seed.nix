# systems/seed.nix — Seed server variant
#
# Zone-level infrastructure server that builds AOS images from source using
# Nix and serves the resulting artifacts over HTTPS for iPXE network boot.
# One seed per zone. Extends the server variant with nginx, Nix daemon, and
# the seed build/serve orchestration.
#
# Adds over server:
#   - nginx web server with ACME TLS
#   - Nix daemon for building packages from source
#   - Seed orchestration (image building + HTTPS serving)
#   - ZFS datasets for Nix store, image artifacts, and source checkout

{
  config,
  pkgs,
  lib,
  ...
}:

{
  imports = [
    ./server.nix
    ../modules/services/nginx.nix
    ../modules/services/nix-daemon.nix
    ../modules/services/seed.nix
  ];

  aos.system.variant = "seed";

  # --- Web server ---
  aos.services.nginx.enable = true;

  # --- Nix daemon ---
  aos.services.nix.enable = true;

  # --- Seed orchestration ---
  aos.services.seed.enable = true;

  # Seed host needs more root space for base system + Nix tooling.
  # The Nix store and built images live on ZFS datasets at runtime.
  aos.image.rootSize = "16G";
}
