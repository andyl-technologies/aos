##! Composes systemd's provider and initrd service abilities.
{
  imports = [
    ./core.nix
    ./boot-preparation-handoff.nix
    ./linux-service-features.nix
    ./manager.nix
    ./package-store-read-view.nix
    ./package-attestation-quote.nix
    ./platform/image.nix
    ./verity-root.nix
  ];
}
