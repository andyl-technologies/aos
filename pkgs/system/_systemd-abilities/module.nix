##! Composes systemd's provider and initrd service abilities.
{
  imports = [
    ./core.nix
    ./boot-preparation-handoff.nix
    ./linux-service-features.nix
    ./manager.nix
    ./package-store-read-view.nix
    ./package-attestation-quote.nix
    ./platform/crash-dump.nix
    ./platform/event-log.nix
    ./platform/image.nix
    ./platform/pam.nix
    ./verity-root.nix
  ];
}
