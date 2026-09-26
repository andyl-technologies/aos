##! Composes systemd's provider and initrd service abilities.
{
  imports = [
    ./core.nix
    ./initrd-handoff-plan.nix
    ./listener-claims.nix
    ./manager.nix
    ./package-store-read-view.nix
    ./policy-implementations.nix
    ./platform/image.nix
    ./verity-root.nix
  ];
}
