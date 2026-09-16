##! Composes systemd's provider and initrd service abilities.
{
  imports = [
    ./core.nix
    ./linux-service-features.nix
    ./verity-root.nix
  ];
}
