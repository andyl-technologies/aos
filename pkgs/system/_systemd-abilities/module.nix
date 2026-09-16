##! Composes systemd's provider and initrd service abilities.
{
  imports = [
    ./core.nix
    ./verity-root.nix
  ];
}
