##! Composes systemd's provider and initrd service abilities.
{
  imports = [
    ./core.nix
    ./linux-service-features.nix
    ./package-attestation-quote.nix
    ./verity-root.nix
  ];
}
