##! Validates the production Nix package inventory through the Rust release model.
{
  pkgs,
  platform,
  releasePackageInventory,
}: let
  inventory = builtins.toFile "aos-release-package-inventory.json" (
    builtins.toJSON releasePackageInventory
  );
in
  pkgs.mkDerivation {
    pname = "aos-release-inventory-boundary-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.aos.testSupport];
    phases = [
      {
        name = "check";
        script = ''
          aos-release-fleet-fixture validate-package-inventory ${inventory} ${platform}
          mkdir -p "$out"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
  }
