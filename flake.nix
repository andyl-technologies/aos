{
  description = "ANDYL OS — immutable, minimal Linux distribution built from source";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, crane }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      aosCliFor = system:
        let
          pkgs = import nixpkgs { inherit system; };
          craneLib = crane.mkLib pkgs;
        in import ./pkgs/tools/aos.nix { inherit craneLib pkgs; };
    in {
      packages = forAllSystems (system: {
        aos = aosCliFor system;
        default = aosCliFor system;
      });

      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = import ./dev/shell.nix {
            inherit pkgs;
            aos = aosCliFor system;
          };
        }
      );

      checks = forAllSystems (system: {
        aos = aosCliFor system;
      });

      formatter = forAllSystems (system:
        (import nixpkgs { inherit system; }).nixfmt-rfc-style
      );
    };
}
