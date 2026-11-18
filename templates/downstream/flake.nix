{
  description = "A repository built with AOS as its only flake input";

  # Pin a release tag or commit for reproducible builds, for example
  # "github:andyl-technologies/aos/<tag>".
  inputs.aos.url = "github:andyl-technologies/aos";

  # Nix reads nixConfig only from the flake being built, never from its
  # inputs, so AOS's own cache settings do not apply here. Keep this block
  # identical to the one in AOS's flake.nix so toolchains download from the
  # AOS binary cache instead of building from source.
  nixConfig = {
    extra-substituters = ["https://cdn.aos.andyl.org/andyl/experimental/"];
    extra-trusted-public-keys = [
      "andyl-experimental-nix-cache-v1:1eydap438KfoN+1wAumCXOewnzzg2Cc5mq9WwEb9z/I="
    ];
    fallback = true;
  };

  outputs = {
    self,
    aos,
  }: let
    # Every system AOS exports a builder contract for.
    systems = builtins.attrNames aos.lib;

    forAllSystems = f:
      builtins.listToAttrs (map (system: {
          name = system;
          value = f system;
        })
        systems);
  in {
    packages = forAllSystems (system: let
      aosLib = aos.lib.${system};
    in rec {
      # The default phases run ./configure, make, and make install when the
      # source provides them. AOS's compiler wrapper is always available.
      hello = aosLib.mkDerivation {
        pname = "hello";
        version = "0.1.0";
        src = ./src;
      };

      default = hello;
    });

    devShells = forAllSystems (system: let
      aosLib = aos.lib.${system};
      aosPkgs = aos.legacyPackages.${system};
    in {
      default = aosLib.mkShell {
        name = "hello-dev";
        buildDeps = [
          aosPkgs.cc
          aosPkgs.gnumake
        ];
      };
    });

    checks = forAllSystems (system: let
      aosLib = aos.lib.${system};
      hello = self.packages.${system}.hello;
    in {
      hello = aosLib.runCommand "hello-check" {} ''
        test "$(${hello}/bin/hello)" = "Hello from AOS"
        touch "$out"
      '';
    });
  };
}
