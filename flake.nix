{
  description = "ANDYL OS — immutable, minimal Linux distribution built from source";

  # No external inputs. All packages — including the toolchain, dev tools,
  # and test infrastructure (QEMU, etc.) — are built from source using only
  # the bootstrap tools and the AOS package set defined in this repository.
  inputs = {};

  outputs = _: let
    systems = [
      "x86_64-linux"
      "aarch64-linux"
    ];

    genAttrs = names: f:
      builtins.listToAttrs (
        map (n: {
          name = n;
          value = f n;
        })
        names
      );

    aosFor = system: let
      lib = import ./lib {inherit system;};
      pkgs = import ./pkgs {inherit lib;};
    in {
      inherit lib pkgs;
    };
  in {
    packages = genAttrs systems (
      system: let
        env = aosFor system;
      in {
        aos = env.pkgs.aos;
        default = env.pkgs.aos;
      }
    );

    devShells = genAttrs systems (
      system: let
        env = aosFor system;
      in {
        default = import ./dev/shell.nix {
          inherit system;
          inherit (env.pkgs) aos just;
        };
      }
    );

    formatter = genAttrs systems (system: (aosFor system).pkgs.alejandra);

    checks = genAttrs systems (system: {
      aos = (aosFor system).pkgs.aos;
    });
  };
}
