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

    prefixAttrs = prefix: attrs:
      builtins.listToAttrs (
        builtins.map (name: {
          name = "${prefix}-${name}";
          value = attrs.${name};
        }) (builtins.attrNames attrs)
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

    checks = genAttrs systems (
      system: let
        env = aosFor system;
        testTools = {
          qemu = env.pkgs.qemu;
          socat = env.pkgs.socat;
          jq = env.pkgs.jq;
        };
        aosSystem = env.lib.evalModules {
          modules = [./system.nix];
          pkgs = env.pkgs;
          lib = env.lib;
        };
        allChecks = import ./lib/testing/collect.nix {
          inherit (env) pkgs lib;
          inherit testTools;
          system = aosSystem;
        };
      in
        {
          # CLI tool builds successfully
          aos = env.pkgs.aos;

          # Format check
          format = env.pkgs.mkDerivation {
            pname = "aos-format-check";
            version = "0";
            src = ./.;
            buildDeps = [env.pkgs.alejandra];
            phases = [
              {
                name = "check";
                script = ''
                  alejandra --check $src
                  mkdir -p $out
                  echo "Format check passed" > $out/result
                '';
              }
            ];
          };

          # Pure evaluation checks
          eval = allChecks.eval;

          # Package build checks
          build = allChecks.build;
        }
        // prefixAttrs "vm" allChecks.vm
        // prefixAttrs "integration" allChecks.integration
    );
  };
}
