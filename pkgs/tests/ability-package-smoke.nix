##! Production ability-companion smoke fixture.
{
  lib,
  mkDerivation,
}: let
  providerArtifact = import ./_ability-package-smoke-provider.nix {
    inherit mkDerivation;
  };
in
  mkDerivation {
    pname = "ability-package-smoke";
    version = "1.0.0";
    src = null;
    runtimeDeps = [providerArtifact];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/ability-package-smoke"
          cp ${./_ability-package-smoke}/default.nix "$out/share/ability-package-smoke/provider.nix"
        '';
      }
    ];

    abilities = {
      config.aos.abilities =
        (lib.abilities.projectDefinitions {
          default = {
            artifacts = [
              (lib.abilities.packageOutput {package = "ability-package-smoke-provider";})
            ];
            definition = lib.abilities.define {
              interface = "aos.test.package-smoke";
              abi = 1;
              requestSchema = lib.abilities.types.boolean;
              outputs = {};
              methods = {};
              lifecycle = {
                stableResourceIdentity = true;
                releasesEphemeralOnDisable = false;
                retainsPersistentByDefault = true;
                persistentDeleteMethod = null;
              };
              guarantees = [];
              aggregation = {
                scope = "provider-instance";
                key = "slot";
                rejectSlotCollisions = true;
                mergeContract = null;
                controllerGroup = "smoke";
              };
              requires = {};
              composeEntry = "compose";
              transitionEntry = "transition";
              ownsResourceKinds = [];
              compose = context: context;
              transition = context: context;
            };
          };
        })
        // {
          requirementTemplates.canonical-edge = {
            description = "Exercises canonical boundary values in a package-owned requirement.";
            interface = "aos.test.canonical-edge";
            abi = 4294967295;
            descriptor = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            methods = [];
            guarantees = [];
            strength = "advisory";
            fallback.outputs.sample = {
              label = "café 東京 😀";
              maximum = 9007199254740991;
              minimum = -9007199254740991;
            };
          };
        };
    };

    meta = {
      description = "Production ability companion smoke fixture";
      license = "Apache-2.0";
    };
  }
