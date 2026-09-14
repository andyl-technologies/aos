##! Production ability-companion smoke fixture.
{
  lib,
  mkDerivation,
}: let
  selfReferentialDependency = mkDerivation {
    pname = "ability-package-smoke-self-reference";
    version = "1.0.0";
    src = null;
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          printf '%s\n' "$out" > "$out/self-reference"
        '';
      }
    ];
  };
  providerArtifact = mkDerivation {
    pname = "ability-package-smoke-provider";
    version = "1.0.0";
    src = null;
    runtimeDeps = [selfReferentialDependency];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp ${./_ability-package-smoke}/default.nix "$out/default.nix"
          printf '%s\n' '${selfReferentialDependency}' > "$out/transitive-dependency"
        '';
      }
    ];
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
      config.aos.abilities.requirementTemplates.canonical-edge = {
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
      config.aos.abilities.implementations.default = {
        artifacts = [
          (lib.abilities.packageOutput {package = "ability-package-smoke-provider";})
        ];
        definition = lib.abilities.define {
          interface = "aos.test.package-smoke";
          abi = 1;
          requestSchema = lib.abilities.schemas.boolean;
          outputs = {};
          methods = {};
          lifecycle = {
            stableResourceIdentity = true;
            releasesEphemeralOnDisable = true;
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
    };

    passthru.serviceDocumentation = {
      kind = "fixture";
      summary = "Ability publication fixture for package authoring tests.";
    };

    meta = {
      description = "Production ability companion smoke fixture";
      license = "Apache-2.0";
    };
  }
