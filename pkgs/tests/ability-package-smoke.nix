##! Native package ability projection smoke fixture.
{
  lib,
  mkDerivation,
}: let
  interface = lib.abilities.declareInterface {
    name = "aos.test.package-smoke";
    abi = 1;
    description = "Exercises package ability projection and retained artifact closure.";
    requestType = lib.abilities.types.boolean;
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
  };
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
      config.aos.abilities = {
        interfaces.default = interface;
        implementations.default = {
          description = "Provides the package ability projection smoke interface.";
          interface = "default";
          methods = [];
          requirements = {};
          guarantees = [];
          compose = context: context;
          transition = context: context;
          artifacts = [
            (lib.abilities.packageOutput {package = "ability-package-smoke-provider";})
          ];
          providerModule = {
            artifact = lib.abilities.packageOutput {};
            path = "share/ability-package-smoke/provider.nix";
          };
        };

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
      description = "Native package ability projection smoke fixture";
      license = "Apache-2.0";
    };
  }
