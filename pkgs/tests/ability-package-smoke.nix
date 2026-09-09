##! Production ability-companion smoke fixture.
{
  lib,
  mkDerivation,
}:
mkDerivation {
  pname = "ability-package-smoke";
  version = "1.0.0";
  src = null;

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/ability-package-smoke"
        cp ${./_ability-package-smoke}/default.nix "$out/share/ability-package-smoke/provider.nix"
      '';
    }
  ];

  abilityPackage = {
    activationMode = "structured-effects";
    requirements.canonical-edge = {
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
    exports.default = {
      artifact = ./_ability-package-smoke;
      export = lib.abilities.define {
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

  meta = {
    description = "Production ability companion smoke fixture";
    license = "Apache-2.0";
  };
}
