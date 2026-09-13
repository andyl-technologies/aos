##! Shared package contract for one package-owned systemd target.
{
  lib,
  packageName,
}: let
  inherit (lib.abilities) schemas;

  catalog = import ./providers/service-package/catalog.nix;
  spec =
    catalog.${packageName}
    or (throw "service ability package has no catalog entry for '${packageName}'");
  providerArtifact = ./providers/service-package;

  systemdEffects = {
    name = "aos.systemd-service-effects";
    abi = 1;
    descriptor = "sha256:383803bfd7eb105968a80a796fc4726b5663890e88220d26b20dbd2b33349b50";
  };
  localSystemdManager = lib.abilities.guarantee {
    name = "aos.local-systemd-manager";
    version = 1;
    descriptor = "sha256:50995c1c62000543639c8d9f85995c35cc44a9022933ed79e5447654593291d4";
  };
  revision = schemas.string {
    maxLength = 71;
    syntax = null;
  };
  provider = import providerArtifact;
in {
  activationMode = "structured-effects";
  requiredFeatures = ["abilities-v1"];
  ownership = [[]];
  artifacts = [];
  requirements = {};

  exports.service = {
    artifact = providerArtifact;
    export = lib.abilities.define {
      interface = spec.interface;
      abi = 1;
      requestSchema = schemas.boolean;
      configurationSchema = schemas.record {
        fields = {
          enabled = schemas.boolean;
          inherit revision;
        };
        optional = [];
      };
      outputs = {};
      methods = {};
      lifecycle = {
        stableResourceIdentity = true;
        releasesEphemeralOnDisable = true;
        retainsPersistentByDefault = false;
        persistentDeleteMethod = null;
      };
      guarantees = [];
      aggregation = {
        scope = "provider-instance";
        key = "slot";
        rejectSlotCollisions = true;
        mergeContract = null;
        controllerGroup = "service";
      };
      requires.service-terminal = {
        interface = systemdEffects.name;
        inherit (systemdEffects) abi descriptor;
        methods = ["start" "stop"];
        guarantees = [localSystemdManager];
        strength = "required";
        fallback = null;
      };
      composeEntry = "compose";
      transitionEntry = "transition";
      ownsResourceKinds = [systemdEffects.name];
      compose = provider.compose;
      transition = provider.transition;
    };
  };
}
