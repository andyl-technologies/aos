##! Authenticated production fixture for the built-in systemd manager.
{
  lib,
  mkDerivation,
  packageRuntime,
}: let
  inherit (lib.abilities) schemas;
  providerArtifact = ./provider;
  systemdManager = {
    name = "aos.systemd-manager";
    abi = 1;
    descriptor = "sha256:ff940aedc92c6492557de96a9d802ad27e8dc945155adc23c7542b0bb5e3bce3";
  };
  localManager = {
    name = "aos.local-systemd-manager";
    version = 1;
    descriptor = "sha256:50995c1c62000543639c8d9f85995c35cc44a9022933ed79e5447654593291d4";
  };
  delegatedManager = {
    name = "aos.system-container-manager-delegation";
    version = 1;
    descriptor = "sha256:a811c4d2cc0fd8e09a019ae518bbe95f393ed5bc3265a1b72902adfa7325ceda";
  };
  string = maximum:
    schemas.string {
      maxLength = maximum;
      syntax = null;
    };
  optionalString = maximum: schemas.optional (string maximum);
  resourceMap = schemas.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 8;
    value = schemas.resourceReference;
  };
  request = schemas.record {
    fields.unit = string 256;
    optional = [];
  };
  observation = schemas.record {
    fields = {
      active = schemas.optional schemas.boolean;
      active_state = optionalString 128;
      job_path = optionalString 4096;
      job_result = optionalString 128;
      manager_bus_id = optionalString 1024;
      manager_owner = optionalString 1024;
      schema = schemas.enum ["aos.ability.systemd-observation/v1"];
      state = string 128;
      unit = string 256;
      unit_identity = optionalString 1024;
    };
    optional = [];
  };
  lifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = false;
    retainsPersistentByDefault = true;
    persistentDeleteMethod = null;
  };
  aggregation = group: {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = group;
  };
  method = name: {
    operationFamily =
      if name == "observe"
      then {kind = "observe-readiness";}
      else {
        kind = "service-lifecycle";
        action = name;
      };
    parameters = request;
    targetResource = systemdManager.name;
    outputs.active = {
      schema = schemas.boolean;
      phase = "observation";
      visibility = "protected";
      lifetime = "attempt";
    };
    permittedOperations = [name];
    guarantees = [];
    outcome = {
      completionEvidence = observation;
      observationEvidence = observation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  methods = ["observe" "reload" "restart" "start" "stop"];
  requirement = {
    interface = systemdManager.name;
    inherit (systemdManager) abi descriptor;
    inherit methods;
    strength = "required";
    fallback = null;
    guarantees = [localManager];
  };
  provider = import ./provider/default.nix;
  abilityPackage = {
    requiredFeatures = ["abilities-v1"];
    activationMode = "structured-effects";
    ownership = [[]];
    artifacts = [];
    requirements = {};
    exports = {
      driver = {
        artifact = providerArtifact;
        export = lib.abilities.define {
          interface = "aos.test.systemd-manager-matrix";
          abi = 1;
          requestSchema = schemas.boolean;
          configurationSchema = schemas.record {
            fields = {
              action = schemas.enum methods;
              revision = string 128;
            };
            optional = [];
          };
          outputs.managers = {
            schema = resourceMap;
            phase = "planning";
            visibility = "protected";
            lifetime = "instance";
          };
          methods = {};
          inherit lifecycle;
          guarantees = [];
          aggregation = aggregation "matrix-systemd";
          requires.manager = requirement;
          composeEntry = "compose";
          transitionEntry = "transition";
          ownsResourceKinds = [systemdManager.name];
          compose = provider.compose;
          transition = provider.transition;
        };
      };
      systemd-manager = {
        artifact = packageRuntime;
        export = lib.abilities.define {
          interface = systemdManager.name;
          inherit (systemdManager) abi;
          requestSchema = request;
          outputs = {};
          methods = builtins.listToAttrs (builtins.map (name: {
              inherit name;
              value = method name;
            }) methods);
          inherit lifecycle;
          guarantees = [localManager delegatedManager];
          aggregation = aggregation "systemd-manager";
          requires = {};
          ownsResourceKinds = [systemdManager.name];
          handler = "native-systemd-manager-v1";
        };
      };
    };
    handlers.native-systemd-manager-v1 = {
      artifact = packageRuntime;
      entryPoint = "libexec/aos-systemd-manager-handler-v1";
      arguments = request;
      result = observation;
    };
  };
in
  mkDerivation {
    pname = "ability-reference-systemd-manager";
    version = "1.0.0";
    src = providerArtifact;
    inherit abilityPackage;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/ability-reference-systemd-manager"
          printf '%s\n' 'native systemd manager matrix fixture' \
            > "$out/share/ability-reference-systemd-manager/README"
        '';
      }
    ];
    meta = {
      description = "Authenticated systemd manager qualification fixture";
      license = "Apache-2.0";
    };
  }
