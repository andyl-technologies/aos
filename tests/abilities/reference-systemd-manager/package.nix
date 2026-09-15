##! Authenticated production fixture for the built-in systemd manager.
{
  lib,
  mkDerivation,
  packageRuntime,
  qualificationObserver ? null,
}: let
  inherit (lib.abilities) resourceRevision types;
  providerArtifact = ./provider;
  systemdManager = {
    name = "aos.systemd-manager";
    abi = 1;
  };
  localManager = lib.abilities.guarantee {
    name = "aos.local-systemd-manager";
    version = 1;
    semantics = "the selected manager controls the local host systemd instance";
  };
  delegatedManager = lib.abilities.guarantee {
    name = "aos.system-container-manager-delegation";
    version = 1;
    semantics = "the selected manager delegates lifecycle control into a system container";
  };
  string = maximum:
    types.string {
      maxLength = maximum;
      syntax = null;
    };
  optionalString = maximum: types.optional (string maximum);
  resourceMap = types.map {
    keyMaxLength = 128;
    keySyntax = "local-key-v1";
    maxEntries = 8;
    value = types.resourceReference;
  };
  request = types.record {
    fields.unit = string 256;
    optional = [];
  };
  observation = types.record {
    fields = {
      active = types.optional types.boolean;
      active_state = optionalString 128;
      job_path = optionalString 4096;
      job_result = optionalString 128;
      manager_bus_id = optionalString 1024;
      manager_owner = optionalString 1024;
      schema = types.enum ["aos.ability.systemd-observation/v1"];
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
  methodSemantics = name: {
    requiredTargetAccess =
      if builtins.elem name ["observe" "observe-boot" "observe-health" "validate" "verify"]
      then "read"
      else "exclusive-write";
    stopsProvider = name == "stop";
  };
  method = name: {
    description = "Performs the ${name} operation through the systemd manager.";
    semantics = methodSemantics name;
    parameters = request;
    targetResource = systemdManager.name;
    outputs.active = {
      description = "Reports whether the selected unit is active.";
      schema = types.boolean;
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
  systemdManagerDeclaration = lib.abilities.declareInterface {
    inherit (systemdManager) name abi;
    description = "Controls and observes units through the host systemd manager.";
    requestType = request;
    outputs = {};
    methods = builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = method name;
      })
      methods);
    inherit lifecycle;
    guarantees = [localManager delegatedManager];
    aggregation = aggregation "systemd-manager";
  };
  systemdManagerDocument = lib.abilities.interfaceDocumentFromDeclaration systemdManagerDeclaration;
  systemdManagerIdentity = lib.abilities.interfaceIdentity systemdManagerDocument;
  requirement = {
    interface = systemdManagerIdentity.name;
    inherit (systemdManagerIdentity) abi descriptor;
    inherit methods;
    strength = "required";
    fallback = null;
    guarantees = [localManager];
  };
  provider = import ./provider/default.nix {
    inherit resourceRevision;
    systemdManager = systemdManagerIdentity;
  };
  packageRuntimeSelector = lib.abilities.packageOutput {
    package = "aos";
    output = "packageRuntime";
  };
  qualificationSupport =
    if qualificationObserver == null
    then null
    else import ../_native-adapter-qualification.nix {
      inherit lib;
      observerPackage = qualificationObserver;
    };
  abilities = {
    config.aos.abilities = lib.recursiveUpdate (lib.abilities.projectDefinitions {
        driver = {
        definition = lib.abilities.define {
          interface = "aos.test.systemd-manager-matrix";
          abi = 1;
          requestSchema = types.boolean;
          configurationSchema = types.record {
            fields = {
              action = types.enum methods;
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
        artifact = packageRuntimeSelector;
        definition = lib.abilities.define {
          interface = systemdManager.name;
          inherit (systemdManager) abi;
          requestSchema = request;
          outputs = {};
          methods = builtins.listToAttrs (builtins.map (name: {
              inherit name;
              value = method name;
            })
            methods);
          inherit lifecycle;
          guarantees = [localManager delegatedManager];
          aggregation = aggregation "systemd-manager";
          requires = {};
          ownsResourceKinds = [systemdManager.name];
          handler = "native-systemd-manager";
        };
        handler = {
          artifact = packageRuntimeSelector;
          entryPoint = "libexec/aos-systemd-manager-handler";
          arguments = request;
          result = observation;
        };
        };
      }) (lib.optionalAttrs (qualificationSupport != null) {
        implementations.systemd-manager.qualification = {
          adapter = "systemd-manager";
          observationKind = "systemd";
          scope = "host-manager";
          conformanceFamilies = [
            "authority-revocation"
            "dependent-effect"
            "durability-recovery"
            "foreign-resource"
            "incarnation-replacement"
            "provider-state-transfer"
          ];
          observer = qualificationSupport.observer;
        };
      });
  };
in
  mkDerivation {
    pname = "ability-reference-systemd-manager";
    version = "1.0.0";
    src = providerArtifact;
    runtimeDeps = [packageRuntime] ++ lib.optional (qualificationObserver != null) qualificationObserver;
    inherit abilities;
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
