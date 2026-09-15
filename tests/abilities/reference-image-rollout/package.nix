##! Checked single-host A/B rollout package for native activation qualification.
{
  lib,
  mkDerivation,
  rolloutRuntime,
  transitionTransform ? transition: transition,
  qualificationCell ? false,
  packageName ? "ability-reference-image-rollout",
  stateFormatOverride ? null,
  qualificationObserver ? null,
}: let
  inherit (lib.abilities) resourceRevision types;

  providerArtifact =
    if qualificationCell
    then ./providers/rollout-qualification
    else ./providers/rollout;
  rolloutStateFormat =
    if stateFormatOverride == null
    then "sha256:${builtins.hashFile "sha256" ./state-format-v1.json}"
    else stateFormatOverride;

  rolloutEffectsName = "aos.ab-image-rollout-effects";
  qualificationSupport =
    if qualificationObserver == null
    then null
    else import ../_native-adapter-qualification.nix {
      inherit lib;
      observerPackage = qualificationObserver;
    };

  storePath = types.string {
    maxLength = 4096;
    syntax = null;
  };
  stateFormat = types.string {
    maxLength = 128;
    syntax = null;
  };
  imageIdentity = types.record {
    fields = {
      executor = storePath;
      state-format = stateFormat;
      toplevel = storePath;
      uki = storePath;
    };
    optional = [];
  };
  rolloutRequest = types.record {
    fields = {
      candidate = imageIdentity;
      concurrency = types.integer {
        minimum = 1;
        maximum = 1;
      };
      predecessor = imageIdentity;
      retention-expires-at-millis = types.integer {
        minimum = 1;
        maximum = 9007199254740991;
      };
      strategy = types.enum ["single-host-ab-v1"];
    };
    optional = [];
  };
  methodSemantics = name: {
    requiredTargetAccess =
      if builtins.elem name ["observe" "observe-boot" "observe-health" "validate" "verify"]
      then "read"
      else "exclusive-write";
    stopsProvider = name == "stop";
  };
  qualificationRequest = types.record {
    fields = {
      method = types.enum [
        "drain"
        "hold"
        "observe-boot"
        "observe-health"
        "prepare"
        "retain"
        "retire"
        "rollout"
        "select"
        "withdraw"
      ];
      request = rolloutRequest;
    };
    optional = [];
  };
  rolloutObservation = types.record {
    fields = {
      active-image = types.enum ["candidate" "predecessor"];
      candidate-prepared = types.boolean;
      drained = types.boolean;
      healthy = types.optional types.boolean;
      lease-expires-at-millis = types.optional (types.integer {
        minimum = 1;
        maximum = 9007199254740991;
      });
      phase = types.enum [
        "booted"
        "drained"
        "fallback-retained"
        "healthy-retained"
        "prepared"
        "retained"
        "retired"
        "selected"
      ];
      schema = types.enum ["aos.ability.ab-image-rollout-observation/v1"];
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
  requirement = selected: methods: {
    inherit (selected) abi descriptor;
    interface = selected.name;
    inherit methods;
    strength = "required";
    fallback = null;
    guarantees = [];
  };
  output = schema: phase: lifetime: {
    description = "Reports rollout state produced by the selected action.";
    inherit schema phase lifetime;
    visibility = "protected";
  };
  actionLifetime = action:
    if builtins.elem action ["drain" "observe-boot" "observe-health"]
    then "attempt"
    else if builtins.elem action ["hold" "retire"]
    then "persistent"
    else "transaction";
  method = action: let
    lifetime = actionLifetime action;
    outputs =
      {
        rollout-state = output rolloutObservation "observation" lifetime;
      }
      // lib.optionalAttrs (action == "observe-health") {
        healthy = output types.boolean "observation" "attempt";
      };
  in {
    description = "Performs the ${action} image-rollout operation.";
    semantics = methodSemantics action;
    parameters = rolloutRequest;
    targetResource = rolloutEffects.name;
    inherit outputs;
    permittedOperations = [action];
    guarantees = [];
    outcome = {
      completionEvidence = rolloutObservation;
      observationEvidence = rolloutObservation;
      supportsRejectedBeforeEffect = true;
      indeterminate = "reconcile";
    };
  };
  rolloutEffectsDeclaration = lib.abilities.declareInterface {
    name = rolloutEffectsName;
    description = "Executes provider effects required by an atomic image rollout.";
    abi = 1;
    requestType = rolloutRequest;
    outputs = {};
    methods = builtins.listToAttrs (builtins.map (action: {
        name = action;
        value = method action;
      }) [
        "drain"
        "hold"
        "observe-boot"
        "observe-health"
        "prepare"
        "retain"
        "retire"
        "select"
        "withdraw"
      ]);
    inherit lifecycle;
    guarantees = [];
    aggregation = aggregation "rollout-effects";
  };
  rolloutEffectsDocument = lib.abilities.interfaceDocumentFromDeclaration rolloutEffectsDeclaration;
  rolloutEffects = lib.abilities.interfaceIdentity rolloutEffectsDocument;
  rolloutProvider = import (providerArtifact + "/default.nix") {
    inherit resourceRevision rolloutEffects;
  };
  rolloutRuntimeSelector = lib.abilities.packageOutput {
    package = "aos";
    output = "packageRuntime";
  };

  abilities = {
    config.aos.abilities = lib.recursiveUpdate (lib.abilities.projectDefinitions {
        rollout = {
        requiredFeatures = ["ab-image-rollout-v1"];
        definition = lib.abilities.define {
          interface = "aos.ab-image-rollout";
          abi = 1;
          requestSchema = types.boolean;
          configurationSchema =
            if qualificationCell
            then qualificationRequest
            else rolloutRequest;
          outputs.machine = output types.resourceReference "planning" "persistent";
          methods = {};
          inherit lifecycle;
          guarantees = [];
          aggregation = aggregation "rollout";
          requires.effects = requirement rolloutEffects [
            "drain"
            "hold"
            "observe-boot"
            "observe-health"
            "prepare"
            "retain"
            "retire"
            "select"
            "withdraw"
          ];
          composeEntry = "compose";
          transitionEntry = "transition";
          ownsResourceKinds = ["aos.ab-image-rollout" rolloutEffects.name];
          stateFormat = rolloutStateFormat;
          compose = rolloutProvider.compose;
          transition = transitionTransform rolloutProvider.transition;
        };
      };
        rollout-effects = {
        artifact = rolloutRuntimeSelector;
        requiredFeatures = ["ab-image-rollout-v1"];
        definition = lib.abilities.define {
          interface = rolloutEffects.name;
          abi = rolloutEffects.abi;
          requestSchema = rolloutRequest;
          outputs = {};
          methods = builtins.listToAttrs (builtins.map (action: {
              name = action;
              value = method action;
            }) [
              "drain"
              "hold"
              "observe-boot"
              "observe-health"
              "prepare"
              "retain"
              "retire"
              "select"
              "withdraw"
            ]);
          inherit lifecycle;
          guarantees = [];
          aggregation = aggregation "rollout-effects";
          requires = {};
          ownsResourceKinds = [rolloutEffects.name];
          handler = "native-ab-image-rollout";
        };
        handler = {
          artifact = rolloutRuntimeSelector;
          entryPoint = "libexec/aos-ab-image-rollout-handler";
          arguments = rolloutRequest;
          result = rolloutObservation;
        };
        };
      }) (lib.optionalAttrs (packageName == "ability-reference-image-rollout" && qualificationSupport != null) {
        implementations.rollout-effects.qualification = {
          adapter = "image-rollout";
          scope = "host-machine";
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
    pname = packageName;
    version = "1.0.0";
    src = providerArtifact;
    runtimeDeps = [rolloutRuntime] ++ lib.optional (qualificationObserver != null) qualificationObserver;
    inherit abilities;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/ability-reference-image-rollout"
          printf '%s\n' 'single-host A/B rollout reference package' \
            > "$out/share/ability-reference-image-rollout/README"
        '';
      }
    ];

    meta = {
      description = "Production A/B image rollout ability fixture";
      license = "Apache-2.0";
    };
  }
