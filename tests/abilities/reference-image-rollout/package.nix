##! Checked single-host A/B rollout package for native activation qualification.
{
  lib,
  mkDerivation,
  rolloutRuntime,
  transitionTransform ? transition: transition,
}: let
  inherit (lib.abilities) schemas;

  providerArtifact = ./providers/rollout;

  interface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };
  rolloutEffects =
    interface
    "aos.ab-image-rollout-effects"
    "sha256:5776469b1b825c017ced9db370a84d693631dad739b91961dee4ef14d8816c7c";

  storePath = schemas.string {
    maxLength = 4096;
    syntax = null;
  };
  stateFormat = schemas.string {
    maxLength = 128;
    syntax = null;
  };
  imageIdentity = schemas.record {
    fields = {
      executor = storePath;
      state-format = stateFormat;
      toplevel = storePath;
      uki = storePath;
    };
    optional = [];
  };
  rolloutRequest = schemas.record {
    fields = {
      candidate = imageIdentity;
      concurrency = schemas.integer {
        minimum = 1;
        maximum = 1;
      };
      predecessor = imageIdentity;
      retention-expires-at-millis = schemas.integer {
        minimum = 1;
        maximum = 9007199254740991;
      };
      strategy = schemas.enum ["single-host-ab-v1"];
    };
    optional = [];
  };
  rolloutObservation = schemas.record {
    fields = {
      active-image = schemas.enum ["candidate" "predecessor"];
      candidate-prepared = schemas.boolean;
      drained = schemas.boolean;
      healthy = schemas.optional schemas.boolean;
      lease-expires-at-millis = schemas.optional (schemas.integer {
        minimum = 1;
        maximum = 9007199254740991;
      });
      phase = schemas.enum [
        "booted"
        "drained"
        "fallback-retained"
        "healthy-retained"
        "prepared"
        "retained"
        "retired"
        "selected"
      ];
      schema = schemas.enum ["aos.ability.ab-image-rollout-observation/v1"];
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
        healthy = output schemas.boolean "observation" "attempt";
      };
  in {
    operationFamily = {
      kind = "image-rollout";
      inherit action;
    };
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
  rolloutProvider = import ./providers/rollout/default.nix;

  abilityPackage = {
    requiredFeatures = ["ab-image-rollout-v1" "abilities-v1"];
    activationMode = "structured-effects";
    ownership = [[]];
    artifacts = [];
    requirements = {};
    exports = {
      rollout = {
        artifact = providerArtifact;
        requiredFeatures = ["ab-image-rollout-v1"];
        export = lib.abilities.define {
          interface = "aos.ab-image-rollout";
          abi = 1;
          requestSchema = schemas.boolean;
          configurationSchema = rolloutRequest;
          outputs.machine = output schemas.resourceReference "planning" "persistent";
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
          ownsResourceKinds = ["aos.ab-image-rollout"];
          compose = rolloutProvider.compose;
          transition = transitionTransform rolloutProvider.transition;
        };
      };
      rollout-effects = {
        artifact = rolloutRuntime;
        requiredFeatures = ["ab-image-rollout-v1"];
        export = lib.abilities.define {
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
          handler = "native-ab-image-rollout-v1";
        };
      };
    };
    handlers.native-ab-image-rollout-v1 = {
      artifact = rolloutRuntime;
      entryPoint = "libexec/aos-ab-image-rollout-handler-v1";
      arguments = rolloutRequest;
      result = rolloutObservation;
    };
  };
in
  mkDerivation {
    pname = "ability-reference-image-rollout";
    version = "1.0.0";
    src = providerArtifact;
    inherit abilityPackage;

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
