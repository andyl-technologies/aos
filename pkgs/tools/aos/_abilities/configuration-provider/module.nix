##! Native qualified image rollout operation owned by the OS package runtime.
{
  lib,
  config,
  package,
  ...
}: let
  option = type: description: lib.mkOption {inherit type description;};
  text = lib.types.str;
  imageOptions =
    lib.genAttrs ["toplevel" "boot-artifact-contract" "executor" "state-format"]
    (name: option text "Exact admitted image ${name}.");
  rolloutOptions = {
    predecessor = option (lib.types.submodule {options = imageOptions;}) "Authenticated currently running image.";
    candidate = option (lib.types.submodule {options = imageOptions;}) "Authenticated prepared candidate image.";
    retention-expires-at-millis = option lib.types.ints.unsigned "Restart-stable deadline retaining both images.";
  };
  executable = lib.types.submodule {
    options = {
      path = option text "Exact retained immutable executable.";
      arguments = lib.mkOption {
        type = lib.types.listOf text;
        default = [];
        description = "Ordered arguments of the selected executable.";
      };
    };
  };
  cfg = config.aos.imageRollout;
  request =
    if cfg.requests == []
    then null
    else lib.last cfg.requests;
  requestType = lib.types.submodule {
    options = {
      rollout = option (lib.types.submodule {options = rolloutOptions;}) "Exact authored image transition request.";
      qualified = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Require drain, boot health, and fallback qualification.";
      };
      restart = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Request a reboot after durable native selection.";
      };
    };
  };
  resultOptions = outcomes: {
    rollout = option (lib.types.submodule {options = rolloutOptions;}) "Retained authenticated rollout identity.";
    outcome = option (lib.types.enum outcomes) "Observed image transition outcome.";
    retentionDirectory = option text "OS-owned durable image transition receipt and closure roots.";
  };
  program =
    package.packageRuntime
    // {
      meta = (package.packageRuntime.meta or {}) // {mainProgram = "aos-image-rollout-provider";};
    };
in {
  options.aos.imageRollout = {
    activationAfter = lib.mkOption {
      type = lib.types.listOf lib.types.effectOutput;
      default = [];
      extensible = true;
      description = "Native prerequisites ordered before image transitions; these references do not change transition inputs.";
    };
    platformExecutable = lib.mkOption {
      type = lib.types.nullOr lib.types.pathInStore;
      default = config.aos.boot.imageRolloutPlatformExecutable or null;
      extensible = true;
      description = "Exact retained boot platform implementation selected for image transitions.";
    };
    drain = lib.mkOption {
      type = lib.types.nullOr executable;
      default = null;
      extensible = true;
      description = "Explicit site workload drain program.";
    };
    drainObservation = lib.mkOption {
      type = lib.types.nullOr executable;
      default = null;
      extensible = true;
      description = "Explicit read-only proof of completed interrupted workload drain.";
    };
    requests = lib.mkOption {
      type = lib.types.listOf requestType;
      default = [];
      extensible = true;
      description = "Ordered authored image requests; the latest request selects the desired transition.";
    };
    retiredRequests = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {options = rolloutOptions;});
      default = [];
      extensible = true;
      description = "Explicit expired image leases submitted for authenticated physical retirement.";
    };
    retirementEffects = lib.mkOption {
      type = lib.types.attrsOf text;
      readOnly = true;
      internal = true;
      description = "Declaration-derived retirement effect identities indexed by exact request digest.";
    };
    selectedEffect = lib.mkOption {
      type = lib.types.nullOr text;
      readOnly = true;
      internal = true;
      description = "Declaration-derived native image transition effect identity.";
    };
  };
  config.aos.imageRollout.retirementEffects = lib.listToAttrs (map (rollout: let
    key = builtins.hashString "sha256" (builtins.toJSON rollout);
  in {
    name = key;
    value = builtins.hashString "sha256" (builtins.toJSON config.aos.abilities.imageRetirement.operations.ensure.effects.${key}.outputs.rollout.identity);
  }) cfg.retiredRequests);
  config.aos.abilities.imageRetirement.operations.ensure = {
    input.options = {
      rollout = option (lib.types.submodule {options = rolloutOptions;}) "Exact committed lease being explicitly retired.";
      platformExecutable = option text "Exact retained boot platform transport.";
      retirement = lib.mkOption {type = lib.types.enum [true]; default = true; description = "Performs expired lease retirement rather than selection.";};
    };
    result.options = resultOptions ["retired"];
    handler.program = program;
    effects = lib.listToAttrs (map (rollout: {
      name = builtins.hashString "sha256" (builtins.toJSON rollout);
      value = {
        lifetime = "persistent";
        after = cfg.activationAfter;
        input = {inherit rollout; inherit (cfg) platformExecutable; retirement = true;};
      };
    }) cfg.retiredRequests);
  };
  config.aos.imageRollout.selectedEffect =
    if request == null
    then null
    else
      builtins.hashString "sha256" (builtins.toJSON (
        if request.qualified
        then config.aos.abilities.imageRollout.operations.ensure.effects.qualified.outputs.rollout.identity
        else config.aos.abilities.imageSelection.operations.ensure.effects.selected.outputs.rollout.identity
      ));
  config.aos.abilities.imageRollout.operations.ensure = {
    input.options = {
      rollout = option (lib.types.submodule {options = rolloutOptions;}) "Exact restart-stable image rollout identity.";
      platformExecutable = option text "Admitted OS boot platform transport executable.";
      drain = option executable "Required workload drain implementation; no implicit no-op is provided.";
      drainObservation = option executable "Read-only interrupted-drain observation: zero proves completion, one leaves outcome uncertain.";
    };
    result.options = resultOptions ["candidate-healthy" "predecessor-fallback"];
    effects = lib.mkIf (request != null && request.qualified) {
      # A historical boot lease expires through explicit retirement, never source disappearance.
      qualified.lifetime = "persistent";
      qualified.after = cfg.activationAfter;
      qualified.input = {
        inherit (request) rollout;
        inherit (cfg) platformExecutable drain drainObservation;
      };
    };
    handler.program = program;
    description = "Drains workloads, selects and observes boot, assesses health, and preserves fallback with durable per-phase recovery.";
  };
  config.aos.abilities.imageSelection.operations.ensure = {
    input.options = {
      rollout = option (lib.types.submodule {options = rolloutOptions;}) "Exact unqualified image selection identity.";
      platformExecutable = option text "Exact retained boot platform transport.";
      qualified = lib.mkOption {
        type = lib.types.enum [false];
        default = false;
        description = "Ordinary image selection does not claim qualified health.";
      };
      restart = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Request reboot after native selection.";
      };
    };
    result.options = resultOptions ["selected"];
    handler.program = program;
    effects = lib.mkIf (request != null && !request.qualified) {
      selected.lifetime = "persistent";
      selected.after = cfg.activationAfter;
      selected.input = {
        inherit (request) rollout restart;
        inherit (cfg) platformExecutable;
      };
    };
  };
}
