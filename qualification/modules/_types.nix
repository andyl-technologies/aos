##! Closed data contracts shared by qualification feature modules.
{lib}: let
  option = type: description: lib.mkOption {inherit type description;};
  text = option lib.types.str;
  strings = option (lib.types.listOf lib.types.str);
  positive = lib.types.addCheck lib.types.int (value: value > 0);
  natural = lib.types.addCheck lib.types.int (value: value >= 0);
  environments = import ./_environment-types.nix {inherit lib;};
  closed = options:
    lib.types.submodule {
      inherit options;
      config._module.strict = true;
    };
in {
  inherit positive natural closed option text strings environments;
  requirement = closed {
    phase = option (lib.types.enum ["build" "staging" "rollout" "complete"]) "Release hold point requiring this evidence.";
    scope = option (lib.types.enum ["release" "packages" "images" "containers"]) "Artifact population expanded into cases.";
    method = (option (lib.types.enum ["automated" "operator"]) "Source of the observation.") // {default = "automated";};
    production_only = (option lib.types.bool "Requires the claim only for main-registry release classes.") // {default = false;};
    checks = strings "Acceptance conditions required in every observation.";
    regressions = (strings "Source regression gates; these do not replace release execution.") // {default = [];};
    invalidated_by = (strings "Identities whose change invalidates evidence.") // {default = ["subject" "policy" "executor" "environment"];};
    measurements =
      (option (lib.types.attrsOf (closed {
        minimum = option natural "Inclusive measured lower bound.";
        maximum = (option (lib.types.nullOr natural) "Inclusive upper bound; zero forbids observed failures.") // {default = null;};
      })) "Numeric acceptance bounds enforced by the coordinator.")
      // {default = {};};
  };
  target = closed {
    platform = option (lib.types.enum ["x86_64-linux" "aarch64-linux"]) "Execution architecture and operating system.";
    kind = option (lib.types.enum ["image" "container"]) "Release artifact kind.";
    required = (option lib.types.bool "Requires the target artifact in every release.") // {default = true;};
    environment = option environments.profile "Typed compatibility scope and execution topology.";
  };
  threshold = closed {
    soak_seconds = option positive "Minimum measured workload observation duration.";
    exercise_max_age_seconds = option positive "Maximum age of operational evidence.";
    require_independent_review = option lib.types.bool "Requires independent signed review.";
    require_complete_matrix = option lib.types.bool "Rejects blocked package/platform cells.";
  };
  packageRule = closed {
    role = option (lib.types.enum ["general-catalog" "qualified-workload" "system-integrity"]) "Functional consequences and inherited dependency obligations.";
    inherit_dependency_obligations = (option lib.types.bool "Preserves obligations inherited through runtime dependencies.") // {default = true;};
  };
  claim = closed {
    target = text "Target defining the exact compatibility scope.";
    requirements = strings "Functional requirements included in this claim.";
    minimum_assurance = option (lib.types.enum ["A1" "A2" "A3"]) "Minimum evidence strength; achieved assurance is derived from observations.";
    phase = option (lib.types.enum ["staging" "complete"]) "Admission hold point for the claim.";
    blocks_release = option lib.types.bool "Rejects admission when the claim is missing or unsuccessful.";
  };
}
