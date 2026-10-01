##! Closed data contracts shared by qualification feature modules.
{lib}: let
  option = type: description: lib.mkOption {inherit type description;};
  text = option lib.types.str;
  strings = option (lib.types.listOf lib.types.str);
  positive = lib.types.addCheck lib.types.int (value: value > 0);
  natural = lib.types.addCheck lib.types.int (value: value >= 0);
  # A channel has 256 partitions; a ring names how many are reached so far.
  partitionCount = lib.types.addCheck lib.types.int (value: value >= 1 && value <= 256);
  surface = lib.types.enum ["staging" "production"];
  # Binding identities a fitness attestation may carry; see the contract design.
  fitnessBinding = lib.types.enum ["surface" "hub-schema" "signer-roster" "tooling" "alert-config"];
  environments = import ./_environment-types.nix {inherit lib;};
  closed = options:
    lib.types.submodule {
      inherit options;
      config._module.strict = true;
    };
  ring = closed {
    partitions = option partitionCount "Cumulative channel partitions reached by this ring; the last ring reaches 256.";
    observe_seconds = option natural "Minimum observation window before the next ring may advance.";
  };
in {
  inherit positive natural closed option text strings environments surface ring;
  requirement = closed {
    phase = option (lib.types.enum ["build" "staging" "rollout" "complete"]) "Release hold point requiring this evidence.";
    scope = option (lib.types.enum ["release" "packages" "images" "containers"]) "Artifact population expanded into cases.";
    method = (option (lib.types.enum ["automated" "operator"]) "Source of the observation.") // {default = "automated";};
    production_only = (option lib.types.bool "Requires this native operation only for production-registry destinations.") // {default = false;};
    checks = strings "Acceptance conditions required in every observation.";
    regressions = (strings "Source regression gates; these do not replace release execution.") // {default = [];};
    invalidated_by = (strings "Identities whose change invalidates evidence.") // {default = ["subject" "policy" "executor" "environment"];};
    native_operation_spec =
      (option (lib.types.nullOr lib.types.attrs) "Exact independently scoped native operation cohorts required by this requirement.")
      // {default = null;};
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
  profile = closed {
    description = text "Human-readable summary of the obligations this profile bundles.";
    requirements = strings "Release- and package-scoped requirement identities required at their own phase.";
    claims = option (lib.types.enum ["none" "functional" "qualified"]) "Target claim selection: functional selects A2 staging claims, qualified adds A3 complete claims.";
    change_scoped = (option lib.types.bool "Applies image, container and package obligations only to targets changed relative to the predecessor.") // {default = false;};
    soak_seconds = option natural "Minimum observed window for A3 claims and rollout observation.";
    review_threshold = option natural "Distinct release-evidence reviewer signatures required over the staging report.";
    require_complete_matrix = (option lib.types.bool "Rejects blocked package/platform cells.") // {default = false;};
    review_registry_transaction = (option lib.types.bool "Requires operator acceptance of the isolated registry transaction before finalization.") // {default = false;};
    fitness =
      (option (lib.types.attrsOf (closed {
        max_age_seconds = option positive "Maximum age of the fitness attestation at admission.";
      })) "Fitness attestation kinds required at admission, keyed by kind.")
      // {default = {};};
    rollout =
      (option (closed {
        rings = option (lib.types.listOf ring) "Ordered cumulative rollout rings.";
      }) "Channel rollout schedule.")
      // {
        default = {
          rings = [
            {
              partitions = 256;
              observe_seconds = 0;
            }
          ];
        };
      };
    override =
      (option (closed {
        soak_seconds = option lib.types.bool "Permits a signed override to relax the soak window.";
        rings = option lib.types.bool "Permits a signed override to relax the rollout rings.";
      }) "Fields a signed profile override may relax.")
      // {
        default = {
          soak_seconds = false;
          rings = false;
        };
      };
  };
  destination = closed {
    surface = option surface "Publication surface role receiving the release.";
    registry_tier = option (lib.types.enum ["testing" "production"]) "Registry tier the destination belongs to.";
    channel = option (lib.types.enum ["edge" "candidate" "stable"]) "Channel kind; per-train channels map to their kind.";
    profile = text "Profile whose obligations gate publication to this destination.";
    after = (option (lib.types.listOf surface) "Surface roles that must already hold a published admission for the same release.") // {default = [];};
  };
  fitnessKind = closed {
    method = option (lib.types.enum ["automated" "operator"]) "Source of the attestation.";
    bindings = option (lib.types.listOf fitnessBinding) "Identities the attestation carries and that must match live values at admission.";
    checks = strings "Checks every attestation of this kind must report as passed.";
  };
  packageRule = closed {
    role = option (lib.types.enum ["general-catalog" "qualified-workload" "system-integrity"]) "Functional consequences and inherited dependency obligations.";
    inherit_dependency_obligations = (option lib.types.bool "Preserves obligations inherited through runtime dependencies.") // {default = true;};
    execution =
      (option (lib.types.nullOr (closed {
        kind = option (lib.types.enum ["recovery-image" "k3s-fleet"]) "Special execution environment required by this package.";
        system_variant = text "System image variant carrying the package.";
        topology = (option (lib.types.nullOr (lib.types.enum ["combined-worker" "control-plane-worker"])) "K3s roles whose exact packages and workload container enter the case subjects.") // {default = null;};
      })) "Image execution required to prove this package's behavior.")
      // {default = null;};
  };
  claim = closed {
    target = text "Target defining the exact compatibility scope.";
    requirements = strings "Functional requirements included in this claim.";
    minimum_assurance = option (lib.types.enum ["A1" "A2" "A3"]) "Minimum evidence strength; achieved assurance is derived from observations.";
    phase = option (lib.types.enum ["staging" "complete"]) "Admission hold point for the claim.";
    blocks_release = option lib.types.bool "Rejects admission when the claim is missing or unsuccessful.";
  };
}
