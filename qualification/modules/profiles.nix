##! Owns the named obligation bundles that destinations select and their floors.
#
# A profile decides what a release must prove before one destination may be
# published: which release/package requirements apply, which target claims are
# selected, how long observation must last, how many reviewers must sign, and
# which fitness attestations must be fresh. Destinations pick a profile by name,
# so the floors below are enforced here once rather than per destination.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification;
  types = import ./_types.nix {inherit lib;};

  # One channel is 256 partitions; a single ring that reaches all of them at
  # once is the schedule for destinations that do not stage their rollout.
  allPartitions = [
    {
      partitions = 256;
      observe_seconds = 0;
    }
  ];

  # A qualified claim is an A3 observation, so a profile that asks for it must
  # observe for at least one day even when an incident override relaxes soak.
  minimumQualifiedSoak = 86400;

  # Fitness attestation freshness: machine-run exercises weekly with a two-week
  # allowance, operator-run exercises quarterly.
  weekly.max_age_seconds = 1209600;
  quarterly.max_age_seconds = 7776000;

  # Image and container obligations enter through claims, not through profile
  # requirements, so the requirement list only carries release/package scopes.
  profileScopes = ["release" "packages"];

  # Native release operations remain obligations of each functional profile.
  nativeRequirements = [
    "ability-native-activation"
    "ability-native-kubernetes"
    "ability-native-recovery"
    "ability-crucible-baseline"
    "ability-native-adapter-matrix"
  ];

  knownRequirement = id:
    builtins.hasAttr id cfg.requirements && builtins.elem cfg.requirements.${id}.scope profileScopes;

  qualifiedFloor = profile:
    builtins.elem "rollout-observation" profile.requirements && profile.soak_seconds >= minimumQualifiedSoak;

  strictlyIncreasing = rings:
    builtins.all (index: (builtins.elemAt rings index).partitions < (builtins.elemAt rings (index + 1)).partitions)
    (lib.range 0 (builtins.length rings - 2));

  validRings = rings: rings != [] && strictlyIncreasing rings && (lib.last rings).partitions == 256;

  declaredFitness = profile: builtins.all (kind: builtins.hasAttr kind cfg.fitness) (builtins.attrNames profile.fitness);

  profiles = builtins.attrValues cfg.profiles;
in {
  options.qualification.profiles = lib.mkOption {
    type = lib.types.attrsOf types.profile;
    default = {};
    description = "Named obligation bundles selected by destinations.";
  };

  config.qualification = {
    profiles = {
      build = {
        description = "Reproducible, authorized build of the complete closure.";
        requirements = ["build-integrity"];
        claims = "none";
        change_scoped = false;
        soak_seconds = 0;
        review_threshold = 0;
        require_complete_matrix = false;
        review_registry_transaction = false;
        fitness = {};
        rollout.rings = allPartitions;
        override = {
          soak_seconds = false;
          rings = false;
        };
      };
      smoke = {
        description = "Automated exact-byte functional checks on the changed targets.";
        requirements = ["build-integrity" "staging-delivery" "package-function"] ++ nativeRequirements;
        claims = "functional";
        change_scoped = true;
        soak_seconds = 0;
        review_threshold = 0;
        require_complete_matrix = false;
        review_registry_transaction = false;
        fitness = {};
        rollout.rings = allPartitions;
        override = {
          soak_seconds = false;
          rings = false;
        };
      };
      functional = {
        description = "Reviewed functional qualification of every target with fresh environment fitness.";
        requirements = ["build-integrity" "staging-delivery" "package-function" "rollout-health"] ++ nativeRequirements;
        claims = "functional";
        change_scoped = false;
        soak_seconds = 0;
        review_threshold = 1;
        require_complete_matrix = false;
        review_registry_transaction = true;
        fitness = {
          storage-restore = weekly;
          alert-delivery = weekly;
          authority-recovery = quarterly;
          hub-restore = quarterly;
        };
        rollout.rings = allPartitions;
        override = {
          soak_seconds = false;
          rings = false;
        };
      };
      soak = {
        description = "Complete-matrix qualification with a week of observation and staged rollout.";
        requirements = ["build-integrity" "staging-delivery" "package-function" "rollout-health" "rollout-observation"] ++ nativeRequirements;
        claims = "qualified";
        change_scoped = false;
        soak_seconds = 604800;
        review_threshold = 1;
        require_complete_matrix = true;
        review_registry_transaction = true;
        fitness = {
          storage-restore = weekly;
          alert-delivery = weekly;
          authority-recovery = quarterly;
          hub-restore = quarterly;
          key-rotation = quarterly;
        };
        rollout.rings = [
          {
            partitions = 4;
            observe_seconds = 86400;
          }
          {
            partitions = 32;
            observe_seconds = 86400;
          }
          {
            partitions = 128;
            observe_seconds = 172800;
          }
          {
            partitions = 256;
            observe_seconds = 0;
          }
        ];
        # Emergency releases are planned as signed overrides of this profile.
        override = {
          soak_seconds = true;
          rings = true;
        };
      };
    };

    assertions = [
      {
        assertion = builtins.all (profile: profile.claims == "none" || builtins.all (id: builtins.elem id profile.requirements) nativeRequirements) profiles;
        message = "Functional profiles must retain native ability qualification requirements.";
      }
      {
        assertion = builtins.all (profile: builtins.elem "build-integrity" profile.requirements) profiles;
        message = "Every profile requires build-integrity.";
      }
      {
        assertion = builtins.all (profile: builtins.all knownRequirement profile.requirements) profiles;
        message = "Profile requirements must name known release- or package-scoped requirements.";
      }
      {
        assertion = builtins.all (profile: profile.claims != "qualified" || qualifiedFloor profile) profiles;
        message = "Qualified claims require rollout-observation and at least one day of soak.";
      }
      {
        # The shipped soak profile is the only qualified destination policy;
        # overriding it may not remove the floor that A3 observation relies on.
        assertion = !(cfg.profiles ? soak) || cfg.profiles.soak.soak_seconds >= minimumQualifiedSoak;
        message = "The soak profile must observe for at least one day.";
      }
      {
        assertion = builtins.all (profile: validRings profile.rollout.rings) profiles;
        message = "Rollout rings must be strictly increasing and end at all 256 partitions.";
      }
      {
        assertion = builtins.all declaredFitness profiles;
        message = "Profile fitness requirements must name declared fitness kinds.";
      }
    ];
  };
}
