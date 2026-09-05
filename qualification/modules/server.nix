##! Defines the shared headless-system promises and class-dependent acceptance floors.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification;
  types = import ./_types.nix {inherit lib;};
  minimumSoak = {
    edge = 86400;
    candidate = 604800;
    stable = 1209600;
    emergency = 1209600;
  };
in {
  options.qualification = {
    id = types.text "Reviewed contract identity.";
    promises = types.strings "Functional obligations of the shared system contract.";
    exclusions = types.strings "Explicit boundaries of the contract.";
    thresholds = lib.mkOption {
      type = lib.types.attrsOf types.threshold;
      description = "Release-class observation and review policy.";
    };
  };
  config.qualification = {
    id = "aos-system-v2";
    promises = [
      "Install authenticated public artifacts and provision a persistent headless server."
      "Configure users, SSH, DNS, time, DHCP, and single-address static networking."
      "Install, change versions, remove, and recover machine-wide package generations."
      "Activate and roll back host configuration with transaction-bound evidence."
      "Update the preceding accepted image, recover or roll back, and update again."
      "Preserve committed workload data within the declared storage and migration contract."
      "Keep update storage bounded and fail safely when resources are exhausted."
      "Run nginx HTTP/TLS and a persistent container workload on the reference targets."
    ];
    exclusions = [
      "No implicit qualification of other hardware, hypervisors, clouds, or container runtimes."
      "No SELinux enforcement claim until labeled-root and enforcing-policy gates pass."
      "No automatic reversal of application data migrations through image rollback."
      "No stock unprivileged per-user package mutation contract."
      "No uptime SLA or failure-rate inference from a finite qualification campaign."
    ];
    thresholds = {
      candidate = {
        exercise_max_age_seconds = 2592000;
        require_complete_matrix = false;
        require_independent_review = true;
        soak_seconds = 604800;
      };
      edge = {
        exercise_max_age_seconds = 2592000;
        require_complete_matrix = false;
        require_independent_review = false;
        soak_seconds = 86400;
      };
      emergency = {
        exercise_max_age_seconds = 2592000;
        require_complete_matrix = true;
        require_independent_review = true;
        soak_seconds = 1209600;
      };
      stable = {
        exercise_max_age_seconds = 2592000;
        require_complete_matrix = true;
        require_independent_review = true;
        soak_seconds = 1209600;
      };
    };
    assertions = [
      {
        assertion =
          builtins.attrNames cfg.thresholds
          == builtins.attrNames minimumSoak
          && builtins.all (name: let
            threshold = cfg.thresholds.${name};
          in
            threshold.soak_seconds
            >= minimumSoak.${name}
            && threshold.exercise_max_age_seconds <= 2592000
            && (name == "edge" || threshold.require_independent_review)
            && (!(builtins.elem name ["stable" "emergency"]) || threshold.require_complete_matrix))
          (builtins.attrNames minimumSoak);
        message = "Release classes must preserve observation, freshness, review and matrix floors.";
      }
    ];
  };
}
