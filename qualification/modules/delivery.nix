##! Owns delivery qualification requirements and their regression coverage.
{...}: {
  config.qualification.requirements = {
    build-integrity = {
      checks = ["source-and-contributor-authorization" "hermetic-build" "repeat-build" "complete-closure" "sbom-and-advisory-dispositions" "licenses-and-corresponding-source"];
      invalidated_by = ["subject" "policy" "executor" "environment"];
      method = "automated";
      phase = "build";
      production_only = false;
      regressions = ["checks.build.critical-pkgs" "checks.build.package-platform-support"];
      scope = "release";
    };
    staging-delivery = {
      checks = ["deployment-identity" "anonymous-package-and-image-consumption" "tuf-expiry-and-renewal" "interrupted-publication" "immutable-source-retention"];
      invalidated_by = ["subject" "policy" "executor" "environment"];
      method = "automated";
      phase = "staging";
      production_only = false;
      regressions = ["checks.fleet.native-hub-release-pipeline"];
      scope = "release";
    };
    rollout-health = {
      checks = ["production-deployment-identity" "exact-byte-promotion" "production-public-readback" "clean-client-consumption" "no-unresolved-integrity-or-recovery-failure"];
      invalidated_by = ["subject" "policy" "executor" "environment"];
      method = "automated";
      phase = "rollout";
      production_only = false;
      regressions = [];
      scope = "release";
    };
    rollout-observation = {
      checks = ["mixed-workload-soak" "operation-denominators" "stop-conditions-reviewed" "retention-confirmed" "operational-handoff"];
      invalidated_by = ["subject" "policy" "executor" "environment"];
      method = "automated";
      phase = "complete";
      production_only = false;
      regressions = [];
      scope = "release";
    };
  };
}
