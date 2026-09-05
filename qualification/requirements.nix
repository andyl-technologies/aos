##! Stable claims and executable/manual evidence required at each hold point.
let
  gate = id: phase: scope: checks: regressions: {
    inherit id phase scope checks regressions;
    method = "automated";
    production_only = false;
    invalidated_by = ["subject" "policy" "executor" "environment"];
  };
  exercise = id: checks:
    (gate id "staging" "release" checks [])
    // {method = "operator";};
in [
  (gate "build-integrity" "build" "release" [
    "source-and-contributor-authorization"
    "hermetic-build"
    "repeat-build"
    "complete-closure"
    "sbom-and-advisory-dispositions"
    "licenses-and-corresponding-source"
  ] ["checks.build.critical-pkgs" "checks.build.package-platform-support"])
  (gate "package-function" "staging" "packages" [
    "anonymous-download"
    "closure-verification"
    "functional-behavior"
    "dependency-obligations"
    "permissions-and-confinement"
  ] ["checks.fleet.apm-e2e"])
  (gate "image-installation" "staging" "images" [
    "anonymous-download-and-resume"
    "disk-format-equivalence"
    "uefi-boot"
    "provisioning"
    "host-configuration"
    "ssh-dns-time-network"
    "boot-integrity-and-encrypted-state"
    "no-fixture-authorities"
  ] ["checks.fleet.install-from-image" "checks.fleet.provisioning-boot"])
  (gate "image-lifecycle" "staging" "images" [
    "configuration-activation-and-rollback"
    "package-install-change-remove-recover"
    "nginx-http-tls"
    "persistent-workload"
    "reboot-persistence"
    "bounded-generation-retention"
    "disk-and-memory-pressure"
  ] ["checks.fleet.runtime-config-all"])
  (gate "image-update-recovery" "staging" "images" [
    "preceding-image-identity"
    "upgrade"
    "configuration-rebind"
    "boot-blessing"
    "interrupted-writes-and-reboots"
    "automatic-fallback"
    "explicit-rollback"
    "committed-data-preserved"
    "offline-recovery"
    "update-after-recovery"
  ] ["checks.fleet.system-image-rollback" "checks.fleet.boot-identity-fail-closed"])
  (gate "container-lifecycle" "staging" "containers" [
    "signed-index-and-platform-selection"
    "anonymous-pull"
    "start-stop-network"
    "persistent-state"
    "runtime-identity"
    "testing-or-production-profile"
  ] ["checks.containers.all" "checks.fleet.container-runtime" "checks.fleet.hub-oci"])
  (gate "staging-delivery" "staging" "release" [
    "deployment-identity"
    "anonymous-package-and-image-consumption"
    "tuf-expiry-and-renewal"
    "interrupted-publication"
    "exact-byte-promotion"
    "immutable-source-retention"
  ] ["checks.fleet.native-hub-release-pipeline"])
  (exercise "operator-recovery" [
    "key-custody"
    "independent-encrypted-backup"
    "restore-to-clean-environment"
    "registry-key-rotation"
    "alert-delivery"
    "abandoned-and-fix-forward-release"
  ])
  ((exercise "production-recovery" [
      "portable-hub-database-export-import"
      "isolated-hub-restore"
      "independent-authority-control"
      "compatibility-and-support-window"
    ])
    // {production_only = true;})
  (gate "rollout-health" "rollout" "release" [
    "production-deployment-identity"
    "production-public-readback"
    "clean-client-consumption"
    "no-unresolved-integrity-or-recovery-failure"
  ] [])
  (gate "rollout-observation" "complete" "release" [
    "mixed-workload-soak"
    "operation-denominators"
    "stop-conditions-reviewed"
    "retention-confirmed"
    "operational-handoff"
  ] [])
]
