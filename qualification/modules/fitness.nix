##! Owns the fitness attestation kinds that prove the environment can recover.
#
# Fitness exercises run outside the release pipeline: machine-run checks
# weekly, operator-run exercises quarterly. Each exercise produces a signed,
# dated attestation carrying the identities it covered. Profiles reference a
# kind and a maximum age; the checks and bindings here define what an
# attestation of that kind must contain.
{
  config,
  lib,
  ...
}: let
  cfg = config.qualification.fitness;
  types = import ./_types.nix {inherit lib;};

  unique = values: builtins.length (lib.unique values) == builtins.length values;

  kinds = builtins.attrValues cfg;
in {
  options.qualification.fitness = lib.mkOption {
    type = lib.types.attrsOf types.fitnessKind;
    default = {};
    description = "Fitness attestation kinds keyed by kind.";
  };

  config.qualification = {
    fitness = {
      storage-restore = {
        method = "automated";
        bindings = ["tooling"];
        checks = ["independent-encrypted-backup" "restore-to-clean-environment" "offline-verification-of-restored-bundle"];
      };
      alert-delivery = {
        method = "automated";
        bindings = ["alert-config"];
        checks = ["failed-unit-alert-delivered" "acknowledged-by-on-call" "no-secret-material-in-alert"];
      };
      authority-recovery = {
        method = "operator";
        bindings = ["signer-roster"];
        checks = ["key-custody" "recover-encrypted-authority-backup" "test-signature-per-role-verifies"];
      };
      hub-restore = {
        method = "operator";
        bindings = ["surface" "hub-schema"];
        checks = ["isolated-hub-restore" "portable-database-export-import" "anonymous-readback-of-restored-deployment"];
      };
      key-rotation = {
        method = "operator";
        bindings = ["signer-roster" "surface"];
        checks = ["registry-key-rotation-trust-continuity" "unauthorized-replacement-rejected" "interrupted-publication-single-final-state"];
      };
    };

    assertions = [
      {
        assertion = builtins.all (kind: kind.checks != [] && unique kind.checks) kinds;
        message = "Fitness kinds require a non-empty list of distinct checks.";
      }
      {
        assertion = builtins.all (kind: kind.bindings != [] && unique kind.bindings) kinds;
        message = "Fitness kinds require a non-empty list of distinct bindings.";
      }
    ];
  };
}
