# lib/testing/fleet-spec-check.nix — Regression guard for fleetSpecType.
#
# Exercises `lib/testing/fleet-spec.nix`'s submodule:
#   1. A minimal valid spec (one machine, no roles, no metadata)
#      evaluates cleanly.
#   2. Adding `roles = ["test-role"]` against a stub system that
#      declares that role evaluates cleanly.
#   3. Naming a non-existent role rejects at eval time — the per-machine
#      `enum` derived from `config.system.config.aos.roles` should
#      reject any name not in the system's role set.
#   4. Setting `instanceMetadata.config` to a malformed ignition fragment
#      (an unknown top-level key under `storage`) rejects at eval time
#      via the strict ignition format submodule.
#
# Runs via `nix-build -A checks.fleet-spec`.
{
  pkgs,
  lib,
}: let
  ignitionFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = false;
  };

  fleetSpec = import ./fleet-spec.nix {
    inherit lib ignitionFormat;
  };

  # Stub system attrset shaped like what `discoverSystems` produces.
  # Only `config.aos.roles` is actually consulted by `fleetSpecType`'s
  # role enum; the rest is here to prove the harness's structural
  # access path holds.
  stubSystem = {
    config = {
      aos.roles = {
        test-role = {enable = false;};
      };
    };
  };

  mkEval = spec:
    lib.evalModules {
      modules = [
        {
          options.spec = lib.mkOption {type = fleetSpec.fleetSpecType;};
        }
        {config.spec = spec;}
      ];
    };

  tryEval = spec:
    builtins.tryEval (
      builtins.deepSeq (mkEval spec).config.spec null
    );

  # 1. Minimal spec evaluates.
  minimalOk =
    (tryEval {
      name = "minimal";
      machines.solo = {system = stubSystem;};
      testScript = "true";
    })
    .success;

  # 2. Roles against a system that declares them evaluates.
  rolesOk =
    (tryEval {
      name = "roles";
      machines.solo = {
        system = stubSystem;
        roles = ["test-role"];
      };
      testScript = "true";
    })
    .success;

  # 3. Bogus role name fails.
  bogusRoleRejected =
    !(tryEval {
      name = "bogus-role";
      machines.solo = {
        system = stubSystem;
        roles = ["does-not-exist"];
      };
      testScript = "true";
    })
    .success;

  # 4. Malformed ignition (unknown key) fails via the strict format.
  malformedIgnitionRejected =
    !(tryEval {
      name = "malformed";
      machines.solo = {
        system = stubSystem;
        instanceMetadata = {
          format = "ignition";
          config = {
            ignition.version = "3.5.0";
            storage.this-key-does-not-exist = 42;
          };
        };
      };
      testScript = "true";
    })
    .success;

  allOk =
    lib.throwIfNot minimalOk
    "fleet-spec: minimal valid spec failed to evaluate"
    (lib.throwIfNot rolesOk
      "fleet-spec: spec with declared role failed to evaluate"
      (lib.throwIfNot bogusRoleRejected
        "fleet-spec: spec with undeclared role should be rejected"
        (lib.throwIfNot malformedIgnitionRejected
          "fleet-spec: spec with malformed ignition fragment should be rejected"
          true)));
in
  pkgs.mkDerivation {
    pname = "fleet-spec-check";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : ${builtins.toString allOk}
          echo "==> fleet-spec regression check"
          echo "  minimal spec evaluates: OK"
          echo "  spec with declared role evaluates: OK"
          echo "  spec with undeclared role rejected: OK"
          echo "  spec with malformed ignition rejected: OK"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Regression guard for lib/testing/fleet-spec.nix";
  }
