# lib/testing/fleet-spec-check.nix — Regression guard for fleetSpecType.
#
# Exercises `lib/testing/fleet-spec.nix`'s submodule:
#   1. A minimal valid spec (one machine, no roles, no metadata)
#      evaluates cleanly.
#   2. Adding `roles = ["test-role"]` against a stub system that
#      declares that role with `bundle = true` evaluates cleanly.
#   3. Naming a non-existent role rejects at eval time — the per-machine
#      `enum` derived from `config.system.config.aos.roles` (filtered
#      to `bundle = true` roles) should reject any name not in the
#      bundled set.
#   4. Setting `instanceMetadata.config` to a malformed ignition fragment
#      (an unknown top-level key under `storage`) rejects at eval time
#      via the strict ignition format submodule.
#   5. Naming a defined-but-unbundled role (`bundle = false`) rejects
#      at eval time — the enum filter must exclude unbundled roles,
#      otherwise a fleet spec could synthesise a merge entry pointing
#      at a fragment that won't exist on the running host.
#
# Runs via `nix-build -A checks.fleet-spec`.
{
  pkgs,
  lib,
}: let
  fleetSpec = import ./fleet-spec.nix {inherit lib pkgs;};

  # Stub system attrset shaped like what `discoverSystems` produces.
  # Only `config.aos.roles` is actually consulted by `fleetSpecType`'s
  # role enum; the rest is here to prove the harness's structural
  # access path holds.
  #
  # `test-role` is bundled (bundle = true) so it appears in the enum;
  # `unbundled-role` is defined but `bundle = false`, exercising the
  # enum filter — listing it in `roles = [...]` must be rejected.
  stubSystem = {
    config = {
      aos.roles = {
        test-role = {bundle = true;};
        unbundled-role = {bundle = false;};
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

  # 5. Defined-but-unbundled role (`bundle = false`) rejects — the
  # enum filter must exclude it. Without the filter this would
  # silently pass and the synthesised merge entry would dangle.
  unbundledRoleRejected =
    !(tryEval {
      name = "unbundled";
      machines.solo = {
        system = stubSystem;
        roles = ["unbundled-role"];
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
          (lib.throwIfNot unbundledRoleRejected
            "fleet-spec: spec listing a role with bundle = false should be rejected"
            true))));
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
          echo "  spec with unbundled role rejected: OK"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Regression guard for lib/testing/fleet-spec.nix";
  }
