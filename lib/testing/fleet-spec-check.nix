# lib/testing/fleet-spec-check.nix — Regression guard for fleetSpecType.
#
# Exercises `lib/testing/fleet-spec.nix`'s submodule:
#   1. A minimal valid spec (one machine, no roles/packages, no metadata)
#      evaluates cleanly.
#   2. Adding `roles = ["test-role"]` against a stub system that
#      declares that role with `bundle = true` evaluates cleanly.
#   3. Adding `packages = ["test-package"]` against a stub system that
#      declares that package with `bundle = true` evaluates cleanly.
#   4. Naming a non-existent role/package rejects at eval time — the
#      per-machine `enum` derived from `config.system.config.aos.roles`
#      and `.aos.packages` (filtered to `bundle = true`) should reject
#      any name not in the bundled set.
#   5. Setting `instanceMetadata.config` to a malformed ignition fragment
#      (an unknown top-level key under `storage`) rejects at eval time
#      via the strict ignition format submodule.
#   6. Naming a defined-but-unbundled role/package (`bundle = false`)
#      rejects at eval time — the enum filters must exclude unbundled
#      entries, otherwise a fleet spec could synthesise runtime
#      activation for artifacts that won't exist on the running host.
#
# Runs via `nix-build -A checks.fleet-spec`.
{
  pkgs,
  lib,
}: let
  fleetSpec = import ./fleet-spec.nix {inherit lib pkgs;};

  # Stub system attrset shaped like what `discoverSystems` produces.
  # Only `config.aos.roles` and `config.aos.packages` are consulted by
  # `fleetSpecType`'s role/package enums; the rest is here to prove the
  # harness's structural access path holds.
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
      aos.packages = {
        test-package = {bundle = true;};
        unbundled-package = {bundle = false;};
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

  # 3. Packages against a system that declares them evaluates.
  packagesOk =
    (tryEval {
      name = "packages";
      machines.solo = {
        system = stubSystem;
        packages = ["test-package"];
      };
      testScript = "true";
    })
    .success;

  # 4. Bogus role/package names fail.
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

  bogusPackageRejected =
    !(tryEval {
      name = "bogus-package";
      machines.solo = {
        system = stubSystem;
        packages = ["does-not-exist"];
      };
      testScript = "true";
    })
    .success;

  # 5. Malformed ignition (unknown key) fails via the strict format.
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

  # 6. Defined-but-unbundled entries (`bundle = false`) reject — the
  # enum filters must exclude them. Without the filters this would
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

  unbundledPackageRejected =
    !(tryEval {
      name = "unbundled-package";
      machines.solo = {
        system = stubSystem;
        packages = ["unbundled-package"];
      };
      testScript = "true";
    })
    .success;

  allOk =
    lib.throwIfNot minimalOk
    "fleet-spec: minimal valid spec failed to evaluate"
    (lib.throwIfNot rolesOk
      "fleet-spec: spec with declared role failed to evaluate"
      (lib.throwIfNot packagesOk
        "fleet-spec: spec with declared package failed to evaluate"
        (lib.throwIfNot bogusRoleRejected
          "fleet-spec: spec with undeclared role should be rejected"
          (lib.throwIfNot bogusPackageRejected
            "fleet-spec: spec with undeclared package should be rejected"
            (lib.throwIfNot malformedIgnitionRejected
              "fleet-spec: spec with malformed ignition fragment should be rejected"
              (lib.throwIfNot unbundledRoleRejected
                "fleet-spec: spec listing a role with bundle = false should be rejected"
                (lib.throwIfNot unbundledPackageRejected
                  "fleet-spec: spec listing a package with bundle = false should be rejected"
                  true)))))));
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
          echo "  spec with declared package evaluates: OK"
          echo "  spec with undeclared role rejected: OK"
          echo "  spec with undeclared package rejected: OK"
          echo "  spec with malformed ignition rejected: OK"
          echo "  spec with unbundled role rejected: OK"
          echo "  spec with unbundled package rejected: OK"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Regression guard for lib/testing/fleet-spec.nix";
  }
