# lib/testing/fleet-spec-check.nix — Regression guard for fleetSpecType.
#
# Exercises `lib/testing/fleet-spec.nix`'s submodule:
#   1. A minimal valid spec (one machine, no packages, no metadata)
#      evaluates cleanly.
#   2. Adding `packages = ["test-package"]` against a stub system that
#      declares that package with `bundle = true` evaluates cleanly.
#   3. Naming a non-existent package rejects at eval time — the per-machine
#      `enum` derived from `config.system.config.aos.packages` (filtered to
#      `bundle = true`) should reject any name not in the bundled set.
#   4. Naming a defined-but-unbundled package (`bundle = false`)
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
  # Only `config.aos.packages` is consulted by `fleetSpecType`'s package enum;
  # the rest is here to prove the harness's structural access path holds.
  #
  # `test-package` is bundled (bundle = true) so it appears in the enum;
  # `unbundled-package` is defined but `bundle = false`, exercising the enum
  # filter.
  stubSystem = {
    config = {
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

  # 2. Packages against a system that declares them evaluates.
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

  # 3. Bogus package names fail.
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

  # 4. Defined-but-unbundled entries (`bundle = false`) reject — the
  # enum filters must exclude them.
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
    (lib.throwIfNot packagesOk
      "fleet-spec: spec with declared package failed to evaluate"
      (lib.throwIfNot bogusPackageRejected
        "fleet-spec: spec with undeclared package should be rejected"
        (lib.throwIfNot unbundledPackageRejected
          "fleet-spec: spec listing a package with bundle = false should be rejected"
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
          echo "  spec with declared package evaluates: OK"
          echo "  spec with undeclared package rejected: OK"
          echo "  spec with unbundled package rejected: OK"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Regression guard for lib/testing/fleet-spec.nix";
  }
