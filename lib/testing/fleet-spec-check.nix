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
#   5. Image-boot firmware seed/export fields evaluate cleanly.
#   6. Both firmware fields reject direct-kernel machines.
#   7. Firmware export rejects a machine name that is unsafe as a basename.
#
# Runs via `nix-build -A checks.fleet-spec`.
{
  pkgs,
  lib,
}: let
  fleetSpec = import ./fleet-spec.nix {inherit lib pkgs;};
  fleetHarness = import ./fleet.nix {inherit lib pkgs;};

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

  tryFirmwareValidation = machine:
    builtins.tryEval (
      builtins.deepSeq (fleetHarness.validateFirmwareVarsMachine machine) null
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

  # 5. Image machines accept an immutable firmware-vars seed and export flag.
  imageFirmwareOptionsOk =
    (tryEval {
      name = "firmware-options";
      machines.solo = {
        system = stubSystem;
        bootMode = "image";
        firmwareVars = "/nix/store/example-OVMF_VARS.fd";
        exportFirmwareVars = true;
      };
      testScript = "true";
    })
    .success;

  firmwareValidationControl =
    (tryFirmwareValidation {
      name = "safe_name";
      bootMode = "image";
      firmwareVars = "/nix/store/example-OVMF_VARS.fd";
      exportFirmwareVars = true;
    })
    .success;

  # 6. The harness rejects image-only fields on direct-kernel machines before
  # it tries to inspect the stub system's build products.
  kernelFirmwareSeedRejected =
    !(tryFirmwareValidation {
      name = "solo";
      bootMode = "kernel";
      firmwareVars = "/nix/store/example-OVMF_VARS.fd";
      exportFirmwareVars = false;
    })
    .success;
  kernelFirmwareExportRejected =
    !(tryFirmwareValidation {
      name = "solo";
      bootMode = "kernel";
      firmwareVars = null;
      exportFirmwareVars = true;
    })
    .success;

  # 7. Exported names become output basenames, so separators and traversal
  # components must fail during evaluation rather than reaching the shell.
  unsafeExportNameRejected =
    !(tryFirmwareValidation {
      name = "../escape";
      bootMode = "image";
      firmwareVars = null;
      exportFirmwareVars = true;
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
          (lib.throwIfNot imageFirmwareOptionsOk
            "fleet-spec: image firmware options failed to evaluate"
            (lib.throwIfNot firmwareValidationControl
              "fleet: valid firmware-vars options failed harness validation"
              (lib.throwIfNot kernelFirmwareSeedRejected
                "fleet: firmwareVars should be rejected for kernel boot"
                (lib.throwIfNot kernelFirmwareExportRejected
                  "fleet: firmware-vars export should be rejected for kernel boot"
                  (lib.throwIfNot unsafeExportNameRejected
                    "fleet: unsafe firmware-vars export name should be rejected"
                    true))))))));
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
          echo "  image firmware options evaluate: OK"
          echo "  valid firmware options pass harness validation: OK"
          echo "  kernel firmware seed rejected: OK"
          echo "  kernel firmware export rejected: OK"
          echo "  unsafe firmware export name rejected: OK"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Regression guard for lib/testing/fleet-spec.nix";
  }
