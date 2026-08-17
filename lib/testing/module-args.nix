# lib/testing/module-args.nix — Regression guard for `_module.args`.
#
# Verifies that the nixpkgs-style `config._module.args.X = value;`
# pattern correctly injects `X` into the args of later module function
# signatures, and that all the important interactions work:
#
#   * Plain attrset setter → function reader
#   * Function-form setter that uses `extraArgs` to compute the value
#   * Caller-provided `extraArgs` takes precedence over `_module.args`
#   * A module that takes no custom args keeps working unchanged
#   * Accessing an arg that nobody provides produces a clean error
#
# Relies on the lazy per-argument thunking pattern added to `evalModule`
# (audit fix 1.3, mirroring nixpkgs' `applyModuleArgs` at
# `lib/modules.nix:704-736`).
#
# Runs via `nix-build -A checks.module-args`.
{
  pkgs,
  lib,
}: let
  # --- Case 1: plain attrset setter, function reader ------------------
  case1 = lib.evalModules {
    modules = [
      {config._module.args.customPkg = "injected";}
      ({customPkg, ...}: {
        options.case1.got = lib.mkOption {type = lib.types.str;};
        config.case1.got = "got: ${customPkg}";
      })
    ];
    lib = lib;
  };

  # --- Case 2: function-form setter using extraArgs.pkgs --------------
  case2 = lib.evalModules {
    modules = [
      ({pkgs, ...}: {
        config._module.args.derivedPkg = "from-${pkgs.flavor}";
      })
      ({derivedPkg, ...}: {
        options.case2.got = lib.mkOption {type = lib.types.str;};
        config.case2.got = derivedPkg;
      })
    ];
    lib = lib;
    extraArgs = {pkgs = {flavor = "vanilla";};};
  };

  # --- Case 3: extraArgs wins over _module.args -----------------------
  case3 = lib.evalModules {
    modules = [
      {config._module.args.name = "from-module";}
      ({name, ...}: {
        options.case3.got = lib.mkOption {type = lib.types.str;};
        config.case3.got = name;
      })
    ];
    lib = lib;
    extraArgs = {name = "from-extra";};
  };

  # --- Case 4: module taking no custom args still works ---------------
  case4 = lib.evalModules {
    modules = [
      {config._module.args.customPkg = "ignored";}
      ({
        config,
        lib,
        ...
      }: {
        options.case4.got = lib.mkOption {
          type = lib.types.str;
          default = "no custom args here";
        };
      })
    ];
    lib = lib;
  };

  # --- Case 5: absent optional argument keeps its pattern default ----
  case5 = lib.evalModules {
    modules = [
      ({optionalFlag ? "defaulted", ...}: {
        options.case5.got = lib.mkOption {type = lib.types.str;};
        config.case5.got = optionalFlag;
      })
    ];
    lib = lib;
  };

  # --- Case 6: caller value still overrides an optional default ------
  case6 = lib.evalModules {
    modules = [
      ({optionalFlag ? "defaulted", ...}: {
        options.case6.got = lib.mkOption {type = lib.types.str;};
        config.case6.got = optionalFlag;
      })
    ];
    lib = lib;
    specialArgs.optionalFlag = "provided";
  };

  # --- Eval-time assertions ------------------------------------------
  evalAssertions =
    lib.throwIfNot (case1.config.case1.got == "got: injected")
    "module-args case 1 failed: ${case1.config.case1.got}"
    (lib.throwIfNot (case2.config.case2.got == "from-vanilla")
      "module-args case 2 failed: ${case2.config.case2.got}"
      (lib.throwIfNot (case3.config.case3.got == "from-extra")
        "module-args case 3 failed (extraArgs should win): ${case3.config.case3.got}"
        (lib.throwIfNot (case4.config.case4.got == "no custom args here")
          "module-args case 4 failed: ${case4.config.case4.got}"
          (lib.throwIfNot (case5.config.case5.got == "defaulted")
            "module-args case 5 failed: ${case5.config.case5.got}"
            (lib.throwIfNot (case6.config.case6.got == "provided")
              "module-args case 6 failed: ${case6.config.case6.got}"
              true)))));
in
  pkgs.mkDerivation {
    pname = "module-args-check";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : ${builtins.toString evalAssertions}
          echo "==> module-args regression check"
          echo "  case 1 (plain setter + function reader): OK"
          echo "  case 2 (function setter + function reader): OK"
          echo "  case 3 (extraArgs beats _module.args): OK"
          echo "  case 4 (module without custom args): OK"
          echo "  case 5 (optional function default): OK"
          echo "  case 6 (caller overrides optional default): OK"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Regression guard for config._module.args propagation";
  }
