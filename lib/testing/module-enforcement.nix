# lib/testing/module-enforcement.nix — Regression guard for Phase 1-3
# lib additions: assertion/warning enforcement + mkEnableOption +
# mkPackageOption + types.pathInStore.
#
# Assertion enforcement lives at `system.build.toplevel` construction
# (Option B in the missing-features plan): a broken config is still
# inspectable via `config.*`, only building the toplevel fails. This
# test confirms both behaviours — that `builtins.tryEval` on the
# toplevel name catches the throw, and that reading unrelated config
# paths from the same broken system succeeds.
#
# mkEnableOption / mkPackageOption / types.pathInStore are covered by
# synthetic `lib.evalModules` invocations that exercise their defaults,
# merging, and type checks.
#
# Runs via `nix-build -A checks.module-enforcement`.
{
  pkgs,
  lib,
}: let
  aos = import ../../. {};

  # --- Assertion enforcement ------------------------------------------
  #
  # Build a broken server system with a failing assertion. The config
  # itself must still be inspectable (Option B semantics).
  brokenSystem = aos.mkSystem {
    modules = [
      ../../systems/server.nix
      {
        assertions = [
          {
            assertion = false;
            message = "REGRESSION-TEST: a deliberately failing assertion";
          }
        ];
      }
    ];
  };

  # Can we still read arbitrary config paths from the broken system?
  brokenConfigStillReadable = brokenSystem.config.aos.users.users.root.home == "/root";

  # Does forcing `system.build.toplevel.name` actually fire the throw?
  # `builtins.tryEval` catches it — if the throw is missing, the
  # regression is silently broken.
  brokenTryBuild = builtins.tryEval brokenSystem.config.system.build.toplevel.name;
  brokenBuildThrows = !brokenTryBuild.success;

  # Control: a well-formed system with passing assertions builds fine.
  healthySystem = aos.mkSystem {
    modules = [
      ../../systems/server.nix
      {
        assertions = [
          {
            assertion = true;
            message = "REGRESSION-TEST: this passes";
          }
        ];
      }
    ];
  };
  healthyTryBuild = builtins.tryEval healthySystem.config.system.build.toplevel.name;
  healthyBuildSucceeds = healthyTryBuild.success;

  # --- mkEnableOption -------------------------------------------------
  enableExplicitlySet =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.foo.enable = lib.mkEnableOption "foo";
        })
        {config.foo.enable = true;}
      ];
      lib = lib;
    })
    .config
    .foo
    .enable;

  enableDefaultsFalse =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.bar.enable = lib.mkEnableOption "bar";
        })
      ];
      lib = lib;
    })
    .config
    .bar
    .enable;

  # --- mkPackageOption ------------------------------------------------
  fakePkgs = {
    coreutils = {
      type = "derivation";
      outPath = "/nix/store/abc-coreutils-1.0";
      drvPath = "/nix/store/abc-coreutils-1.0.drv";
      name = "coreutils";
    };
  };

  packageOptDefaultName =
    (lib.evalModules {
      modules = [
        ({
          lib,
          pkgs,
          ...
        }: {
          options.cu = lib.mkPackageOption pkgs "coreutils" {};
        })
      ];
      lib = lib;
      extraArgs = {pkgs = fakePkgs;};
    })
    .config
    .cu
    .name;

  # --- types.pathInStore ----------------------------------------------
  pathInStoreAccepts = lib.types.pathInStore.check "/nix/store/abc-foo-1.0/bin/foo";
  pathInStoreRejectsHost = !lib.types.pathInStore.check "/etc/passwd";
  pathInStoreRejectsRelative = !lib.types.pathInStore.check "not-a-path";
  pathInStoreRejectsNumber = !lib.types.pathInStore.check 42;

  # --- Eval-time assertions for the test itself -----------------------
  evalAssertions =
    lib.throwIfNot brokenConfigStillReadable
    "module-enforcement: broken config should still be inspectable (Option B semantics)"
    (lib.throwIfNot brokenBuildThrows
      "module-enforcement: forcing system.build.toplevel on a broken config should throw"
      (lib.throwIfNot healthyBuildSucceeds
        "module-enforcement: a healthy config should build without issues"
        (lib.throwIfNot enableExplicitlySet
          "module-enforcement: mkEnableOption should accept user-provided true"
          (lib.throwIfNot (enableDefaultsFalse == false)
            "module-enforcement: mkEnableOption should default to false"
            (lib.throwIfNot (packageOptDefaultName == "coreutils")
              "module-enforcement: mkPackageOption should look up default from pkgs"
              (lib.throwIfNot pathInStoreAccepts
                "module-enforcement: pathInStore should accept /nix/store/* paths"
                (lib.throwIfNot pathInStoreRejectsHost
                  "module-enforcement: pathInStore should reject /etc/passwd"
                  (lib.throwIfNot pathInStoreRejectsRelative
                    "module-enforcement: pathInStore should reject 'not-a-path'"
                    (lib.throwIfNot pathInStoreRejectsNumber
                      "module-enforcement: pathInStore should reject non-strings/paths"
                      true)))))))));
in
  pkgs.mkDerivation {
    pname = "module-enforcement-check";
    version = "0";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          : ${builtins.toString evalAssertions}
          echo "==> module-enforcement regression check"
          echo "  assertion enforcement — broken config still inspectable: OK"
          echo "  assertion enforcement — broken build throws: OK"
          echo "  assertion enforcement — healthy build succeeds: OK"
          echo "  mkEnableOption — explicit value: OK"
          echo "  mkEnableOption — defaults to false: OK"
          echo "  mkPackageOption — default from pkgs: OK"
          echo "  types.pathInStore — accepts store paths: OK"
          echo "  types.pathInStore — rejects host paths: OK"
          echo "  types.pathInStore — rejects non-paths: OK"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Regression guard for Phase 1-3 lib additions";
  }
