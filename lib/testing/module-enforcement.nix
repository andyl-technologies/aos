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

  # --- Contributable option surface -----------------------------------
  #
  # An owner marks the curated extension points `contributable = true` and
  # leaves `enable` / globals owner-only (the default). The marker is a pure
  # declaration field — it must not perturb the merged value — and is
  # surfaced via `result._optionDecls` / `lib.contributableSurface`.
  f3bEval = lib.evalModules {
    modules = [
      ({lib, ...}: {
        options.nginx.enable = lib.mkOption {
          type = lib.types.bool;
          default = false;
        };
        options.nginx.virtualHosts = lib.mkOption {
          type = lib.types.attrsOf (lib.types.submodule {
            options.root = lib.mkOption {
              type = lib.types.str;
              default = "/";
            };
          });
          default = {};
          contributable = true;
        };
      })
      {config.nginx.enable = true;}
    ];
    lib = lib;
  };
  f3bSurfacePaths = builtins.map (d: d.pathStr) (lib.contributableSurface f3bEval);
  # exactly the marked extension point is contributable
  f3bSurfaceIsVirtualHosts = f3bSurfacePaths == ["nginx.virtualHosts"];
  # the marker did not change the merged value
  f3bValueUnperturbed = f3bEval.config.nginx.enable == true;

  # --- Operator priority-75 band --------------------------------------
  #
  # A bare def from a resolver-supplied `operatorModules` member is lifted to
  # tier 75 and beats a normal package contribution (tier 100), regardless of
  # module order. With no `operatorModules` the lift never fires (no-op).
  opDecl = {lib, ...}: {
    options.svc.x = lib.mkOption {
      type = lib.types.str;
      default = "d";
    };
  };
  operatorWins =
    (lib.evalModules {
      modules = [
        opDecl
        {config.svc.x = "from-package";}
      ];
      operatorModules = [{config.svc.x = "from-operator";}];
      lib = lib;
    })
    .config
    .svc
    .x
    == "from-operator";
  # No `operatorModules` ⇒ identical to before: last package def wins (lastValue).
  noOperatorNoLift =
    (lib.evalModules {
      modules = [
        opDecl
        {config.svc.x = "a";}
        {config.svc.x = "b";}
      ];
      lib = lib;
    })
    .config
    .svc
    .x
    == "b";
  # mkForce (tier 50) still beats the operator (tier 75): correct band order.
  forceBeatsOperator =
    (lib.evalModules {
      modules = [
        opDecl
        {config.svc.x = lib.mkForce "pkg-force";}
      ];
      operatorModules = [{config.svc.x = "op-bare";}];
      lib = lib;
    })
    .config
    .svc
    .x
    == "pkg-force";
  # Forge guard (M-forgeable-file): a PACKAGE that sets `_file`/`_provenance`
  # in its own body must NOT obtain operator priority. Here the forging
  # package def is ordered last, so if the forge "worked" (tier 75) it would
  # win; correct behaviour leaves it tier 100 ⇒ last-value among 100s, which
  # *is* the forge string — so to disprove forging we instead assert the real
  # operator (passed via operatorModules) still beats it.
  forgeDoesNotBeatOperator =
    (lib.evalModules {
      modules = [
        opDecl
        {
          _file = "host.nix";
          _provenance = "operator";
          config.svc.x = "forged-by-package";
        }
      ];
      operatorModules = [{config.svc.x = "true-operator";}];
      lib = lib;
    })
    .config
    .svc
    .x
    == "true-operator";

  # --- types.uniqEnum (owned shared scalar) ---------------------------
  uniqEnumAgrees =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.p = lib.mkOption {type = lib.types.uniqEnum ["a" "b"];};
        })
        {config.p = "a";}
        {config.p = "a";}
      ];
      lib = lib;
    })
    .config
    .p
    == "a";
  uniqEnumRejectsConflict =
    !(builtins.tryEval (
        (lib.evalModules {
          modules = [
            ({lib, ...}: {
              options.p = lib.mkOption {type = lib.types.uniqEnum ["a" "b"];};
            })
            {config.p = "a";}
            {config.p = "b";}
          ];
          lib = lib;
        })
        .config
        .p
      ))
    .success;

  # uniq must NOT bypass the element type's constraint: an out-of-set value is
  # rejected even with no conflict (the inner `enum` check fires via delegation).
  uniqEnumRejectsBadValue =
    !(builtins.tryEval (
        (lib.evalModules {
          modules = [
            ({lib, ...}: {
              options.p = lib.mkOption {type = lib.types.uniqEnum ["a" "b"];};
            })
            {config.p = "z";}
          ];
          lib = lib;
        })
        .config
        .p
      ))
    .success;

  # --- mkPackageRoot ({pkg}.* mount) ----------------------------------
  #
  # Mount a package module under its own root name; the root name is injected
  # as the submodule `name`, and an un-configured root is inert (defaults).
  pkgRootEval = lib.evalModules {
    modules =
      (lib.mountPackageModules {
        redis = {name, ...}: {
          options.enable = lib.mkOption {
            type = lib.types.bool;
            default = false;
          };
          options.rootName = lib.mkOption {
            type = lib.types.str;
            default = name;
          };
        };
      })
      ++ [{config.redis.enable = true;}];
    lib = lib;
  };
  pkgRootNameInjected = pkgRootEval.config.redis.rootName == "redis";
  pkgRootConfigurable = pkgRootEval.config.redis.enable == true;

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
                      (lib.throwIfNot f3bSurfaceIsVirtualHosts
                        "module-enforcement: contributableSurface should list exactly the marked extension point"
                        (lib.throwIfNot f3bValueUnperturbed
                          "module-enforcement: the contributable marker must not change the merged value"
                          (lib.throwIfNot operatorWins
                            "module-enforcement: operator (tier 75) must beat a package contribution (tier 100)"
                            (lib.throwIfNot noOperatorNoLift
                              "module-enforcement: without operatorModules the priority lift must not fire (last-value wins)"
                              (lib.throwIfNot forceBeatsOperator
                                "module-enforcement: mkForce (tier 50) must beat the operator (tier 75)"
                                (lib.throwIfNot forgeDoesNotBeatOperator
                                  "module-enforcement: a package-supplied _file/_provenance must not forge operator priority"
                                  (lib.throwIfNot uniqEnumAgrees
                                    "module-enforcement: uniqEnum should accept agreeing definitions"
                                    (lib.throwIfNot uniqEnumRejectsConflict
                                      "module-enforcement: uniqEnum should reject conflicting definitions"
                                      (lib.throwIfNot uniqEnumRejectsBadValue
                                        "module-enforcement: uniqEnum must reject an out-of-set value (inner enum check must fire)"
                                        (lib.throwIfNot pkgRootNameInjected
                                          "module-enforcement: mkPackageRoot should inject the root name as the submodule name"
                                          (lib.throwIfNot pkgRootConfigurable
                                            "module-enforcement: mkPackageRoot mount should be configurable under its root"
                                            true))))))))))))))))))));
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
          echo "  contributable surface exposed, marker inert: OK"
          echo "  operator tier-75 beats package, mkForce beats operator: OK"
          echo "  no operatorModules means no priority lift: OK"
          echo "  package provenance cannot forge operator priority: OK"
          echo "  types.uniqEnum agree/conflict: OK"
          echo "  mkPackageRoot mount and name injection: OK"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Regression guard for Phase 1-3 lib additions";
  }
