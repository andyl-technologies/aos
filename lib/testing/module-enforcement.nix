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
  aos = import ../../. {system = pkgs.stdenv.buildPlatform.system;};

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
  imageBudgetCheckWired = healthySystem.config.system.build.checks ? image-budget;
  defaultRootPartitionHasHeadroom =
    healthySystem.config.aos.image.rootPartitionMiB
    == 1024
    && healthySystem.config.aos.image.budgets.maxRootMiB == 512;

  overriddenRootPartitionSystem = aos.mkSystem {
    modules = [
      ../../systems/server.nix
      {aos.image.rootPartitionMiB = 1536;}
    ];
  };
  rootPartitionOverridePropagates =
    overriddenRootPartitionSystem.config.aos.image.rootPartitionMiB
    == 1536
    && overriddenRootPartitionSystem.config.aos.boot.storage.zfs.rootSlotSizeMiB == 1536;

  undersizedRootPartitionSystem = aos.mkSystem {
    modules = [
      ../../systems/server.nix
      {aos.image.rootPartitionMiB = 511;}
    ];
  };
  undersizedRootPartitionRejected =
    !(
      builtins.tryEval undersizedRootPartitionSystem.config.system.build.toplevel.name
    )
    .success;

  # The ESP budget is also its storage geometry. Reject a contract that cannot
  # hold two maximum-sized UKIs before any image derivation is realized.
  undersizedEspSystem = aos.mkSystem {
    modules = [
      ../../systems/server.nix
      {aos.image.budgets.maxEspMiB = lib.mkForce 351;}
    ];
  };
  undersizedEspRejected =
    !(
      builtins.tryEval undersizedEspSystem.config.system.build.toplevel.name
    )
    .success;

  # A ZFS installer must not allocate zvols smaller than payloads admitted by
  # the image contract.
  undersizedZfsSlotSystem = aos.mkSystem {
    modules = [
      ../../systems/server.nix
      {
        aos.boot.storage = {
          backend = "zfs-zvol";
          zfs.rootSlotSizeMiB = lib.mkForce 511;
        };
      }
    ];
  };
  undersizedZfsSlotRejected =
    !(
      builtins.tryEval undersizedZfsSlotSystem.config.system.build.toplevel.name
    )
    .success;

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
  f3bBoolTypeSig =
    (builtins.head (builtins.filter (d: d.pathStr == "nginx.enable") f3bEval._optionDecls)).typeSig;

  packageDiagnosticsEval = lib.evalModules {
    modules = [
      ({lib, ...}: {
        options.assertions = lib.mkOption {
          type = lib.types.listOf lib.types.attrs;
          default = [];
        };
        options.warnings = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [];
        };
      })
    ];
    packageModules = [
      {
        name = "diagnostic-fixture";
        authorization = {
          owns = [];
          contributes = {};
        };
        module.config = {
          assertions = [
            {
              assertion = true;
              message = "package assertion";
            }
          ];
          warnings = ["package warning"];
        };
      }
    ];
    lib = lib;
  };
  packageEngineDiagnosticsAccepted =
    builtins.length packageDiagnosticsEval.config.assertions
    == 1
    && packageDiagnosticsEval.config.warnings == ["package warning"];

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
  # Forge guard (M-forgeable-file): provenance is a reserved engine field.
  # Reject a module-authored stamp rather than merely ignoring it, so an
  # ownership audit can never mistake the attempted identity for metadata.
  forgedProvenanceRejected =
    !(
      builtins.tryEval ((lib.evalModules {
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
        .x)
    )
    .success;

  resolverPackageOwner =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options = {
            artifacts = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = {};
            };
            observedOwner = lib.mkOption {type = lib.types.str;};
          };
        })
        ({provenance, ...}: {
          config.observedOwner = provenance.ownerOfAttr ["artifacts"] "pkg.conf";
        })
      ];
      packageModules = [
        {
          name = "redis";
          authorization = {
            owns = ["artifacts"];
            contributes = {};
          };
          module = {config.artifacts."pkg.conf" = "value";};
        }
      ];
      lib = lib;
    })
    .config
    .observedOwner
    == "redis";

  nestedDecl = {lib, ...}: {
    options.tree = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          left = lib.mkOption {type = lib.types.str;};
          right = lib.mkOption {type = lib.types.str;};
          nested = lib.mkOption {
            type = lib.types.submodule {
              options = {
                left = lib.mkOption {
                  type = lib.types.str;
                  default = "default-left";
                };
                right = lib.mkOption {
                  type = lib.types.str;
                  default = "default-right";
                };
              };
            };
            default = {};
          };
        };
      });
      default = {};
    };
  };
  packageRecord = module: {
    name = "redis";
    authorization = {
      owns = ["tree" "artifacts" "rules"];
      contributes = {nginx = ["virtualHosts"];};
    };
    inherit module;
  };
  nestedPriorityEval = lib.evalModules {
    modules = [nestedDecl];
    packageModules = [
      (packageRecord {
        config.tree.main = {
          left = "package";
          right = "preserved";
        };
      })
    ];
    operatorModules = [{config.tree.main.left = "host";}];
    inherit lib;
  };
  nestedHostPriorityIsLeafScoped =
    nestedPriorityEval.config.tree.main.left
    == "host"
    && nestedPriorityEval.config.tree.main.right == "preserved";
  nestedSubmodulePriorityEval = lib.evalModules {
    modules = [nestedDecl];
    packageModules = [
      (packageRecord {
        config.tree.main.nested = {
          left = "package-left";
          right = "package-right";
        };
      })
    ];
    operatorModules = [{config.tree.main.nested.left = "host-left";}];
    inherit lib;
  };
  nestedSubmoduleHostPriorityIsLeafScoped =
    nestedSubmodulePriorityEval.config.tree.main.nested.left
    == "host-left"
    && nestedSubmodulePriorityEval.config.tree.main.nested.right == "package-right";
  nestedForceBeatsHost =
    (lib.evalModules {
      modules = [nestedDecl];
      packageModules = [(packageRecord {config.tree.main.left = lib.mkForce "forced";})];
      operatorModules = [{config.tree.main.left = "host";}];
      inherit lib;
    })
    .config
    .tree
    .main
    .left
    == "forced";
  importedForgedFileStaysPackageOwned =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.artifacts = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
          };
          options.observed = lib.mkOption {type = lib.types.str;};
        })
        ({provenance, ...}: {config.observed = provenance.ownerOfAttr ["artifacts"] "imported";})
      ];
      packageModules = [
        (packageRecord {
          imports = [
            {
              _file = "host.nix";
              config.artifacts.imported = "value";
            }
          ];
        })
      ];
      inherit lib;
    })
    .config
    .observed
    == "redis";
  foreignEnableRejected =
    !(builtins.tryEval (
      (lib.evalModules {
        modules = [
          ({lib, ...}: {
            options.nginx.enable = lib.mkOption {
              type = lib.types.bool;
              default = false;
            };
          })
        ];
        packageModules = [(packageRecord {config.nginx.enable = true;})];
        inherit lib;
      })
      .config
      .nginx
      .enable
    ))
    .success;
  nestedForeignEnableRejected =
    !(builtins.tryEval (
      (lib.evalModules {
        modules = [
          ({lib, ...}: {
            options.systemd.services = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule {
                options.enable = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                };
              });
              default = {};
            };
          })
        ];
        packageModules = [
          {
            name = "redis";
            authorization = {
              owns = [];
              contributes.systemd = ["services"];
            };
            module.config.systemd.services.victim.enable = true;
          }
        ];
        inherit lib;
      })
      .config
      .systemd
      .services
      .victim
      .enable
    ))
    .success;
  packageModuleArgsRejected =
    !(builtins.tryEval (
      (lib.evalModules {
        modules = [nestedDecl];
        packageModules = [
          (packageRecord {
            config = {
              _module.args.laundered = "value";
              tree.main.left = "package";
            };
          })
        ];
        inherit lib;
      })
      .config
      .tree
      .main
      .left
    ))
    .success;
  foreignPackageDeclarationRejected =
    !(builtins.tryEval (
      (lib.evalModules {
        modules = [
          ({lib, ...}: {
            options.nginx.enable = lib.mkOption {
              type = lib.types.bool;
              default = false;
            };
          })
        ];
        packageModules = [
          (packageRecord ({lib, ...}: {
            options.nginx.foreignDefault = lib.mkOption {
              type = lib.types.str;
              default = "laundered";
            };
          }))
        ];
        inherit lib;
      })
      .config
      .nginx
      .enable
    ))
    .success;
  allowedContributionAccepted =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.nginx.virtualHosts = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
          };
        })
      ];
      packageModules = [(packageRecord {config.nginx.virtualHosts.demo = "ok";})];
      inherit lib;
    })
    .config
    .nginx
    .virtualHosts
    .demo
    == "ok";
  mkOrderOwnershipPeeled =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.rules = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
          };
          options.observed = lib.mkOption {type = lib.types.str;};
        })
        ({provenance, ...}: {config.observed = provenance.ownerOfListString ["rules"] "ordered";})
      ];
      packageModules = [(packageRecord {config.rules = lib.mkAfter ["ordered"];})];
      inherit lib;
    })
    .config
    .observed
    == "redis";
  mixedDependencyOwnersDetected =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.artifacts = lib.mkOption {
            type = lib.types.attrsOf (lib.types.submodule {
              options.left = lib.mkOption {
                type = lib.types.str;
                default = "";
              };
              options.right = lib.mkOption {
                type = lib.types.str;
                default = "";
              };
            });
            default = {};
          };
          options.observedOwners = lib.mkOption {type = lib.types.listOf lib.types.str;};
        })
        ({provenance, ...}: {config.observedOwners = provenance.dependencyOwnersOfAttr ["artifacts"] "mixed";})
      ];
      packageModules = [
        (packageRecord {config.artifacts.mixed.left = "left";})
        {
          name = "other";
          authorization = {
            owns = ["artifacts"];
            contributes = {};
          };
          module.config.artifacts.mixed.right = "right";
        }
      ];
      inherit lib;
    })
    .config
    .observedOwners
    == ["redis" "other"];

  packageDefaultDependencyOwner =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options = {
            artifacts = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = {};
            };
            observed = lib.mkOption {type = lib.types.str;};
          };
        })
        ({config, ...}: {config.artifacts.defaulted = config.provider.value;})
        ({provenance, ...}: {config.observed = provenance.ownerOfAttr ["artifacts"] "defaulted";})
      ];
      packageModules = [
        {
          name = "provider";
          authorization = {
            owns = [];
            contributes = {};
          };
          module = {lib, ...}: {
            options.provider.value = lib.mkOption {
              type = lib.types.str;
              default = "package default";
            };
          };
        }
      ];
      inherit lib;
    })
    .config
    .observed
    == "provider";

  undeclaredCrossPackageReadRejected =
    !(builtins.tryEval (builtins.toJSON (
      (lib.evalModules {
        modules = [];
        packageModules = [
          {
            name = "provider";
            authorization = {
              owns = [];
              contributes = {};
            };
            module = {lib, ...}: {
              options.provider.value = lib.mkOption {type = lib.types.str;};
              config.provider.value = "private";
            };
          }
          {
            name = "consumer";
            authorization = {
              owns = [];
              contributes = {};
            };
            module = {
              lib,
              config,
              ...
            }: {
              options.consumer.observed = lib.mkOption {type = lib.types.str;};
              config.consumer.observed = config.provider.value;
            };
          }
        ];
        inherit lib;
      })
      .config
      .consumer
      .observed
    )))
    .success;

  hostImportedOwner =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.artifacts = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
          };
          options.observed = lib.mkOption {type = lib.types.str;};
        })
        ({provenance, ...}: {config.observed = provenance.ownerOfAttr ["artifacts"] "imported";})
      ];
      operatorModules = [{imports = [{config.artifacts.imported = "host";}];}];
      inherit lib;
    })
    .config
    .observed
    == "@host";
  hostImportedNestedValue =
    (lib.evalModules {
      modules = [nestedDecl];
      operatorModules = [{imports = [{config.tree.main.nested.left = "host imported nested";}];}];
      inherit lib;
    })
    .config
    .tree
    .main
    .nested
    .left
    == "host imported nested";
  hostImportKeepsNormalPriority =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.artifacts = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
          };
        })
      ];
      packageModules = [(packageRecord {config.artifacts.priority = lib.mkOverride 80 "package";})];
      operatorModules = [{imports = [{config.artifacts.priority = "host import";}];}];
      inherit lib;
    })
    .config
    .artifacts
    .priority
    == "package";

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

  # --- Authenticated package import roots -----------------------------
  confinedPackageImport =
    (lib.evalModules {
      modules = [];
      packageModules = [
        {
          name = "import-fixture";
          authorization = {
            owns = ["importConfinement"];
            contributes = {};
          };
          configRoot = ./fixtures/package-import-confined;
          module = ./fixtures/package-import-confined/module.nix;
          outputs = {
            self = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-import-fixture";
            dependencies = {};
          };
        }
      ];
      lib = lib;
    })
    .config
    .importConfinement
    .value
    == "confined";
  escapedPackageImportRejected =
    !(builtins.tryEval (builtins.deepSeq (
        (lib.evalModules {
          modules = [];
          packageModules = [
            {
              name = "import-fixture";
              authorization = {
                owns = ["importConfinement"];
                contributes = {};
              };
              configRoot = ./fixtures/package-import-escaped;
              module = ./fixtures/package-import-escaped/module.nix;
              outputs = {
                self = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-import-fixture";
                dependencies = {};
              };
            }
          ];
          lib = lib;
        })
        .config
        .importConfinement
        .value
      )
      true))
    .success;
  evaluatedPackageImportRejected =
    !(builtins.tryEval (builtins.deepSeq (
        (lib.evalModules {
          modules = [];
          packageModules = [
            {
              name = "import-fixture";
              authorization = {
                owns = ["importConfinement"];
                contributes = {};
              };
              configRoot = ./fixtures/package-import-evaluated;
              module = ./fixtures/package-import-evaluated/module.nix;
              outputs = {
                self = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-import-fixture";
                dependencies = {};
              };
            }
          ];
          lib = lib;
        })
        .config
        .importConfinement
        .value
      )
      true))
    .success;
  lexicalStringPackageImportRejected =
    !(builtins.tryEval (builtins.deepSeq (
        (lib.evalModules {
          modules = [];
          packageModules = [
            {
              name = "import-fixture";
              authorization = {
                owns = ["importConfinement"];
                contributes = {};
              };
              configRoot = ./fixtures/package-import-string-escape;
              module = ./fixtures/package-import-string-escape/module.nix;
              outputs = {
                self = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-import-fixture";
                dependencies = {};
              };
            }
          ];
          lib = lib;
        })
        .config
        .importConfinement
        .value
      )
      true))
    .success;
  unlistedPackageOutputRejected =
    !(
      (lib.evalModules {
        modules = [];
        packageModules = [
          {
            name = "output-fixture";
            authorization = {
              owns = ["outputConfinement"];
              contributes = {};
            };
            configRoot = ./fixtures/package-output-unlisted;
            module = ./fixtures/package-output-unlisted/module.nix;
            outputs = {
              self = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-output-fixture";
              dependencies.allowed = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-allowed";
            };
          }
        ];
        lib = lib;
      })
      .config
      .outputConfinement
      .hasForbidden
    );

  # --- Eval-time assertions for the test itself -----------------------
  evalAssertions =
    builtins.foldl' (result: check:
      lib.throwIfNot check.ok check.message result)
    true [
      {
        ok = brokenConfigStillReadable;
        message = "broken config should remain inspectable";
      }
      {
        ok = brokenBuildThrows;
        message = "broken build must throw";
      }
      {
        ok = healthyBuildSucceeds;
        message = "healthy build must succeed";
      }
      {
        ok = imageBudgetCheckWired;
        message = "per-image budget check must be exposed";
      }
      {
        ok = defaultRootPartitionHasHeadroom;
        message = "default root partition must retain headroom above the artifact budget";
      }
      {
        ok = rootPartitionOverridePropagates;
        message = "root partition override must propagate to default ZFS slot capacity";
      }
      {
        ok = undersizedRootPartitionRejected;
        message = "root partition smaller than its artifact budget must throw";
      }
      {
        ok = undersizedEspRejected;
        message = "undersized image ESP contract must throw";
      }
      {
        ok = undersizedZfsSlotRejected;
        message = "undersized ZFS image slot must throw";
      }
      {
        ok = enableExplicitlySet;
        message = "mkEnableOption explicit value";
      }
      {
        ok = enableDefaultsFalse == false;
        message = "mkEnableOption default";
      }
      {
        ok = packageOptDefaultName == "coreutils";
        message = "mkPackageOption default";
      }
      {
        ok = pathInStoreAccepts && pathInStoreRejectsHost && pathInStoreRejectsRelative && pathInStoreRejectsNumber;
        message = "pathInStore validation";
      }
      {
        ok = f3bSurfaceIsVirtualHosts && f3bValueUnperturbed && f3bBoolTypeSig == "boolean";
        message = "contributable typed surface";
      }
      {
        ok = packageEngineDiagnosticsAccepted;
        message = "package module engine diagnostics";
      }
      {
        ok = operatorWins && noOperatorNoLift && forceBeatsOperator;
        message = "operator priority bands";
      }
      {
        ok = forgedProvenanceRejected;
        message = "reserved provenance stamp";
      }
      {
        ok = resolverPackageOwner;
        message = "resolver package owner";
      }
      {
        ok = nestedHostPriorityIsLeafScoped && nestedSubmoduleHostPriorityIsLeafScoped && nestedForceBeatsHost;
        message = "nested provenance priority";
      }
      {
        ok = importedForgedFileStaysPackageOwned;
        message = "imported forged _file provenance";
      }
      {
        ok = foreignEnableRejected && nestedForeignEnableRejected && allowedContributionAccepted;
        message = "actual package write authorization";
      }
      {
        ok = packageModuleArgsRejected;
        message = "package _module.args authorization";
      }
      {
        ok = foreignPackageDeclarationRejected;
        message = "package option declaration authorization";
      }
      {
        ok = mkOrderOwnershipPeeled;
        message = "mkOrder ownership";
      }
      {
        ok = mixedDependencyOwnersDetected;
        message = "mixed artifact dependency owners";
      }
      {
        ok = packageDefaultDependencyOwner;
        message = "package option-default dependency owner";
      }
      {
        ok = undeclaredCrossPackageReadRejected;
        message = "undeclared cross-package read";
      }
      {
        ok = hostImportedOwner && hostImportedNestedValue && hostImportKeepsNormalPriority;
        message = "host import ownership and priority";
      }
      {
        ok = uniqEnumAgrees && uniqEnumRejectsConflict && uniqEnumRejectsBadValue;
        message = "uniqEnum semantics";
      }
      {
        ok = pkgRootNameInjected && pkgRootConfigurable;
        message = "package root mount";
      }
      {
        ok = confinedPackageImport && escapedPackageImportRejected && evaluatedPackageImportRejected && lexicalStringPackageImportRejected;
        message = "authenticated package import-root confinement";
      }
      {
        ok = unlistedPackageOutputRejected;
        message = "authenticated package output-map confinement";
      }
    ];
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
