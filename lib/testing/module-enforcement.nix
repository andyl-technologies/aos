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
  mkSystem,
}: let
  imagePlatformChecks = import ./image-platform.nix;

  # --- Assertion enforcement ------------------------------------------
  #
  # Build a broken server system with a failing assertion. The config
  # itself must still be inspectable (Option B semantics).
  brokenSystem = mkSystem {
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
  healthySystem = mkSystem {
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
  extendedSystem = healthySystem.extendModules {modules = [{}];};
  extendedSystemRetainsSelectedProviders = extendedSystem.config.aos.image.platform != null;
  imageBudgetCheckWired = healthySystem.config.system.build.checks ? image-budget;
  serverRootPartitionHasHeadroom =
    healthySystem.config.aos.image.rootPartitionMiB
    > healthySystem.config.aos.image.budgets.maxRootMiB;

  overriddenRootPartitionSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      {aos.image.rootPartitionMiB = 1536;}
    ];
  };
  rootPartitionOverridePropagates =
    overriddenRootPartitionSystem.config.aos.image.rootPartitionMiB
    == 1536
    && overriddenRootPartitionSystem.config.aos.boot.storage.zfs.rootSlotSizeMiB == 1536;

  undersizedRootPartitionSystem = mkSystem {
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
  undersizedEspSystem = mkSystem {
    modules = [
      ../../systems/server.nix
      {aos.image.budgets.maxFirmwarePartitionMiB = lib.mkForce 351;}
    ];
  };
  undersizedEspRejected =
    !(
      builtins.tryEval undersizedEspSystem.config.system.build.toplevel.name
    )
    .success;

  # A ZFS installer must not allocate zvols smaller than payloads admitted by
  # the image contract.
  undersizedZfsSlotSystem = mkSystem {
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

  # --- types.addCheck -------------------------------------------------
  #
  # The additional predicate applies to the final merged value. Cover
  # scalar, submodule, and list merges because each has distinct merge
  # behavior in the module engine.
  addCheckDeclaration = {lib, ...}: {
    options.checked = {
      scalar = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0);
      };
      record = lib.mkOption {
        type = lib.types.addCheck (lib.types.submodule {
          options = {
            lower = lib.mkOption {type = lib.types.int;};
            upper = lib.mkOption {type = lib.types.int;};
          };
        }) (value: value.lower < value.upper);
      };
      values = lib.mkOption {
        type =
          lib.types.addCheck (lib.types.listOf lib.types.int) (values:
            values == [1 2]);
      };
    };
  };
  addCheckEvaluation = modules:
    lib.evalModules {
      modules = [addCheckDeclaration] ++ modules;
      inherit lib;
    };
  validAddCheckEvaluation = addCheckEvaluation [
    {checked.scalar = 1;}
    {checked.record.lower = 1;}
    {checked.record.upper = 2;}
    {checked.values = [1];}
    {checked.values = [2];}
  ];
  addCheckScalarMerged = validAddCheckEvaluation.config.checked.scalar == 1;
  addCheckSubmoduleMerged =
    validAddCheckEvaluation.config.checked.record.lower
    == 1
    && validAddCheckEvaluation.config.checked.record.upper == 2;
  addCheckListMerged = validAddCheckEvaluation.config.checked.values == [1 2];
  addCheckScalarRejected =
    !(builtins.tryEval (addCheckEvaluation [{checked.scalar = 0;}]).config.checked.scalar).success;
  addCheckSubmoduleRejected =
    !(
      builtins.tryEval
      (addCheckEvaluation [
        {checked.record.lower = 2;}
        {checked.record.upper = 1;}
      ])
      .config
      .checked
      .record
    )
    .success;
  addCheckListRejected =
    !(
      builtins.tryEval
      (addCheckEvaluation [{checked.values = [1];}])
      .config
      .checked
      .values
    )
    .success;

  # --- types.submodule public value ----------------------------------
  submoduleVisibilityDeclaration = {lib, ...}: {
    options = {
      strictRecord = lib.mkOption {
        type = lib.types.submodule {
          _module.strict = true;
          options.value = lib.mkOption {type = lib.types.str;};
        };
      };
      freeformRecord = lib.mkOption {
        type = lib.types.submodule {
          freeformType = lib.types.attrs;
          options.declared = lib.mkOption {type = lib.types.str;};
        };
      };
      nestedRecord = lib.mkOption {
        type = lib.types.submodule {
          options.inner = lib.mkOption {
            type = lib.types.submodule {
              options.value = lib.mkOption {type = lib.types.str;};
            };
          };
        };
      };
    };
  };
  submoduleVisibilityEvaluation = lib.evalModules {
    modules = [
      submoduleVisibilityDeclaration
      {
        strictRecord.value = "strict";
        freeformRecord = {
          declared = "declared";
          extra = "freeform";
        };
        nestedRecord.inner.value = "nested";
      }
    ];
    inherit lib;
  };
  strictSubmodulePublic =
    submoduleVisibilityEvaluation.config.strictRecord
    == {value = "strict";};
  freeformSubmodulePublic =
    submoduleVisibilityEvaluation.config.freeformRecord
    == {
      declared = "declared";
      extra = "freeform";
    };
  nestedSubmodulePublic =
    submoduleVisibilityEvaluation.config.nestedRecord
    == {inner = {value = "nested";};};
  strictSubmoduleRejectsUndeclared =
    !(
      builtins.tryEval
      (lib.evalModules {
        modules = [
          submoduleVisibilityDeclaration
          {
            strictRecord = {
              value = "strict";
              extra = "forbidden";
            };
          }
        ];
        inherit lib;
      })
      .config
      .strictRecord
    )
    .success;

  composedServiceEvaluation = lib.evalModules {
    inherit lib;
    modules = [
      {
        options.services = lib.mkOption {
          type = lib.types.attrsOf (lib.types.submodule {
            config._module.strict = true;
            options.command = lib.mkOption {type = lib.types.str;};
          });
          default = {};
        };
        config.services.web.command = "serve";
      }
      {
        options.services = lib.mkOption {
          type = lib.types.attrsOf (lib.types.submodule {
            options.order.after = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
            };
          });
          default = {};
        };
        config.services.web.order.after = ["database"];
      }
    ];
  };
  composedServiceOptions =
    composedServiceEvaluation.config.services.web
    == {
      command = "serve";
      order.after = ["database"];
    };
  composedServiceRejectsUnknown =
    !(builtins.tryEval
      (composedServiceEvaluation.extendModules {
        modules = [{services.web.unknown = true;}];
      })
      .config
      .services
      .web)
    .success;
  deferredServiceFeatureEvaluation = lib.evalModules {
    inherit lib;
    modules = [
      ({config, ...}: {
        options.serviceFeatures = lib.mkOption {
          type = lib.types.listOf lib.types.deferredModule;
          default = [];
        };
        options.services = lib.mkOption {
          type = lib.types.attrsOf (lib.types.submodule (
            [{config._module.strict = true;}]
            ++ config.serviceFeatures
          ));
          default = {};
        };
      })
      {
        serviceFeatures = [
          {options.command = lib.mkOption {type = lib.types.str;};}
          {
            options.order.after = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
            };
          }
        ];
        services.web = {
          command = "serve";
          order.after = ["database"];
        };
      }
    ];
  };
  deferredServiceFeaturesCompose =
    deferredServiceFeatureEvaluation.config.services.web
    == {
      command = "serve";
      order.after = ["database"];
    };
  serviceRegistryEvaluation = lib.evalModules {
    inherit lib;
    modules = [
      ../../modules/abilities/_service.nix
      ({config, ...}: {
        options.aos.serviceOptionModules.first = lib.mkOption {
          type = lib.types.deferredModule;
          default.options.enable = lib.mkOption {
            type = lib.types.bool;
            default = false;
          };
        };
        options.aos.serviceOptionModules.second = lib.mkOption {
          type = lib.types.deferredModule;
          default.options.command = lib.mkOption {
            type = lib.types.str;
            default = "idle";
            description = "The second service command.";
          };
        };
        config = lib.mkIf config.aos.services.first.enable {
          aos.services.second.command = "run";
        };
      })
      {
        aos.serviceFeatureModules = [
          {
            options.extensions.start.command = lib.mkOption {
              type = lib.types.str;
            };
          }
        ];
        aos.services.second.extensions.start.command = "start";
      }
      {
        aos.serviceFeatureModules = [
          ({config, ...}: {
            options.extensions.order.after = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
            };
            config.extensions.order.after =
              lib.mkIf
              (config.extensions.start.command == "start")
              ["first"];
          })
        ];
      }
    ];
  };
  serviceRegistryAvoidsSiblingCycle =
    serviceRegistryEvaluation.config.aos.services.second.command == "idle";
  serviceFeatureModulesCompose =
    serviceRegistryEvaluation.config.aos.services.second.extensions
    == {
      start.command = "start";
      order.after = ["first"];
    };
  serviceRegistryProjectsNestedOptions =
    builtins.any
    (declaration:
      declaration.pathStr
      == "command"
      && declaration.description == "The second service command.")
    (lib.submoduleOptionDeclarations
      serviceRegistryEvaluation.options.aos.services.type._elementType
      ["aos" "services" "second"]);

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
          description = "Whether to enable nginx.";
          example = true;
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
  f3bEnableDocumentation =
    builtins.head (builtins.filter (d: d.pathStr == "nginx.enable") f3bEval._optionDecls);
  f3bDocumentationIsStructured =
    f3bEnableDocumentation.type
    == {kind = "bool";}
    && f3bEnableDocumentation.description == "Whether to enable nginx."
    && f3bEnableDocumentation.default
    == {
      kind = "literal";
      value = false;
    }
    && f3bEnableDocumentation.example
    == {
      kind = "literal";
      value = true;
    }
    && f3bEnableDocumentation.visibility == "public"
    && !f3bEnableDocumentation.readOnly
    && !f3bEnableDocumentation.contributable;

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
              contributable = true;
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
      contributable = true;
    };
  };
  packageRecord = module: {
    name = "redis";
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
            contributable = true;
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
              contributable = true;
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
              contributable = true;
            };
          })
        ];
        packageModules = [
          {
            name = "redis";
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
  uniquePackageDeclarationAccepted =
    (lib.evalModules {
      modules = [];
      packageModules = [
        (packageRecord ({lib, ...}: {
          options.redis.value = lib.mkOption {type = lib.types.str;};
          config.redis.value = "owned";
        }))
      ];
      inherit lib;
    })
    .config
    .redis
    .value
    == "owned";
  duplicatePackageDeclarationRejected =
    !(builtins.tryEval (
      builtins.deepSeq (lib.evalModules {
        modules = [
          ({lib, ...}: {
            options.nginx.foreignDefault = lib.mkOption {
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
      true
    ))
    .success;
  allowedContributionAccepted =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.nginx.virtualHosts = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
            contributable = true;
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
  nonContributableContributionRejected =
    !(builtins.tryEval (
      builtins.deepSeq (lib.evalModules {
        modules = [
          ({lib, ...}: {
            options.nginx.workerProcesses = lib.mkOption {
              type = lib.types.int;
              default = 1;
            };
          })
        ];
        packageModules = [(packageRecord {config.nginx.workerProcesses = 8;})];
        inherit lib;
      })
      true
    ))
    .success;
  undeclaredPackageWriteRejected =
    !(builtins.tryEval (
      builtins.deepSeq (lib.evalModules {
        modules = [];
        packageModules = [(packageRecord {config.undeclared.value = true;})];
        inherit lib;
      })
      true
    ))
    .success;
  mkOrderOwnershipPeeled =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.rules = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
            contributable = true;
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
            contributable = true;
          };
          options.observedOwners = lib.mkOption {type = lib.types.listOf lib.types.str;};
        })
        ({provenance, ...}: {config.observedOwners = provenance.dependencyOwnersOfAttr ["artifacts"] "mixed";})
      ];
      packageModules = [
        (packageRecord {config.artifacts.mixed.left = "left";})
        {
          name = "other";
          module.config.artifacts.mixed.right = "right";
        }
      ];
      inherit lib;
    })
    .config
    .observedOwners
    == ["redis" "other"];

  packageValuesAreAtomicForDependencyOwnership = let
    packageLikeValue = {
      outPath = "/nix/store/00000000000000000000000000000000-package";
      internal = throw "dependency ownership traversed package internals";
    };
  in
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options = {
            artifacts = lib.mkOption {
              type = lib.types.attrsOf (lib.types.submodule {
                options.package = lib.mkOption {type = lib.types.package;};
              });
              default = {};
              contributable = true;
            };
            observedOwners = lib.mkOption {type = lib.types.listOf lib.types.str;};
          };
          config.artifacts.inert.package = packageLikeValue;
        })
        ({provenance, ...}: {
          config.observedOwners = provenance.dependencyOwnersOfAttr ["artifacts"] "inert";
        })
      ];
      inherit lib;
    })
    .config
    .observedOwners
    == ["@base"];

  packageDefaultDependencyOwner =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options = {
            artifacts = lib.mkOption {
              type = lib.types.attrsOf lib.types.str;
              default = {};
              contributable = true;
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
            module = {lib, ...}: {
              options.provider.value = lib.mkOption {type = lib.types.str;};
              config.provider.value = "private";
            };
          }
          {
            name = "consumer";
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
            contributable = true;
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
            contributable = true;
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
  runtimeDirectGetsOperatorPriority =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.artifacts = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
            contributable = true;
          };
        })
      ];
      packageModules = [(packageRecord {config.artifacts.priority = "package";})];
      runtimeModules = [{config.artifacts.priority = "runtime";}];
      inherit lib;
    })
    .config
    .artifacts
    .priority
    == "runtime";
  runtimeNestedMatchesOperator = let
    operatorValue =
      (lib.evalModules {
        modules = [nestedDecl];
        operatorModules = [{config.tree.main.nested.left = "nested operator";}];
        inherit lib;
      })
      .config
      .tree
      .main
      .nested
      .left;
    runtimeValue =
      (lib.evalModules {
        modules = [nestedDecl];
        runtimeModules = [{config.tree.main.nested.left = "nested operator";}];
        inherit lib;
      })
      .config
      .tree
      .main
      .nested
      .left;
  in
    runtimeValue == operatorValue && runtimeValue == "nested operator";
  runtimeOwnershipMatchesMergePriority =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.artifacts = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
            contributable = true;
          };
          options.observed = lib.mkOption {type = lib.types.str;};
        })
        ({provenance, ...}: {config.observed = provenance.ownerOfAttr ["artifacts"] "priority";})
      ];
      packageModules = [(packageRecord {config.artifacts.priority = lib.mkOverride 80 "package";})];
      runtimeModules = [{config.artifacts.priority = "runtime";}];
      inherit lib;
    })
    .config
    .observed
    == "@host";
  runtimeImportKeepsNormalPriority =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.artifacts = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = {};
            contributable = true;
          };
        })
      ];
      packageModules = [(packageRecord {config.artifacts.priority = lib.mkOverride 80 "package";})];
      runtimeModules = [{imports = [{config.artifacts.priority = "runtime import";}];}];
      inherit lib;
    })
    .config
    .artifacts
    .priority
    == "package";
  runtimeNestedImportKeepsNormalPriority =
    (lib.evalModules {
      modules = [nestedDecl];
      packageModules = [(packageRecord {config.tree.main.nested.left = lib.mkOverride 80 "package";})];
      runtimeModules = [{imports = [{config.tree.main.nested.left = "runtime import";}];}];
      inherit lib;
    })
    .config
    .tree
    .main
    .nested
    .left
    == "package";
  runtimeProvisioningRejected =
    !(builtins.tryEval ((lib.evalModules {
        modules = [
          ({lib, ...}: {
            options.aos.provisioning.test = lib.mkOption {type = lib.types.str;};
          })
        ];
        runtimeModules = [{config.aos.provisioning.test = "forbidden";}];
        inherit lib;
      })
      .config
      .aos
      .provisioning
      .test))
    .success;
  runtimeUnknownOptionRejected =
    !(builtins.tryEval ((lib.evalModules {
        modules = [
          ({lib, ...}: {
            options.known = lib.mkOption {type = lib.types.bool;};
          })
        ];
        runtimeModules = [
          {
            config = {
              known = true;
              unknown.value = true;
            };
          }
        ];
        inherit lib;
      })
      .config
      .known))
    .success;
  runtimeImportedUnknownOptionRejected =
    !(builtins.tryEval ((lib.evalModules {
        modules = [
          ({lib, ...}: {
            options.known = lib.mkOption {type = lib.types.bool;};
          })
        ];
        runtimeModules = [
          {
            imports = [
              {
                config = {
                  known = true;
                  unknown.value = true;
                };
              }
            ];
          }
        ];
        inherit lib;
      })
      .config
      .known))
    .success;
  runtimeUnknownOptionDeferredForSelection =
    (lib.evalModules {
      modules = [../../modules/base/host-selection.nix];
      runtimeModules = [
        {
          config = {
            aos.apm.desiredPackages = ["nginx"];
            environment.etc."runtime-selection/deferred.conf".mode = "0644";
          };
        }
      ];
      enforceRuntimeDeclarations = false;
      inherit lib;
    })
    .config
    .aos
    .apm
    .desiredPackages
    == ["nginx"];
  hostUnknownOptionRemainsLazy =
    (lib.evalModules {
      modules = [
        ({lib, ...}: {
          options.known = lib.mkOption {type = lib.types.bool;};
        })
      ];
      operatorModules = [
        {
          config = {
            known = true;
            unknown.value = true;
          };
        }
      ];
      inherit lib;
    })
    .config
    .known;

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

  # --- Authenticated package import roots -----------------------------
  authenticatedFixtureRecord = {
    name,
    source,
    dependencies ? {},
  }: let
    configRoot = builtins.path {
      path = source;
      name = "${name}-module";
    };
    moduleSelector = builtins.toJSON {
      package = name;
      output = "module";
    };
  in {
    inherit name configRoot;
    module = "${configRoot}/module.nix";
    outputs = {
      self = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-${name}";
      dependencies =
        dependencies
        // {${moduleSelector} = builtins.toString configRoot;};
    };
  };

  confinedPackageImport =
    (lib.evalModules {
      modules = [];
      packageModules = [
        (authenticatedFixtureRecord {
          name = "import-fixture";
          source = ./fixtures/package-import-confined;
        })
      ];
      lib = lib;
    })
    .config
    .importConfinement
    .value
    == "confined";
  evaluatedPackageImportRejected =
    !(builtins.tryEval (builtins.deepSeq (
        (lib.evalModules {
          modules = [];
          packageModules = [
            (authenticatedFixtureRecord {
              name = "import-fixture";
              source = ./fixtures/package-import-evaluated;
            })
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
            (authenticatedFixtureRecord {
              name = "import-fixture";
              source = ./fixtures/package-import-string-escape;
            })
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
          (authenticatedFixtureRecord {
            name = "output-fixture";
            source = ./fixtures/package-output-unlisted;
            dependencies.allowed = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-allowed";
          })
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
        ok = extendedSystemRetainsSelectedProviders;
        message = "extendModules must retain resolver-selected provider modules";
      }
      {
        ok = imageBudgetCheckWired;
        message = "per-image budget check must be exposed";
      }
      {
        ok = imagePlatformChecks;
        message = "cross images must retain target identity and native construction tools";
      }
      {
        ok = serverRootPartitionHasHeadroom;
        message = "server root partition must retain headroom above its declared artifact budget";
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
        ok = import ./type-addcheck.nix {inherit lib;};
        message = "additional type predicates validate merged, default, and nested values";
      }
      {
        ok = pathInStoreAccepts && pathInStoreRejectsHost && pathInStoreRejectsRelative && pathInStoreRejectsNumber;
        message = "pathInStore validation";
      }
      {
        ok =
          addCheckScalarMerged
          && addCheckSubmoduleMerged
          && addCheckListMerged
          && addCheckScalarRejected
          && addCheckSubmoduleRejected
          && addCheckListRejected;
        message = "addCheck validates merged scalar, submodule, and list values";
      }
      {
        ok =
          strictSubmodulePublic
          && freeformSubmodulePublic
          && nestedSubmodulePublic
          && strictSubmoduleRejectsUndeclared;
        message = "submodule hides engine metadata and preserves strict/freeform/nested semantics";
      }
      {
        ok =
          composedServiceOptions
          && composedServiceRejectsUnknown
          && deferredServiceFeaturesCompose
          && serviceRegistryAvoidsSiblingCycle
          && serviceFeatureModulesCompose
          && serviceRegistryProjectsNestedOptions;
        message = "feature modules compose one strict named submodule";
      }
      {
        ok = f3bSurfaceIsVirtualHosts && f3bValueUnperturbed && f3bBoolTypeSig == "boolean" && f3bDocumentationIsStructured;
        message = "contributable typed documentation surface";
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
        ok =
          foreignEnableRejected
          && nestedForeignEnableRejected
          && allowedContributionAccepted
          && nonContributableContributionRejected
          && undeclaredPackageWriteRejected;
        message = "actual package write authorization";
      }
      {
        ok = packageModuleArgsRejected;
        message = "package _module.args authorization";
      }
      {
        ok = uniquePackageDeclarationAccepted && duplicatePackageDeclarationRejected;
        message = "package option declaration ownership";
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
        ok = packageValuesAreAtomicForDependencyOwnership;
        message = "package values are atomic for dependency ownership";
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
        ok = runtimeDirectGetsOperatorPriority && runtimeNestedMatchesOperator && runtimeOwnershipMatchesMergePriority && runtimeImportKeepsNormalPriority && runtimeNestedImportKeepsNormalPriority && runtimeProvisioningRejected && runtimeUnknownOptionRejected && runtimeImportedUnknownOptionRejected && runtimeUnknownOptionDeferredForSelection && hostUnknownOptionRemainsLazy;
        message = "runtime module priority, declared surface, and provisioning confinement";
      }
      {
        ok = uniqEnumAgrees && uniqEnumRejectsConflict && uniqEnumRejectsBadValue;
        message = "uniqEnum semantics";
      }
      {
        ok = confinedPackageImport && evaluatedPackageImportRejected && lexicalStringPackageImportRejected;
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
          echo "  types.addCheck — validates merged scalar/submodule/list values: OK"
          echo "  types.submodule — hides engine metadata and preserves merge semantics: OK"
          echo "  contributable surface exposed, marker inert: OK"
          echo "  operator tier-75 beats package, mkForce beats operator: OK"
          echo "  no operatorModules means no priority lift: OK"
          echo "  package provenance cannot forge operator priority: OK"
          echo "  types.uniqEnum agree/conflict: OK"
          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
    meta.description = "Regression guard for Phase 1-3 lib additions";
  }
