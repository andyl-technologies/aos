##! lib/testing/package-expose.nix — RFC-0001 package expose smoke check.
##!
##! Builds a normal discovered package with an `expose` block and verifies that
##! its integration artifacts are rendered in a separate store path.
{
  pkgs,
  lib,
  mkSystem,
  packagesWithExpose,
}: let
  pkg = pkgs.expose-smoke;
  configModulePackage = pkgs.config-module-smoke;
  configModuleOutput = configModulePackage.config;
  composedConfigModulePackage = pkgs.mkDerivation {
    pname = "composed-config-smoke";
    version = "0";
    src = null;
    runtimeDeps = [pkgs.bash];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          printf payload > "$out/payload"
          ln -s '${pkgs.bash}' "$out/bash"
        '';
      }
    ];
    configModule = {
      src = ../../pkgs/tests/_config-module-smoke;
      dependencies.bash = pkgs.bash;
      declares = [
        "configModuleSmoke.command"
        "configModuleSmoke.enable"
        "configModuleSmoke.privateMessage"
      ];
      ownsRoots = [{root = "configModuleSmoke";}];
    };
    expose = {};
  };
  configModulePayloadBaseline = pkgs.mkDerivation {
    pname = "config-module-smoke";
    version = "0";
    src = null;
    runtimeDeps = [pkgs.bash];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/config-module-smoke"
          printf '%s\n' payload > "$out/share/config-module-smoke/payload.txt"
          ln -s '${pkgs.bash}' "$out/share/config-module-smoke/bash"
        '';
      }
    ];
  };
  evaluatedConfigModule = lib.evalModules {
    modules = [
      {config.configModuleSmoke.enable = true;}
    ];
    packageModules = [
      {
        name = "config-module-smoke";
        authorization = {
          owns = ["configModuleSmoke"];
          contributes = {};
        };
        configRoot = ../../pkgs/tests/_config-module-smoke;
        module = ../../pkgs/tests/_config-module-smoke/module.nix;
        outputs = {
          self = "${configModulePackage}";
          dependencies.bash = configModulePackage.configModuleDependencies.bash;
        };
      }
    ];
  };
  configModuleEvalContract =
    lib.throwIfNot
    evaluatedConfigModule.config.configModuleSmoke.enable
    "config module fixture must evaluate through lib.evalModules"
    (lib.throwIfNot
      (evaluatedConfigModule.config.configModuleSmoke.command == "${pkgs.bash}/bin/bash")
      "config modules must resolve dependency output strings through evaluator injection"
      (lib.throwIfNot
        (evaluatedConfigModule.config.configModuleSmoke.privateMessage
          == "configModuleSmoke.enable remains evaluable")
        "config module fixture must import and use its private helper"
        true));
  configModuleContract =
    lib.throwIfNot
    (configModuleOutput.outputName == "config")
    "config module fixture must expose the named config output"
    (lib.throwIfNot
      (configModuleOutput.outPath != configModulePackage.outPath)
      "config output must be separate from the package payload output"
      (lib.throwIfNot
        (configModulePackage.configModule.outPath == configModuleOutput.outPath)
        "configModule compatibility alias must identify pkg.config"
        (lib.throwIfNot
          (configModulePackage.passthru.configModule.outPath == configModuleOutput.outPath)
          "passthru.configModule compatibility alias must identify pkg.config"
          (lib.throwIfNot
            (!(builtins.elem "config" configModulePackage.outputs))
            "companion config artifact must not alter payload derivation outputs"
            (lib.throwIfNot
              (configModulePackage.drvPath == configModulePayloadBaseline.drvPath)
              "configModule must not alter the payload derivation contract"
              true)))));
  phaseExitPackage = pkgs.mkDerivation {
    pname = "config-module-phase-exit";
    version = "0";
    src = null;
    phases = [
      {
        name = "authored-exit";
        script = ''
          mkdir -p "$out"
          printf payload > "$out/payload"
          exit 0
        '';
      }
    ];
    configModule = {
      src = ../../pkgs/tests/_config-module-smoke;
      declares = ["configModuleSmoke.enable"];
      ownsRoots = [{root = "configModuleSmoke";}];
    };
  };
  exitTrapPackage = pkgs.mkDerivation {
    pname = "config-module-exit-trap";
    version = "0";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          trap 'if [ -n "''${config:-}" ]; then chmod -R u+w "$config"; ln -sf /etc/passwd "$config/module.nix"; fi' EXIT
          mkdir -p "$out"
          printf payload > "$out/payload"
        '';
      }
    ];
    configModule = {
      src = ../../pkgs/tests/_config-module-smoke;
      declares = ["configModuleSmoke.enable"];
      ownsRoots = [{root = "configModuleSmoke";}];
    };
  };
  foreignDeclareRejected =
    !(builtins.tryEval ((pkgs.mkDerivation {
        pname = "config-module-foreign-declare";
        version = "0";
        src = null;
        phases = [];
        configModule = {
          src = ../../pkgs/tests/_config-module-smoke;
          declares = ["foreign.enable"];
          ownsRoots = [{root = "configModuleSmoke";}];
        };
      })
      .config
      .outPath))
    .success;
  privateDeclareAccepted =
    (builtins.tryEval ((pkgs.mkDerivation {
        pname = "private-root";
        version = "0";
        src = null;
        phases = [];
        configModule = {
          src = ../../pkgs/tests/_config-module-smoke;
          declares = ["private-root.enable"];
        };
      })
      .config
      .outPath))
    .success;
  contributionSiblingRejected =
    !(builtins.tryEval ((pkgs.mkDerivation {
        pname = "contribution-sibling";
        version = "0";
        src = null;
        phases = [];
        configModule = {
          src = ../../pkgs/tests/_config-module-smoke;
          declares = ["nginx.enable"];
          contributes = [
            {
              root = "nginx";
              interfaceAbi = 1;
              paths = ["virtualHosts"];
            }
          ];
        };
      })
      .config
      .outPath))
    .success;
  contributionDescendantAccepted =
    (builtins.tryEval ((pkgs.mkDerivation {
        pname = "contribution-descendant";
        version = "0";
        src = null;
        phases = [];
        configModule = {
          src = ../../pkgs/tests/_config-module-smoke;
          declares = ["nginx.virtualHosts.demo.enable"];
          contributes = [
            {
              root = "nginx";
              interfaceAbi = 1;
              paths = ["virtualHosts"];
            }
          ];
        };
      })
      .config
      .outPath))
    .success;
  typedExposeRejects = field: expose:
    lib.throwIfNot
    (!(builtins.tryEval (builtins.deepSeq (pkg.overrideAttrs (_: {inherit expose;})).expose true)).success)
    "typed expose module accepted invalid ${field}"
    true;
  typedFirewallRejected = typedExposeRejects "firewall" {
    firewall.allowedTCP = "443";
  };
  typedKernelRejected = typedExposeRejects "kernel" {
    kernel.modules = "br_netfilter";
  };
  typedUnitsRejected = typedExposeRejects "units" {
    units."bad.service" = "not-an-attrset";
  };
  typedArtifactsRejected = typedExposeRejects "config.artifacts" {
    config.artifacts = [
      {
        name = "bad";
        path = "/etc/aos/packages/expose-smoke/bad.env";
        optional = "TOKEN";
      }
    ];
  };
  typedPermissionsRejected = typedExposeRejects "permissions" {
    permissions."tcp-bind" = "443";
  };
  typedCredentialsRejected = typedExposeRejects "credentials" {
    config.credentials = [
      {
        name = "bad";
        encrypted = "yes";
      }
    ];
  };
  minimal = pkgs.mkDerivation {
    pname = "expose-minimal";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-minimal"
          printf expose-minimal > "$out/share/expose-minimal/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-minimal.service" = {
        description = "RFC-0001 expose minimal service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
    };
  };
  verityImageArtifact = pkgs.runCommand "expose-verity-root-image" {} ''
    mkdir -p "$out"
    printf image > "$out/root.img"
    printf verity > "$out/root.verity"
    printf signature > "$out/root.roothash.p7s"
  '';
  verityImageMeta = {
    format = "ext4-verity";
    store_path = "${verityImageArtifact}";
    nar_hash = "sha256:verity";
    nar_size = 1;
    root_image = "root.img";
    root_verity = "root.verity";
    root_hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    root_hash_sig = "root.roothash.p7s";
  };
  verityRoot = pkgs.mkDerivation {
    pname = "expose-verity-root";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-verity-root"
          printf expose-verity-root > "$out/share/expose-verity-root/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-verity-root.service" = {
        description = "RFC-0001 expose verity root service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      images = [
        verityImageMeta
      ];
    };
  };
  verityTupleMissing = builtins.tryEval (
    (verityRoot.overrideAttrs (_: {
      expose = {
        units."expose-verity-root.service" = {
          description = "RFC-0001 expose verity root service";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        images = [
          {
            format = "ext4-verity";
            store_path = "${verityImageArtifact}";
            nar_hash = "sha256:verity";
            nar_size = 1;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  verityTupleMissingRejected =
    if verityTupleMissing.success
    then throw "expose renderer must reject verity image formats without RootImage metadata"
    else "ok";
  verityAuthoredRootDirectory = builtins.tryEval (
    (verityRoot.overrideAttrs (_: {
      expose = {
        units."expose-verity-root.service" = {
          description = "RFC-0001 expose verity root service";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
            RootDirectory = "/srv/expose-verity-root";
          };
        };
        images = [
          verityImageMeta
        ];
      };
    }))
    .expose
    .outPath
  );
  verityAuthoredRootDirectoryRejected =
    if verityAuthoredRootDirectory.success
    then throw "expose renderer must reject authored RootDirectory with verity RootImage metadata"
    else "ok";
  verityUnconfined = builtins.tryEval (
    (verityRoot.overrideAttrs (_: {
      expose = {
        units."expose-verity-root.service" = {
          description = "RFC-0001 expose verity root service";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        permissions = {
          privileged-users = true;
        };
        images = [
          verityImageMeta
        ];
      };
    }))
    .expose
    .outPath
  );
  verityUnconfinedRejected =
    if verityUnconfined.success
    then throw "expose renderer must reject verity RootImage metadata on unconfined packages"
    else "ok";
  manualStart = pkgs.mkDerivation {
    pname = "expose-manual-start";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-manual-start"
          printf expose-manual-start > "$out/share/expose-manual-start/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-manual-start.service" = {
        description = "RFC-0001 expose manual-start service";
        onlyManualStart = true;
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
    };
  };
  testEncryptedCredential = pkgs.writeTextFile {
    name = "expose-config-generated-token-encrypted";
    destination = "/generated-token.cred";
    text = "opaque encrypted credential blob\n";
  };
  configPackage = pkgs.mkDerivation {
    pname = "expose-config";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-config"
          printf expose-config > "$out/share/expose-config/payload.txt"
        '';
      }
    ];

    expose = {
      units."expose-config.service" = {
        description = "RFC-0001 expose config service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      config = {
        artifacts = [
          {
            name = "env";
            path = "/etc/aos/packages/expose-config/config.env";
            format = "env";
            required = ["TOKEN"];
            optional = ["URL"];
            units = ["expose-config.service"];
            reload = "reload";
          }
        ];
        credentials = [
          {
            name = "join-token";
            source = "/usr/lib/credstore.encrypted/join-token";
            units = ["expose-config.service"];
            encrypted = true;
          }
          {
            name = "generated-token";
            encryptedFile = "${testEncryptedCredential}/generated-token.cred";
            units = ["expose-config.service"];
          }
          {
            name = "inline-secret";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config.service"];
            encrypted = true;
          }
          {
            name = "plain-note";
          }
        ];
      };
      provides = [
        {
          name = "data";
          kind = "directory";
          path = "/var/lib/expose-config/data";
        }
      ];
      uses = [
        {
          provider = "expose-config";
          name = "data";
          kind = "directory";
          unit = "expose-config.service";
        }
      ];
    };
  };
  splitConfigPackage = pkgs.mkDerivation {
    pname = "expose-config-split";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/expose-config-split"
          printf expose-config-split > "$out/share/expose-config-split/payload.txt"
        '';
      }
    ];

    expose = {
      units = {
        "expose-config-split-main.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        "expose-config-split-sidecar.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        "expose-config-split-socket.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        "expose-config-split-socket.socket" = {
          socketConfig.ListenStream = "127.0.0.1:18081";
        };
      };
      config.artifacts = [
        {
          name = "main";
          path = "/etc/aos/packages/expose-config-split/main.env";
          format = "env";
          required = ["TOKEN"];
          units = ["expose-config-split-main.service"];
        }
        {
          name = "sidecar";
          path = "/etc/aos/packages/expose-config-split/sidecar.env";
          format = "env";
          required = ["TOKEN"];
          units = ["expose-config-split-sidecar.service"];
        }
      ];
      config.credentials = [
        {
          name = "main-secret";
          source = "/usr/lib/credstore.encrypted/main-secret";
          units = ["expose-config-split-main.service"];
          encrypted = true;
        }
        {
          name = "sidecar-note";
          units = ["expose-config-split-sidecar.service"];
        }
        {
          name = "socket-secret";
          source = "/usr/lib/credstore.encrypted/socket-secret";
          units = ["expose-config-split-socket.service"];
          encrypted = true;
        }
      ];
      permissions.tcp-bind = [18081];
    };
  };
  unknownConfigUnit = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.artifacts = [
          {
            name = "bad";
            path = "/etc/aos/packages/expose-config-split/bad.env";
            format = "env";
            units = ["missing.service"];
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  unknownConfigUnitRejected =
    if unknownConfigUnit.success
    then throw "expose renderer must reject config artifacts that reference unknown units"
    else "ok";
  credentialNonServiceUnit = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            units = ["expose-config-split-main.socket"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialNonServiceUnitRejected =
    if credentialNonServiceUnit.success
    then throw "expose renderer must reject credentials that reference non-service units"
    else "ok";
  credentialBadSource = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            source = "/etc/shadow";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialBadSourceRejected =
    if credentialBadSource.success
    then throw "expose renderer must reject credential sources outside systemd credstore paths"
    else "ok";
  credentialBadSourceInjection = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            source = "/usr/lib/credstore.encrypted/bad\nPrivateNetwork=false";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialBadSourceInjectionRejected =
    if credentialBadSourceInjection.success
    then throw "expose renderer must reject credential source unit syntax injection"
    else "ok";
  credentialBadCiphertext = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            ciphertext = "abc\nPrivateNetwork=false";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialBadCiphertextRejected =
    if credentialBadCiphertext.success
    then throw "expose renderer must reject credential ciphertext unit syntax injection"
    else "ok";
  credentialPlainCiphertext = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialPlainCiphertextRejected =
    if credentialPlainCiphertext.success
    then throw "expose renderer must reject ciphertext on unencrypted credentials"
    else "ok";
  credentialSourceAndCiphertext = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            source = "/usr/lib/credstore.encrypted/bad";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialSourceAndCiphertextRejected =
    if credentialSourceAndCiphertext.success
    then throw "expose renderer must reject credentials that declare both source and ciphertext"
    else "ok";
  credentialGeneratedNamespaceSource = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            source = "/run/credstore.encrypted/aos/expose-config-split/bad";
            encrypted = true;
            units = ["expose-config-split-main.service"];
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialGeneratedNamespaceSourceRejected =
    if credentialGeneratedNamespaceSource.success
    then throw "expose renderer must reject source credentials in the generated /run credstore namespace"
    else "ok";
  credentialVendoredPlain = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            encryptedFile = "${testEncryptedCredential}/generated-token.cred";
            units = ["expose-config-split-main.service"];
            encrypted = false;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialVendoredPlainRejected =
    if credentialVendoredPlain.success
    then throw "expose renderer must reject vendored encrypted credentials with encrypted=false"
    else "ok";
  credentialVendoredCustomSource = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            source = "/run/credstore.encrypted/aos/other-package/bad";
            encryptedFile = "${testEncryptedCredential}/generated-token.cred";
            units = ["expose-config-split-main.service"];
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialVendoredCustomSourceRejected =
    if credentialVendoredCustomSource.success
    then throw "expose renderer must reject custom source paths on vendored encrypted credentials"
    else "ok";
  credentialVendoredCiphertext = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            encryptedFile = "${testEncryptedCredential}/generated-token.cred";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialVendoredCiphertextRejected =
    if credentialVendoredCiphertext.success
    then throw "expose renderer must reject vendored encrypted credentials with inline ciphertext"
    else "ok";
  credentialVendoredNonStoreFile = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            encryptedFile = "/tmp/generated-token.cred";
            units = ["expose-config-split-main.service"];
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialVendoredNonStoreFileRejected =
    if credentialVendoredNonStoreFile.success
    then throw "expose renderer must reject non-store encryptedFile paths"
    else "ok";
  credentialVendoredStoreParentTraversal = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "bad";
            encryptedFile = "/nix/store/../../tmp/generated-token.cred";
            units = ["expose-config-split-main.service"];
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialVendoredStoreParentTraversalRejected =
    if credentialVendoredStoreParentTraversal.success
    then throw "expose renderer must reject vendored encryptedFile store paths containing parent components"
    else "ok";
  credentialDuplicateName = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        config.credentials = [
          {
            name = "duplicate";
            source = "/usr/lib/credstore.encrypted/duplicate";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
          {
            name = "duplicate";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialDuplicateNameRejected =
    if credentialDuplicateName.success
    then throw "expose renderer must reject duplicate credential names"
    else "ok";
  credentialAuthoredCollision = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          SetCredentialEncrypted = "main-secret:abcDEF0123+/=";
        };
        config.credentials = [
          {
            name = "main-secret";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialAuthoredCollisionRejected =
    if credentialAuthoredCollision.success
    then throw "expose renderer must reject authored credential directive collisions with expose.config.credentials"
    else "ok";
  credentialAuthoredImportCollision = builtins.tryEval (
    (splitConfigPackage.overrideAttrs (_: {
      expose = {
        units."expose-config-split-main.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          ImportCredential = "main-secret";
        };
        config.credentials = [
          {
            name = "main-secret";
            ciphertext = "abcDEF0123+/=";
            units = ["expose-config-split-main.service"];
            encrypted = true;
          }
        ];
      };
    }))
    .expose
    .outPath
  );
  credentialAuthoredImportCollisionRejected =
    if credentialAuthoredImportCollision.success
    then throw "expose renderer must reject authored ImportCredential collisions with expose.config.credentials"
    else "ok";
  k3sWorkerPackage = pkgs.k3s-worker;
  k3sControlPlanePackage = pkgs.k3s-control-plane;
  k3sCombinedPackage = pkgs.k3s-combined;
  overridden = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-override.service" = {
        description = "RFC-0001 expose override service";
        wantedBy = ["aos-pkg-expose-smoke.target"];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions.network = "private";
    };
  });
  reservedCollision = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."aos-pkg-expose-smoke-firewall.service" = {};
        permissions.network = "private";
      };
    }))
    .expose
    .outPath
  );
  reservedCollisionRejected =
    if reservedCollision.success
    then throw "expose renderer must reject package-authored synthesized side-effect unit names"
    else "ok";
  targetMismatch = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        target = "aos-pkg-other.target";
        units."expose-smoke-target-mismatch.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        permissions.network = "private";
      };
    }))
    .expose
    .outPath
  );
  targetMismatchRejected =
    if targetMismatch.success
    then throw "expose renderer must reject expose.target values that are not bound to the package name"
    else "ok";
  privilegedExecPrefix = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-privileged-prefix.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "+${pkgs.bash}/bin/bash -c true";
          };
        };
        permissions.network = "private";
      };
    }))
    .expose
    .outPath
  );
  privilegedExecPrefixRejected =
    if privilegedExecPrefix.success
    then throw "expose renderer must reject systemd privileged Exec* prefixes on workload services"
    else "ok";
  landlockScriptDerivedExec = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-landlock-script-derived.service" = {
          preStart = ''
            true
          '';
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        permissions = {
          network = "private";
        };
      };
    }))
    .expose
    .outPath
  );
  landlockScriptDerivedExecRejected =
    if landlockScriptDerivedExec.success
    then throw "expose renderer must reject script-derived Exec* commands for Landlock services"
    else "ok";
  landlockShellExecPrefix = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-landlock-shell-prefix.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "|${pkgs.bash}/bin/bash -c true";
          };
        };
        permissions.network = "private";
      };
    }))
    .expose
    .outPath
  );
  landlockShellExecPrefixRejected =
    if landlockShellExecPrefix.success
    then throw "expose renderer must reject systemd shell Exec* prefixes for Landlock services"
    else "ok";
  landlockCombinedExecPrefix = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-landlock-combined-prefix.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "|+${pkgs.bash}/bin/bash -c true";
          };
        };
        permissions.network = "private";
      };
    }))
    .expose
    .outPath
  );
  landlockCombinedExecPrefixRejected =
    if landlockCombinedExecPrefix.success
    then throw "expose renderer must reject combined systemd Exec* prefixes for Landlock services"
    else "ok";
  landlockSlashlessExec = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-landlock-slashless.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "bash -c true";
          };
        };
        permissions.network = "private";
      };
    }))
    .expose
    .outPath
  );
  landlockSlashlessExecRejected =
    if landlockSlashlessExec.success
    then throw "expose renderer must reject slashless Exec* executables for Landlock services"
    else "ok";
  landlockExecReset = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-landlock-reset.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = [
            ""
            "${pkgs.bash}/bin/bash -c true"
          ];
          ExecStartPre = [
            ""
            "${pkgs.bash}/bin/bash -c true"
          ];
        };
      };
      permissions.network = "private";
    };
  });
  landlockExecResetEval = builtins.tryEval landlockExecReset.expose.outPath;
  landlockExecResetAccepted =
    if landlockExecResetEval.success
    then "ok"
    else throw "expose renderer must preserve empty Exec*= reset entries for Landlock services";
  socketMissingTcpBind = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-missing-tcp-bind.socket".socketConfig.ListenStream = "127.0.0.1:18082";
        permissions = {
          network = "private";
        };
      };
    }))
    .expose
    .outPath
  );
  socketMissingTcpBindRejected =
    if socketMissingTcpBind.success
    then throw "expose renderer must reject TCP socket listeners without matching permissions.tcp-bind grants"
    else "ok";
  socketListenStreamsMissingTcpBind = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-listen-streams-missing-tcp-bind.socket".listenStreams = ["127.0.0.1:18083"];
        permissions = {
          network = "private";
        };
      };
    }))
    .expose
    .outPath
  );
  socketListenStreamsMissingTcpBindRejected =
    if socketListenStreamsMissingTcpBind.success
    then throw "expose renderer must reject typed listenStreams without matching permissions.tcp-bind grants"
    else "ok";
  socketListenStreamReset = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-listen-stream-reset.socket".socketConfig.ListenStream = [
          "127.0.0.1:18084"
          ""
        ];
        permissions = {
          network = "private";
        };
      };
    }))
    .expose
    .outPath
  );
  socketListenStreamResetAccepted =
    if socketListenStreamReset.success
    then "ok"
    else throw "expose renderer must honor empty ListenStream reset semantics";
  kernelModulePermissionMismatch = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-kernel-module-mismatch.service" = {
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${pkgs.bash}/bin/bash -c true";
          };
        };
        kernel.modules = ["br_netfilter"];
        permissions = {
          network = "private";
          kernel-modules = [];
        };
      };
    }))
    .expose
    .outPath
  );
  kernelModulePermissionMismatchRejected =
    if kernelModulePermissionMismatch.success
    then throw "expose renderer must reject host module loads that are absent from permissions.kernel-modules"
    else "ok";
  undeclaredPreparedHostPathDirectory = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-undeclared-prep.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        permissions = {
          network = "private";
          host-paths = [];
        };
        prepareHostPathDirectories = ["/srv/expose-smoke-rw"];
      };
    }))
    .expose
    .outPath
  );
  undeclaredPreparedHostPathDirectoryRejected =
    if undeclaredPreparedHostPathDirectory.success
    then throw "expose renderer must reject prepared host path directories absent from rw permissions.host-paths"
    else "ok";
  readOnlyPreparedHostPathDirectory = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-read-only-prep.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        permissions = {
          network = "private";
          host-paths = [
            {
              path = "/srv/expose-smoke-ro";
              mode = "read-only";
            }
          ];
        };
        prepareHostPathDirectories = ["/srv/expose-smoke-ro"];
      };
    }))
    .expose
    .outPath
  );
  readOnlyPreparedHostPathDirectoryRejected =
    if readOnlyPreparedHostPathDirectory.success
    then throw "expose renderer must reject read-only prepared host path directories"
    else "ok";
  unsupportedHostPathCharacters = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-bad-host-path-chars.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        permissions = {
          network = "private";
          host-paths = [
            {
              path = "/srv/expose smoke";
              mode = "rw";
            }
          ];
        };
      };
    }))
    .expose
    .outPath
  );
  unsupportedHostPathCharactersRejected =
    if unsupportedHostPathCharacters.success
    then throw "expose renderer must reject host paths with unsupported characters"
    else "ok";
  readOnlyTempHostPath = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-read-only-temp-host-path.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
        permissions = {
          network = "private";
          host-paths = [
            {
              path = "/tmp/expose-smoke-ro";
              mode = "read-only";
            }
          ];
        };
      };
    }))
    .expose
    .outPath
  );
  readOnlyTempHostPathRejected =
    if readOnlyTempHostPath.success
    then throw "expose renderer must reject read-only host paths under writable temp grants"
    else "ok";
  staticUser = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-static-user.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          User = "aos-static";
          Group = "aos-static";
          StateDirectory = "expose-smoke-static";
        };
      };
      permissions = {
        network = "private";
      };
    };
  });
  rootUserWithoutPrivilege = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-root-user.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          User = "root";
        };
        permissions = {
          network = "private";
        };
      };
    }))
    .expose
    .outPath
  );
  rootUserWithoutPrivilegeRejected =
    if rootUserWithoutPrivilege.success
    then throw "expose renderer must reject User=root without permissions.privileged-users"
    else "ok";
  numericRootUserWithoutPrivilege = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-root-user-numeric.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          User = "0";
        };
        permissions = {
          network = "private";
        };
      };
    }))
    .expose
    .outPath
  );
  numericRootUserWithoutPrivilegeRejected =
    if numericRootUserWithoutPrivilege.success
    then throw "expose renderer must reject User=0 without permissions.privileged-users"
    else "ok";
  dynamicUserFalseWithoutIdentity = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-dynamic-user-false.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          DynamicUser = false;
        };
        permissions = {
          network = "private";
        };
      };
    }))
    .expose
    .outPath
  );
  dynamicUserFalseWithoutIdentityRejected =
    if dynamicUserFalseWithoutIdentity.success
    then throw "expose renderer must reject DynamicUser=false without User or privileged-users"
    else "ok";
  dynamicUserStringFalse = builtins.tryEval (
    (pkg.overrideAttrs (_: {
      expose = {
        units."expose-smoke-dynamic-user-string-false.service".serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          DynamicUser = "false";
        };
        permissions = {
          network = "private";
        };
      };
    }))
    .expose
    .outPath
  );
  dynamicUserStringFalseRejected =
    if dynamicUserStringFalse.success
    then throw "expose renderer must reject non-boolean DynamicUser values"
    else "ok";
  permissionOnlyModules = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-permission-only-modules.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private";
        kernel-modules = ["br_netfilter"];
      };
    };
  });
  hostPathWithoutPrepare = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-rw-host-path.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private";
        host-paths = [
          {
            path = "/srv/expose-smoke-rw";
            mode = "rw";
          }
        ];
      };
    };
  });
  privateOutbound = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-private-outbound.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
          ExecReload = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private-outbound";
        tcp-bind = [8000];
        tcp-connect = [443];
      };
    };
  });
  withHoles = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-holes.service" = {
        description = "RFC-0001 expose sandboxed-with-holes label service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private";
        capabilities = ["CAP_NET_BIND_SERVICE"];
      };
    };
  });
  unconfined = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-unconfined.service" = {
        description = "RFC-0001 expose unconfined label service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "host";
        capabilities = ["CAP_NET_ADMIN"];
        host-paths = [
          {
            path = "/srv/expose-smoke-unconfined";
            mode = "read-only";
          }
        ];
        privileged-users = true;
      };
    };
  });
  privilegedSyscalls = pkg.overrideAttrs (_: {
    expose = {
      units."expose-smoke-privileged-syscalls.service" = {
        description = "RFC-0001 expose privileged syscalls label service";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions = {
        network = "private";
        syscalls = "privileged";
      };
    };
  });
  regexNamePrivateOutbound = pkg.overrideAttrs (_: {
    pname = "expose.smoke.regex";
    expose = {
      units."expose-smoke-regex-private-outbound.service" = {
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${pkgs.bash}/bin/bash -c true";
        };
      };
      permissions.network = "private-outbound";
    };
  });
in
  pkgs.mkDerivation {
    pname = "package-expose-check";
    version = "0";
    src = null;

    payload = pkg;
    exposePath = pkg.expose;
    generatedExposeConfigOutput = pkg.config;
    inherit configModuleContract configModuleEvalContract configModuleOutput;
    configModulePayload = configModulePackage;
    configModuleAlias = configModulePackage.configModule;
    composedConfigModuleOutput = composedConfigModulePackage.config;
    inherit
      phaseExitPackage
      exitTrapPackage
      foreignDeclareRejected
      privateDeclareAccepted
      contributionSiblingRejected
      contributionDescendantAccepted
      typedFirewallRejected
      typedKernelRejected
      typedUnitsRejected
      typedArtifactsRejected
      typedPermissionsRejected
      typedCredentialsRejected
      ;
    phaseExitConfig = phaseExitPackage.config;
    exitTrapConfig = exitTrapPackage.config;
    exposeConfinement = builtins.toJSON pkg.expose.passthru.confinement;
    minimalPayload = minimal;
    minimalExposePath = minimal.expose;
    verityRootExposePath = verityRoot.expose;
    inherit verityImageArtifact;
    manualStartExposePath = manualStart.expose;
    configExposePath = configPackage.expose;
    splitConfigExposePath = splitConfigPackage.expose;
    overriddenPayload = overridden;
    overriddenExposePath = overridden.expose;
    staticUserExposePath = staticUser.expose;
    permissionOnlyModulesExposePath = permissionOnlyModules.expose;
    withHolesExposePath = withHoles.expose;
    unconfinedExposePath = unconfined.expose;
    privilegedSyscallsExposePath = privilegedSyscalls.expose;
    privateOutboundExposePath = privateOutbound.expose;
    regexNamePrivateOutboundExposePath = regexNamePrivateOutbound.expose;
    landlockExecResetExposePath = landlockExecReset.expose;
    hostPathWithoutPrepareExposePath = hostPathWithoutPrepare.expose;
    k3sWorkerExposePath = k3sWorkerPackage.expose;
    k3sControlPlaneExposePath = k3sControlPlanePackage.expose;
    k3sCombinedExposePath = k3sCombinedPackage.expose;
    inherit
      reservedCollisionRejected
      targetMismatchRejected
      verityTupleMissingRejected
      privilegedExecPrefixRejected
      landlockScriptDerivedExecRejected
      landlockShellExecPrefixRejected
      landlockCombinedExecPrefixRejected
      landlockSlashlessExecRejected
      landlockExecResetAccepted
      socketMissingTcpBindRejected
      socketListenStreamsMissingTcpBindRejected
      socketListenStreamResetAccepted
      kernelModulePermissionMismatchRejected
      unknownConfigUnitRejected
      credentialNonServiceUnitRejected
      credentialBadSourceRejected
      credentialBadSourceInjectionRejected
      credentialBadCiphertextRejected
      credentialPlainCiphertextRejected
      credentialSourceAndCiphertextRejected
      credentialGeneratedNamespaceSourceRejected
      credentialVendoredPlainRejected
      credentialVendoredCustomSourceRejected
      credentialVendoredCiphertextRejected
      credentialVendoredNonStoreFileRejected
      credentialVendoredStoreParentTraversalRejected
      credentialDuplicateNameRejected
      credentialAuthoredCollisionRejected
      credentialAuthoredImportCollisionRejected
      undeclaredPreparedHostPathDirectoryRejected
      readOnlyPreparedHostPathDirectoryRejected
      verityAuthoredRootDirectoryRejected
      verityUnconfinedRejected
      unsupportedHostPathCharactersRejected
      readOnlyTempHostPathRejected
      rootUserWithoutPrivilegeRejected
      numericRootUserWithoutPrivilegeRejected
      dynamicUserFalseWithoutIdentityRejected
      dynamicUserStringFalseRejected
      ;

    buildDeps =
      (builtins.map (pkg: pkg.exposeCheck) (builtins.attrValues packagesWithExpose))
      ++ [
        minimal.exposeCheck
        verityRoot.exposeCheck
        manualStart.exposeCheck
        configPackage.exposeCheck
        splitConfigPackage.exposeCheck
        overridden.exposeCheck
        staticUser.exposeCheck
        permissionOnlyModules.exposeCheck
        withHoles.exposeCheck
        unconfined.exposeCheck
        privilegedSyscalls.exposeCheck
        privateOutbound.exposeCheck
        regexNamePrivateOutbound.exposeCheck
        hostPathWithoutPrepare.exposeCheck
        k3sWorkerPackage.exposeCheck
        k3sControlPlanePackage.exposeCheck
        k3sCombinedPackage.exposeCheck
      ];

    phases = [
      {
        name = "check";
        script = ''
          set -eu

          : "$configModuleContract"
          : "$configModuleEvalContract"
          : "$foreignDeclareRejected"
          : "$privateDeclareAccepted"
          : "$contributionSiblingRejected"
          : "$contributionDescendantAccepted"
          : "$typedFirewallRejected"
          : "$typedKernelRejected"
          : "$typedUnitsRejected"
          : "$typedArtifactsRejected"
          : "$typedPermissionsRejected"
          : "$typedCredentialsRejected"
          test "$configModuleOutput" != "$configModulePayload"
          test "$configModuleAlias" = "$configModuleOutput"
          test -f "$configModuleOutput/module.nix"
          test -f "$configModuleOutput/private.nix"
          test -f "$configModuleOutput/config-meta.json"
          test -f "$phaseExitPackage/payload"
          test -f "$phaseExitConfig/module.nix"
          test -f "$exitTrapPackage/payload"
          test -f "$exitTrapConfig/module.nix"
          test ! -L "$exitTrapConfig/module.nix"
          grep -q 'aos.config-module-meta/v1' "$configModuleOutput/config-meta.json"
          grep -q 'configModuleSmoke.enable' "$configModuleOutput/config-meta.json"
          if grep -R -n -F "$NIX_STORE_DIR/" "$configModuleOutput"; then
            echo "config output contains a Nix store-path literal" >&2
            exit 1
          fi
          test -f "$composedConfigModuleOutput/module.nix"
          test -f "$composedConfigModuleOutput/authored/module.nix"
          test -f "$composedConfigModuleOutput/authored/private.nix"
          test -f "$composedConfigModuleOutput/generated/module.nix"
          test -f "$composedConfigModuleOutput/generated/expose-config.json"
          grep -q 'configModuleSmoke.enable' "$composedConfigModuleOutput/config-meta.json"
          grep -q 'composed-config-smoke._aosExposeConfigProjection' "$composedConfigModuleOutput/config-meta.json"
          grep -q './authored/module.nix' "$composedConfigModuleOutput/module.nix"
          grep -q './generated/module.nix' "$composedConfigModuleOutput/module.nix"
          test "$generatedExposeConfigOutput" != "$payload"
          test -f "$generatedExposeConfigOutput/module.nix"
          test -f "$generatedExposeConfigOutput/expose-config.json"
          test -f "$generatedExposeConfigOutput/config-meta.json"
          grep -q 'aos.expose-config-binding/v1' "$generatedExposeConfigOutput/module.nix"
          grep -q 'expose-smoke._aosExposeConfigProjection' "$generatedExposeConfigOutput/config-meta.json"
          grep -q '"package":"expose-smoke"' "$generatedExposeConfigOutput/expose-config.json"
          if grep -R -n -F "$NIX_STORE_DIR/" "$generatedExposeConfigOutput"; then
            echo "generated expose config output contains a Nix store-path literal" >&2
            exit 1
          fi

          unit="$exposePath/units/expose-smoke.service"
          target="$exposePath/units/aos-pkg-expose-smoke.target"
          slice="$exposePath/units/aos-pkg-expose-smoke.slice"
          modules="$exposePath/units/aos-pkg-expose-smoke-modules.service"
          sysctl="$exposePath/units/aos-pkg-expose-smoke-sysctl.service"
          firewall="$exposePath/units/aos-pkg-expose-smoke-firewall.service"
          netns="$exposePath/units/aos-pkg-expose-smoke-netns.service"
          mac="$exposePath/units/aos-pkg-expose-smoke-mac.service"
          ebpf="$exposePath/units/aos-pkg-expose-smoke-ebpf.service"
          manifest="$exposePath/manifest.json"
          policy="$exposePath/network-policy.json"
          mac_profile="$exposePath/mac-profile.json"
          selinux_profile="$exposePath/mac/selinux/aos_x2eexpose_x2dsmoke.pp"
          selinux_module="$exposePath/mac/selinux/aos_x2eexpose_x2dsmoke.mod"
          selinux_source="$exposePath/mac/selinux/aos_x2eexpose_x2dsmoke.te"

          test -d "$exposePath/units"
          test -f "$unit"
          test -f "$target"
          test -f "$slice"
          test -f "$modules"
          test -f "$sysctl"
          test -f "$firewall"
          test ! -f "$netns"
          test -f "$mac"
          test -f "$ebpf"
          test -f "$manifest"
          test -f "$policy"
          test -f "$mac_profile"
          test -s "$selinux_profile"
          test -s "$selinux_module"
          test -f "$selinux_source"

          grep -q 'Description=RFC-0001 expose smoke service' "$unit"
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$unit"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$unit"
          grep -q 'After=network.target aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service aos-pkg-expose-smoke-mac.service aos-pkg-expose-smoke-ebpf.service' "$unit"
          grep -q 'Requires=aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service aos-pkg-expose-smoke-mac.service aos-pkg-expose-smoke-ebpf.service' "$unit"
          grep -q 'ExecStart=.*/bin/aos-selinux-run --context system_u:system_r:aos_x2eexpose_x2dsmoke_t -- .*/bin/aos-landlock --require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /var/lib/aos-pkg-expose-smoke -- ${pkgs.bash}/bin/bash -c true' "$unit"
          grep -q "RootDirectory=$payload" "$unit"
          grep -q 'MountAPIVFS=true' "$unit"
          grep -q 'ProtectSystem=strict' "$unit"
          grep -q 'ProtectHome=true' "$unit"
          grep -q 'PrivateTmp=disconnected' "$unit"
          grep -q 'TemporaryFileSystem=/tmp' "$unit"
          grep -q 'TemporaryFileSystem=/var/tmp' "$unit"
          grep -q 'StateDirectory=aos-pkg-expose-smoke' "$unit"
          grep -q 'NoNewPrivileges=true' "$unit"
          grep -q 'DynamicUser=true' "$unit"
          grep -q 'PrivateUsers=identity' "$unit"
          grep -q 'PrivateNetwork=true' "$unit"
          grep -q 'PrivateDevices=true' "$unit"
          grep -q 'DevicePolicy=closed' "$unit"
          grep -q '^CapabilityBoundingSet=$' "$unit"
          grep -q '^AmbientCapabilities=$' "$unit"
          grep -q 'BindReadOnlyPaths=/nix/store' "$unit"
          grep -q 'ProtectKernelTunables=true' "$unit"
          grep -q 'ProtectKernelModules=true' "$unit"
          grep -q 'ProtectKernelLogs=true' "$unit"
          grep -q 'ProtectControlGroups=private' "$unit"
          grep -q 'SystemCallFilter=@system-service landlock_create_ruleset landlock_add_rule landlock_restrict_self' "$unit"
          grep -q 'SystemCallErrorNumber=EPERM' "$unit"
          grep -q 'SystemCallArchitectures=native' "$unit"
          grep -q 'ProtectClock=true' "$unit"
          grep -q 'ProtectProc=invisible' "$unit"
          grep -q 'ProcSubset=pid' "$unit"
          grep -q 'ProtectHostname=true' "$unit"
          grep -q 'RestrictAddressFamilies=AF_UNIX' "$unit"
          grep -q 'RestrictAddressFamilies=AF_INET' "$unit"
          grep -q 'RestrictAddressFamilies=AF_INET6' "$unit"
          grep -q 'RestrictNamespaces=true' "$unit"
          grep -q 'RestrictRealtime=true' "$unit"
          grep -q 'RestrictSUIDSGID=true' "$unit"
          grep -q 'LockPersonality=true' "$unit"
          grep -q 'MemoryDenyWriteExecute=true' "$unit"
          grep -q 'Slice=aos-pkg-expose-smoke.slice' "$unit"
          grep -q 'Where=/var/lib/exposesmoke' "$exposePath/units/var-lib-exposesmoke.mount"

          grep -q 'Description=Activation target for expose-smoke' "$target"
          grep -q 'Wants=aos-pkg-expose-smoke.slice expose-smoke.service var-lib-exposesmoke.mount aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service aos-pkg-expose-smoke-mac.service aos-pkg-expose-smoke-ebpf.service' "$target"
          test ! -e "$exposePath/units/multi-user.target.wants/aos-pkg-expose-smoke.target"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke.slice"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/expose-smoke.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/var-lib-exposesmoke.mount"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-modules.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-sysctl.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-firewall.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-mac.service"
          test -L "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-ebpf.service"
          test ! -e "$exposePath/units/aos-pkg-expose-smoke.target.wants/aos-pkg-expose-smoke-netns.service"
          test ! -e "$exposePath/units/multi-user.target.wants/expose-smoke.service"
          test ! -e "$exposePath/units/multi-user.target.requires/expose-smoke.service"
          test ! -e "$exposePath/units/multi-user.target.upholds/expose-smoke.service"
          test ! -e "$exposePath/units/multi-user.target.wants/var-lib-exposesmoke.mount"
          if find "$exposePath" \
            \( -path '*/modules-load.d/*' -o -path '*/sysctl.d/*' -o -path '*/nftables.d/*' \) \
            | grep .; then
            echo "package expose output must not contain global scan-dir entries" >&2
            exit 1
          fi

          grep -q 'Description=Apply kernel modules for expose-smoke' "$modules"
          if grep -q 'RootDirectory=' "$modules"; then
            echo "host-side modules service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$modules"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$modules"
          grep -q 'ExecStart=${pkgs.kmod}/sbin/modprobe -a br_netfilter' "$modules"

          grep -q 'Description=Apply sysctl settings for expose-smoke' "$sysctl"
          if grep -q 'RootDirectory=' "$sysctl"; then
            echo "host-side sysctl service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$sysctl"
          grep -q 'After=aos-pkg-expose-smoke-modules.service' "$sysctl"
          grep -q 'Requires=aos-pkg-expose-smoke-modules.service' "$sysctl"
          grep -q 'ExecStart=${pkgs.procps-ng}/sbin/sysctl -w net.ipv4.ip_forward=1' "$sysctl"

          grep -q 'Description=Apply firewall rules for expose-smoke' "$firewall"
          if grep -q 'RootDirectory=' "$firewall"; then
            echo "host-side firewall service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$firewall"
          grep -q 'After=nftables.service' "$firewall"
          grep -q 'Requires=nftables.service' "$firewall"
          grep -q 'ReloadPropagatedFrom=nftables.service' "$firewall"
          firewall_start="$(sed -n 's/^ExecStart=//p' "$firewall")"
          firewall_reload="$(sed -n 's/^ExecReload=//p' "$firewall")"
          firewall_stop="$(sed -n 's/^ExecStop=//p' "$firewall")"
          test "$firewall_start" = "$firewall_reload"
          test -x "$firewall_start"
          test -x "$firewall_stop"
          grep -q 'aos-pkg-expose-smoke-firewall-apply' "$firewall"
          grep -q 'aos-pkg-expose-smoke-firewall-revert' "$firewall"
          grep -Fq '${pkgs.nftables}/sbin/nft add element inet filter allowed_tcp { 8000, 8443 }' "$firewall_start"
          grep -Fq '${pkgs.nftables}/sbin/nft add element inet filter allowed_udp { 5353 }' "$firewall_start"
          grep -Fq 'aos-pkg-expose-smoke-firewall-forward-start' "$firewall_start"
          grep -Fq '${pkgs.nftables}/sbin/nft delete element inet filter allowed_tcp { 8000, 8443 }' "$firewall_stop"
          grep -Fq '${pkgs.nftables}/sbin/nft delete element inet filter allowed_udp { 5353 }' "$firewall_stop"
          grep -Fq 'aos-pkg-expose-smoke-firewall-forward-stop' "$firewall_stop"

          grep -q 'Description=Load SELinux policy module for expose-smoke' "$mac"
          if grep -q 'RootDirectory=' "$mac"; then
            echo "host-side MAC policy service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          if grep -q 'aos-landlock' "$mac"; then
            echo "host-side MAC policy service must not run through aos-landlock" >&2
            exit 1
          fi
          if grep -q 'aos-selinux-run' "$mac"; then
            echo "host-side MAC policy service must not run through aos-selinux-run" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$mac"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$mac"
          grep -q 'Before=expose-smoke.service var-lib-exposesmoke.mount' "$mac"
          grep -q 'ConditionSecurity=selinux' "$mac"
          grep -q 'Type=oneshot' "$mac"
          grep -q 'RemainAfterExit=true' "$mac"
          grep -q 'Slice=aos-pkg-expose-smoke.slice' "$mac"
          grep -q 'NoNewPrivileges=true' "$mac"
          grep -q 'CapabilityBoundingSet=CAP_MAC_ADMIN' "$mac"
          grep -q '^AmbientCapabilities=$' "$mac"
          grep -q 'PrivateDevices=true' "$mac"
          grep -q 'DevicePolicy=closed' "$mac"
          grep -q 'PrivateNetwork=true' "$mac"
          grep -q 'ProtectSystem=full' "$mac"
          grep -q 'ReadWritePaths=/etc/selinux /var/lib/selinux' "$mac"
          grep -q 'ProtectHome=true' "$mac"
          grep -q 'RestrictAddressFamilies=AF_UNIX' "$mac"
          grep -q 'RestrictNamespaces=true' "$mac"
          grep -q 'MemoryDenyWriteExecute=true' "$mac"
          grep -Fq "ExecStart=${pkgs.policycoreutils}/sbin/semodule -i $exposePath/mac/selinux/aos_x2eexpose_x2dsmoke.pp" "$mac"

          grep -q 'Description=Attach eBPF network policy for expose-smoke' "$ebpf"
          if grep -q 'RootDirectory=' "$ebpf"; then
            echo "host-side eBPF policy service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          if grep -q 'aos-landlock' "$ebpf"; then
            echo "host-side eBPF policy service must not run through aos-landlock" >&2
            exit 1
          fi
          if grep -q 'aos-selinux-run' "$ebpf"; then
            echo "host-side eBPF policy service must not run through aos-selinux-run" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$ebpf"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$ebpf"
          grep -q 'Before=expose-smoke.service var-lib-exposesmoke.mount' "$ebpf"
          grep -q 'Type=notify' "$ebpf"
          grep -q 'NotifyAccess=main' "$ebpf"
          grep -q 'Slice=aos-pkg-expose-smoke.slice' "$ebpf"
          grep -q 'NoNewPrivileges=true' "$ebpf"
          grep -q 'CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE' "$ebpf"
          grep -q '^AmbientCapabilities=$' "$ebpf"
          grep -q 'LimitMEMLOCK=infinity' "$ebpf"
          grep -q 'PrivateDevices=true' "$ebpf"
          grep -q 'DevicePolicy=closed' "$ebpf"
          grep -q 'PrivateNetwork=true' "$ebpf"
          grep -q 'ProtectSystem=strict' "$ebpf"
          grep -q 'ProtectHome=true' "$ebpf"
          grep -q 'RestrictAddressFamilies=AF_UNIX' "$ebpf"
          grep -q 'RestrictNamespaces=true' "$ebpf"
          grep -q 'MemoryDenyWriteExecute=true' "$ebpf"
          grep -Fq "ExecStart=${pkgs.aos-ebpf-net-policy}/bin/aos-ebpf-net-policy run --policy $exposePath/network-policy.json --cgroup /sys/fs/cgroup/aos.slice/aos-pkg.slice/aos-pkg-expose.slice/aos-pkg-expose-smoke.slice --object ${pkgs.aos-ebpf-net-policy}/lib/bpf/aos-ebpf-net-policy.bpf.o" "$ebpf"

          grep -q '"target":"aos-pkg-expose-smoke.target"' "$manifest"
          grep -q '"aos-pkg-expose-smoke.target"' "$manifest"
          grep -q '"aos-pkg-expose-smoke.slice"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-modules.service"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-sysctl.service"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-firewall.service"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-mac.service"' "$manifest"
          grep -q '"aos-pkg-expose-smoke-ebpf.service"' "$manifest"
          grep -q '"expose-smoke.service"' "$manifest"
          grep -q '"var-lib-exposesmoke.mount"' "$manifest"
          grep -q '"modules":\["br_netfilter"\]' "$manifest"
          grep -q '"landlock":{"abi":4,"fs":{"readOnly":\["/"\],"readWrite":\["/tmp","/var/tmp","/var/lib/aos-pkg-expose-smoke"\]}' \
            "$policy"
          grep -q '"ebpf":{"hooks":\["socket_bind","socket_connect"\],"identity":"aos.expose-smoke","tcp":{"bind":\[\],"connect":\[\]}}' \
            "$policy"
          grep -q '"sysctl":{"net.ipv4.ip_forward":"1"}' "$manifest"
          grep -q '"allowedTCP":\[8000,8443\]' "$manifest"
          grep -q '"allowedUDP":\[5353\]' "$manifest"
          grep -q '"forwardPolicy":"accept"' "$manifest"
          grep -q '"confinement":{"class":"sandboxed","holes":\[\],"label":"sandboxed"}' "$manifest"
          test "$exposeConfinement" = '{"class":"sandboxed","holes":[],"label":"sandboxed"}'
          grep -q '"network":"private"' "$manifest"
          grep -q '"security-label":"aos.expose-smoke"' "$manifest"
          grep -q '"syscalls":"restricted"' "$manifest"
          grep -Fq '"mac":' "$manifest"
          grep -Fq '"backend":"selinux"' "$mac_profile"
          grep -Fq '"defaultDeny":true' "$mac_profile"
          grep -Fq '"package":"expose-smoke"' "$mac_profile"
          grep -Fq '"profilePath":"mac/selinux/aos_x2eexpose_x2dsmoke.pp"' "$mac_profile"
          grep -Fq '"securityLabel":"aos.expose-smoke"' "$mac_profile"
          grep -Fq 'module aos_x2eexpose_x2dsmoke 1.0;' "$selinux_source"
          grep -Fq 'type aos_x2eexpose_x2dsmoke_t;' "$selinux_source"
          grep -Fq 'typeattribute aos_x2eexpose_x2dsmoke_t domain;' "$selinux_source"
          grep -Fq 'role system_r types aos_x2eexpose_x2dsmoke_t;' "$selinux_source"
          grep -Fq 'class fd use;' "$selinux_source"
          grep -Fq 'allow aos_x2eexpose_x2dsmoke_t init_t:fd use;' "$selinux_source"
          grep -Fq 'allow aos_x2eexpose_x2dsmoke_t kernel_t:fd use;' "$selinux_source"
          grep -Fq 'allow kernel_t aos_x2eexpose_x2dsmoke_t:process dyntransition;' "$selinux_source"
          grep -Fq 'allow aos_x2eexpose_x2dsmoke_t self:process { execmem execstack execheap };' "$selinux_source"
          grep -Fq 'allow aos_x2eexpose_x2dsmoke_t self:process2 { nnp_transition nosuid_transition };' "$selinux_source"
          grep -Fq 'allow aos_x2eexpose_x2dsmoke_t file_type:file execmod;' "$selinux_source"
          grep -Fq 'allow aos_x2eexpose_x2dsmoke_t root_t:dir { getattr open read search };' "$selinux_source"
          grep -Fq 'allow aos_x2eexpose_x2dsmoke_t tmpfs_t:dir { getattr open read search };' "$selinux_source"
          grep -Fq 'allow aos_x2eexpose_x2dsmoke_t var_lib_t:dir { getattr open read search };' "$selinux_source"
          grep -Fq 'allow aos_x2eexpose_x2dsmoke_t unlabeled_t:file { execute execute_no_trans execmod getattr map open read };' "$selinux_source"

          minimal_unit="$minimalExposePath/units/expose-minimal.service"
          minimal_target="$minimalExposePath/units/aos-pkg-expose-minimal.target"
          minimal_slice="$minimalExposePath/units/aos-pkg-expose-minimal.slice"
          minimal_modules="$minimalExposePath/units/aos-pkg-expose-minimal-modules.service"
          minimal_sysctl="$minimalExposePath/units/aos-pkg-expose-minimal-sysctl.service"
          minimal_firewall="$minimalExposePath/units/aos-pkg-expose-minimal-firewall.service"
          minimal_mac="$minimalExposePath/units/aos-pkg-expose-minimal-mac.service"
          minimal_ebpf="$minimalExposePath/units/aos-pkg-expose-minimal-ebpf.service"
          minimal_manifest="$minimalExposePath/manifest.json"
          minimal_mac_profile="$minimalExposePath/mac-profile.json"
          minimal_selinux_profile="$minimalExposePath/mac/selinux/aos_x2dpkg_x2dexpose_x2dminimal.pp"
          minimal_selinux_module="$minimalExposePath/mac/selinux/aos_x2dpkg_x2dexpose_x2dminimal.mod"
          minimal_selinux_source="$minimalExposePath/mac/selinux/aos_x2dpkg_x2dexpose_x2dminimal.te"
          test -f "$minimal_unit"
          test -f "$minimal_target"
          test -f "$minimal_slice"
          test -f "$minimal_modules"
          test -f "$minimal_sysctl"
          test -f "$minimal_firewall"
          test -f "$minimal_mac"
          test -f "$minimal_ebpf"
          test ! -f "$minimalExposePath/units/aos-pkg-expose-minimal-netns.service"
          test -f "$minimal_manifest"
          test -f "$minimal_mac_profile"
          test -s "$minimal_selinux_profile"
          test -s "$minimal_selinux_module"
          test -f "$minimal_selinux_source"
          grep -q 'Description=RFC-0001 expose minimal service' "$minimal_unit"
          grep -q "RootDirectory=$minimalPayload" "$minimal_unit"
          grep -q 'Slice=aos-pkg-expose-minimal.slice' "$minimal_unit"
          grep -q 'ExecStart=.*/bin/aos-selinux-run --context system_u:system_r:aos_x2dpkg_x2dexpose_x2dminimal_t -- .*/bin/aos-landlock --require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /var/lib/aos-pkg-expose-minimal -- ${pkgs.bash}/bin/bash -c true' \
            "$minimal_unit"
          grep -q 'PrivateNetwork=true' "$minimal_unit"
          grep -q 'PrivateDevices=true' "$minimal_unit"
          grep -q '^CapabilityBoundingSet=$' "$minimal_unit"
          grep -q '^AmbientCapabilities=$' "$minimal_unit"
          grep -q 'DevicePolicy=closed' "$minimal_unit"

          verity_unit="$verityRootExposePath/units/expose-verity-root.service"
          verity_manifest="$verityRootExposePath/manifest.json"
          test -f "$verity_unit"
          test -f "$verity_manifest"
          grep -q 'Description=RFC-0001 expose verity root service' "$verity_unit"
          grep -q "RootImage=$verityImageArtifact/root.img" "$verity_unit"
          grep -q "RootVerity=$verityImageArtifact/root.verity" "$verity_unit"
          grep -q 'RootHash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$verity_unit"
          grep -q "RootHashSignature=$verityImageArtifact/root.roothash.p7s" "$verity_unit"
          grep -q 'RootImagePolicy=root=signed' "$verity_unit"
          grep -q 'ExecStartPre=.*/bin/aos-verity-root-guard --signature-only aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa .*/root.roothash.p7s' "$verity_unit"
          if grep -q 'ExecStartPre=.*-- .*bin/aos-selinux-run' "$verity_unit"; then
            echo "verity RootImage precheck must not run workload sandbox wrappers" >&2
            exit 1
          fi
          grep -q 'ExecStart=.*/bin/aos-selinux-run' "$verity_unit"
          if grep -q 'ExecStart=.*/bin/aos-verity-root-guard' "$verity_unit"; then
            echo "verity RootImage workload ExecStart must not run the root-only guard" >&2
            exit 1
          fi
          grep -q 'PermissionsStartOnly=true' "$verity_unit"
          grep -q 'After=.*systemd-udevd.service' "$verity_unit"
          grep -q 'Requires=.*systemd-udevd.service' "$verity_unit"
          grep -q 'BindReadOnlyPaths=/sys/firmware/efi/efivars:/run/aos-secure-boot-efivars' "$verity_unit"
          grep -q 'PrivateDevices=false' "$verity_unit"
          if grep -q 'RootDirectory=' "$verity_unit"; then
            echo "verity RootImage service must not also render RootDirectory" >&2
            exit 1
          fi
          grep -q 'ExecStart=${pkgs.coreutils}/bin/true' "$minimal_modules"
          grep -q 'ExecStart=${pkgs.coreutils}/bin/true' "$minimal_sysctl"
          grep -q 'ExecStart=${pkgs.coreutils}/bin/true' "$minimal_firewall"
          grep -q 'Type=oneshot' "$minimal_mac"
          grep -Fq "ExecStart=${pkgs.policycoreutils}/sbin/semodule -i $minimalExposePath/mac/selinux/aos_x2dpkg_x2dexpose_x2dminimal.pp" "$minimal_mac"
          grep -q 'Type=notify' "$minimal_ebpf"
          grep -Fq "ExecStart=${pkgs.aos-ebpf-net-policy}/bin/aos-ebpf-net-policy run --policy $minimalExposePath/network-policy.json --cgroup /sys/fs/cgroup/aos.slice/aos-pkg.slice/aos-pkg-expose.slice/aos-pkg-expose-minimal.slice --object ${pkgs.aos-ebpf-net-policy}/lib/bpf/aos-ebpf-net-policy.bpf.o" "$minimal_ebpf"
          grep -q '"modules":\[\]' "$minimal_manifest"
          grep -q '"sysctl":{}' "$minimal_manifest"
          grep -q '"allowedTCP":\[\]' "$minimal_manifest"
          grep -q '"allowedUDP":\[\]' "$minimal_manifest"
          grep -q '"forwardPolicy":"drop"' "$minimal_manifest"
          grep -q '"confinement":{"class":"sandboxed","holes":\[\],"label":"sandboxed"}' "$minimal_manifest"
          grep -q '"security-label":"aos-pkg-expose-minimal"' "$minimal_manifest"
          grep -Fq '"securityLabel":"aos-pkg-expose-minimal"' "$minimal_mac_profile"
          grep -Fq '"profilePath":"mac/selinux/aos_x2dpkg_x2dexpose_x2dminimal.pp"' "$minimal_mac_profile"
          grep -Fq 'module aos_x2dpkg_x2dexpose_x2dminimal 1.0;' "$minimal_selinux_source"
          grep -Fq 'typeattribute aos_x2dpkg_x2dexpose_x2dminimal_t domain;' "$minimal_selinux_source"
          grep -Fq 'allow aos_x2dpkg_x2dexpose_x2dminimal_t file_type:file execmod;' "$minimal_selinux_source"
          grep -Fq 'allow aos_x2dpkg_x2dexpose_x2dminimal_t tmp_t:dir { getattr open read search };' "$minimal_selinux_source"
          grep -Fq 'allow kernel_t aos_x2dpkg_x2dexpose_x2dminimal_t:process dyntransition;' "$minimal_selinux_source"
          if grep -q '"kernel-modules"\|"capabilities"\|"devices"\|"host-paths"\|"cgroup-delegate"\|"privileged-users"\|"network"' \
            "$minimal_manifest"; then
            echo "minimal expose manifest must not request explicit permission grants" >&2
            exit 1
          fi
          if find "$minimalExposePath/units" -name '*.mount' | grep .; then
            echo "minimal expose package must not render package-authored mount units" >&2
            exit 1
          fi

          manual_start_unit="$manualStartExposePath/units/expose-manual-start.service"
          manual_start_target="$manualStartExposePath/units/aos-pkg-expose-manual-start.target"
          test -f "$manual_start_unit"
          test -f "$manual_start_target"
          grep -q 'X-OnlyManualStart=true' "$manual_start_unit"
          grep -q 'PartOf=aos-pkg-expose-manual-start.target' "$manual_start_unit"
          if grep -q 'WantedBy=aos-pkg-expose-manual-start.target' "$manual_start_unit"; then
            echo "manual-start services must not be enabled by the package target preset" >&2
            exit 1
          fi
          if grep -q 'Wants=.*expose-manual-start.service' "$manual_start_target"; then
            echo "manual-start services must not be target members" >&2
            exit 1
          fi
          test ! -e "$manualStartExposePath/units/aos-pkg-expose-manual-start.target.wants/expose-manual-start.service"

          config_unit="$configExposePath/units/expose-config.service"
          config_manifest="$configExposePath/manifest.json"
          grep -q 'BindReadOnlyPaths=/nix/store' "$config_unit"
          grep -q 'BindReadOnlyPaths=/etc/aos/packages/expose-config/config.env' "$config_unit"
          grep -q 'ConditionPathExists=/etc/aos/packages/expose-config/config.env' "$config_unit"
          grep -q 'ConditionPathExists=/usr/lib/credstore.encrypted/join-token' "$config_unit"
          grep -q 'ConditionPathExists=/run/credstore.encrypted/aos/expose-config/generated-token' "$config_unit"
          grep -q 'LoadCredential=plain-note' "$config_unit"
          grep -q 'LoadCredentialEncrypted=join-token:/usr/lib/credstore.encrypted/join-token' "$config_unit"
          grep -q 'LoadCredentialEncrypted=generated-token:/run/credstore.encrypted/aos/expose-config/generated-token' "$config_unit"
          grep -q 'SetCredentialEncrypted=inline-secret:abcDEF0123+/=' "$config_unit"
          grep -q 'X-ReloadIfChanged=true' "$config_unit"
          grep -q 'X-Reload-Triggers=/etc/aos/packages/expose-config/config.env' "$config_unit"
          test -s "$configExposePath/credstore.encrypted/aos/expose-config/generated-token"
          grep -q '"config":{"artifacts":\[{"format":"env","name":"env","optional":\["URL"\],"path":"/etc/aos/packages/expose-config/config.env","reload":"reload","required":\["TOKEN"\],"units":\["expose-config.service"\]}\],"credentials":\[{"encrypted":true,"name":"join-token","source":"/usr/lib/credstore.encrypted/join-token","units":\["expose-config.service"\]},{"encrypted":true,"name":"generated-token","source":"/run/credstore.encrypted/aos/expose-config/generated-token","units":\["expose-config.service"\]},{"ciphertext":"abcDEF0123+/=","encrypted":true,"name":"inline-secret","units":\["expose-config.service"\]},{"encrypted":false,"name":"plain-note","units":\[\]}\]}' "$config_manifest"
          if grep -q 'encryptedFile' "$config_manifest"; then
            echo "vendored credential build input leaked into manifest" >&2
            exit 1
          fi
          if grep -q '${testEncryptedCredential}' "$config_manifest"; then
            echo "vendored credential store path leaked into manifest" >&2
            exit 1
          fi
          grep -q '"provides":\[{"kind":"directory","name":"data","path":"/var/lib/expose-config/data"}\]' "$config_manifest"
          grep -q '"uses":\[{"kind":"directory","name":"data","provider":"expose-config","unit":"expose-config.service"}\]' "$config_manifest"
          test "$unknownConfigUnitRejected" = ok
          test "$credentialGeneratedNamespaceSourceRejected" = ok
          test "$credentialVendoredPlainRejected" = ok
          test "$credentialVendoredCustomSourceRejected" = ok
          test "$credentialVendoredCiphertextRejected" = ok
          test "$credentialVendoredNonStoreFileRejected" = ok
          test "$credentialVendoredStoreParentTraversalRejected" = ok

          split_main="$splitConfigExposePath/units/expose-config-split-main.service"
          split_sidecar="$splitConfigExposePath/units/expose-config-split-sidecar.service"
          split_socket_service="$splitConfigExposePath/units/expose-config-split-socket.service"
          split_socket="$splitConfigExposePath/units/expose-config-split-socket.socket"
          grep -q 'BindReadOnlyPaths=/etc/aos/packages/expose-config-split/main.env' "$split_main"
          grep -q 'ConditionPathExists=/etc/aos/packages/expose-config-split/main.env' "$split_main"
          grep -q 'ConditionPathExists=/usr/lib/credstore.encrypted/main-secret' "$split_main"
          grep -q 'LoadCredentialEncrypted=main-secret:/usr/lib/credstore.encrypted/main-secret' "$split_main"
          if grep -q 'expose-config-split/sidecar.env' "$split_main"; then
            echo "main service must not receive sidecar config artifact" >&2
            exit 1
          fi
          if grep -q 'sidecar-note' "$split_main"; then
            echo "main service must not receive sidecar credential" >&2
            exit 1
          fi
          grep -q 'BindReadOnlyPaths=/etc/aos/packages/expose-config-split/sidecar.env' "$split_sidecar"
          grep -q 'ConditionPathExists=/etc/aos/packages/expose-config-split/sidecar.env' "$split_sidecar"
          grep -q 'LoadCredential=sidecar-note' "$split_sidecar"
          if grep -q 'expose-config-split/main.env' "$split_sidecar"; then
            echo "sidecar service must not receive main config artifact" >&2
            exit 1
          fi
          if grep -q 'main-secret' "$split_sidecar"; then
            echo "sidecar service must not receive main credential" >&2
            exit 1
          fi
          grep -q 'ConditionPathExists=/usr/lib/credstore.encrypted/socket-secret' "$split_socket_service"
          grep -q 'LoadCredentialEncrypted=socket-secret:/usr/lib/credstore.encrypted/socket-secret' "$split_socket_service"
          grep -q 'ConditionPathExists=/usr/lib/credstore.encrypted/socket-secret' "$split_socket"

          test "$payload" = "$overriddenPayload"
          test "$exposePath" != "$overriddenExposePath"
          test -f "$overriddenExposePath/units/expose-smoke-override.service"
          grep -q 'Description=RFC-0001 expose override service' \
            "$overriddenExposePath/units/expose-smoke-override.service"
          test "$reservedCollisionRejected" = ok
          test "$targetMismatchRejected" = ok
          test "$privilegedExecPrefixRejected" = ok
          test "$landlockScriptDerivedExecRejected" = ok
          test "$landlockShellExecPrefixRejected" = ok
          test "$landlockCombinedExecPrefixRejected" = ok
          test "$landlockSlashlessExecRejected" = ok
          test "$landlockExecResetAccepted" = ok
          reset_unit="$landlockExecResetExposePath/units/expose-smoke-landlock-reset.service"
          grep -qx 'ExecStart=' "$reset_unit"
          grep -qx 'ExecStartPre=' "$reset_unit"
          grep -q 'ExecStart=.*/bin/aos-selinux-run --context system_u:system_r:aos_x2dpkg_x2dexpose_x2dsmoke_t -- .*/bin/aos-landlock --require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /var/lib/aos-pkg-expose-smoke -- ${pkgs.bash}/bin/bash -c true' "$reset_unit"
          grep -q 'ExecStartPre=.*/bin/aos-selinux-run --context system_u:system_r:aos_x2dpkg_x2dexpose_x2dsmoke_t -- .*/bin/aos-landlock --require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /var/lib/aos-pkg-expose-smoke -- ${pkgs.bash}/bin/bash -c true' "$reset_unit"
          test "$socketMissingTcpBindRejected" = ok
          test "$socketListenStreamsMissingTcpBindRejected" = ok
          test "$socketListenStreamResetAccepted" = ok
          test "$kernelModulePermissionMismatchRejected" = ok
          test "$undeclaredPreparedHostPathDirectoryRejected" = ok
          test "$readOnlyPreparedHostPathDirectoryRejected" = ok
          test "$unsupportedHostPathCharactersRejected" = ok
          test "$readOnlyTempHostPathRejected" = ok
          test "$rootUserWithoutPrivilegeRejected" = ok
          test "$numericRootUserWithoutPrivilegeRejected" = ok
          test "$dynamicUserFalseWithoutIdentityRejected" = ok
          test "$dynamicUserStringFalseRejected" = ok
          static_user_unit="$staticUserExposePath/units/expose-smoke-static-user.service"
          grep -q 'User=aos-static' "$static_user_unit"
          grep -q 'Group=aos-static' "$static_user_unit"
          grep -q 'StateDirectory=expose-smoke-static' "$static_user_unit"
          grep -q 'DynamicUser=false' "$static_user_unit"
          grep -q 'PrivateUsers=false' "$static_user_unit"
          if grep -q 'DynamicUser=true' "$static_user_unit"; then
            echo "static User= services must not receive generated DynamicUser=true" >&2
            exit 1
          fi
          grep -q '"confinement":{"class":"sandboxed-with-holes","holes":\["static-user:aos-static"\],"label":"sandboxed-with-holes (static-user:aos-static)"}' \
            "$staticUserExposePath/manifest.json"
          permission_only_modules="$permissionOnlyModulesExposePath/units/aos-pkg-expose-smoke-modules.service"
          permission_only_manifest="$permissionOnlyModulesExposePath/manifest.json"
          grep -q 'ExecStart=${pkgs.kmod}/sbin/modprobe -a br_netfilter' \
            "$permission_only_modules"
          grep -q '"modules":\["br_netfilter"\]' "$permission_only_manifest"
          grep -q '"kernel-modules":\["br_netfilter"\]' "$permission_only_manifest"
          grep -q '"confinement":{"class":"sandboxed-with-holes","holes":\["capability:CAP_NET_BIND_SERVICE"\],"label":"sandboxed-with-holes (capability:CAP_NET_BIND_SERVICE)"}' \
            "$withHolesExposePath/manifest.json"
          grep -q '"security-label":"aos-pkg-expose-smoke"' \
            "$withHolesExposePath/manifest.json"
          grep -q 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' \
            "$withHolesExposePath/units/expose-smoke-holes.service"
          grep -q 'AmbientCapabilities=CAP_NET_BIND_SERVICE' \
            "$withHolesExposePath/units/expose-smoke-holes.service"
          unconfined_policy="$unconfinedExposePath/network-policy.json"
          grep -q '"confinement":{"class":"unconfined","holes":\["network:host","capability:CAP_NET_ADMIN","host-path:read-only:/srv/expose-smoke-unconfined","privileged-users"\],"label":"unconfined"}' \
            "$unconfinedExposePath/manifest.json"
          grep -q '"fs":{"readOnly":\["/srv/expose-smoke-unconfined"\],"readWrite":\[\]}' \
            "$unconfined_policy"
          grep -q '"landlock":{"abi":4,"fs":{"readOnly":\[\],"readWrite":\[\]}' \
            "$unconfined_policy"
          test -f "$unconfinedExposePath/mac-profile.json"
          grep -Fq '"defaultDeny":false' "$unconfinedExposePath/mac-profile.json"
          grep -Fq '"profilePath":null' "$unconfinedExposePath/mac-profile.json"
          if test -d "$unconfinedExposePath/mac/selinux"; then
            echo "unconfined package must not render a default-deny SELinux profile" >&2
            exit 1
          fi
          test -f "$unconfinedExposePath/units/aos-pkg-expose-smoke.slice"
          test ! -f "$unconfinedExposePath/units/aos-pkg-expose-smoke-mac.service"
          test ! -f "$unconfinedExposePath/units/aos-pkg-expose-smoke-ebpf.service"
          grep -q 'Slice=aos-pkg-expose-smoke.slice' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          if grep -q 'aos-landlock' "$unconfinedExposePath/units/expose-smoke-unconfined.service"; then
            echo "unconfined host path package must not run through aos-landlock" >&2
            exit 1
          fi
          if grep -q 'aos-selinux-run' "$unconfinedExposePath/units/expose-smoke-unconfined.service"; then
            echo "unconfined host path package must not run through aos-selinux-run" >&2
            exit 1
          fi
          for directive in RootDirectory MountAPIVFS ProtectSystem NoNewPrivileges BindPaths BindReadOnlyPaths CapabilityBoundingSet AmbientCapabilities DeviceAllow DevicePolicy PrivateDevices RestrictAddressFamilies SystemCallFilter SystemCallErrorNumber; do
            if grep -q "^$directive=" "$unconfinedExposePath/units/expose-smoke-unconfined.service"; then
              echo "unconfined package must not render host-unit sandbox directive $directive" >&2
              exit 1
            fi
          done
          grep -q 'PrivateUsers=false' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          grep -q 'DynamicUser=false' \
            "$unconfinedExposePath/units/expose-smoke-unconfined.service"
          grep -q '"confinement":{"class":"sandboxed-with-holes","holes":\["syscalls:privileged"\],"label":"sandboxed-with-holes (syscalls:privileged)"}' \
            "$privilegedSyscallsExposePath/manifest.json"
          if grep -q 'SystemCallFilter=' \
            "$privilegedSyscallsExposePath/units/expose-smoke-privileged-syscalls.service"; then
            echo "privileged syscall profile must not render a restrictive SystemCallFilter" >&2
            exit 1
          fi
          grep -q 'SystemCallArchitectures=native' \
            "$privilegedSyscallsExposePath/units/expose-smoke-privileged-syscalls.service"
          private_outbound_unit="$privateOutboundExposePath/units/expose-smoke-private-outbound.service"
          private_outbound_netns="$privateOutboundExposePath/units/aos-pkg-expose-smoke-netns.service"
          private_outbound_mac="$privateOutboundExposePath/units/aos-pkg-expose-smoke-mac.service"
          private_outbound_ebpf="$privateOutboundExposePath/units/aos-pkg-expose-smoke-ebpf.service"
          private_outbound_target="$privateOutboundExposePath/units/aos-pkg-expose-smoke.target"
          private_outbound_manifest="$privateOutboundExposePath/manifest.json"
          private_outbound_policy="$privateOutboundExposePath/network-policy.json"
          test -f "$private_outbound_unit"
          test -f "$private_outbound_netns"
          test -f "$private_outbound_mac"
          test -f "$private_outbound_ebpf"
          test -f "$private_outbound_policy"
          grep -q 'After=aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service aos-pkg-expose-smoke-netns.service aos-pkg-expose-smoke-mac.service aos-pkg-expose-smoke-ebpf.service' \
            "$private_outbound_unit"
          grep -q 'Requires=aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service aos-pkg-expose-smoke-netns.service aos-pkg-expose-smoke-mac.service aos-pkg-expose-smoke-ebpf.service' \
            "$private_outbound_unit"
          grep -q 'Slice=aos-pkg-expose-smoke.slice' "$private_outbound_unit"
          grep -q 'PrivateNetwork=false' "$private_outbound_unit"
          grep -q 'NetworkNamespacePath=/run/netns/aos-pkg-expose-smoke' "$private_outbound_unit"
          grep -q 'ExecStart=.*/bin/aos-selinux-run --context system_u:system_r:aos_x2dpkg_x2dexpose_x2dsmoke_t -- .*/bin/aos-landlock --require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /var/lib/aos-pkg-expose-smoke --tcp-bind 8000 --tcp-connect 443 -- ${pkgs.bash}/bin/bash -c true' \
            "$private_outbound_unit"
          grep -q 'ExecReload=.*/bin/aos-selinux-run --context system_u:system_r:aos_x2dpkg_x2dexpose_x2dsmoke_t -- .*/bin/aos-landlock --require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /var/lib/aos-pkg-expose-smoke --tcp-bind 8000 --tcp-connect 443 -- ${pkgs.bash}/bin/bash -c true' \
            "$private_outbound_unit"
          grep -q 'aos-landlock' "$private_outbound_unit"
          grep -q 'Wants=aos-pkg-expose-smoke.slice expose-smoke-private-outbound.service aos-pkg-expose-smoke-modules.service aos-pkg-expose-smoke-sysctl.service aos-pkg-expose-smoke-firewall.service aos-pkg-expose-smoke-netns.service aos-pkg-expose-smoke-mac.service aos-pkg-expose-smoke-ebpf.service' \
            "$private_outbound_target"
          grep -q 'Description=Create outbound network namespace for expose-smoke' \
            "$private_outbound_netns"
          if grep -q 'RootDirectory=' "$private_outbound_netns"; then
            echo "host-side netns service must not be RootDirectory-sandboxed" >&2
            exit 1
          fi
          if grep -q 'aos-landlock' "$private_outbound_netns"; then
            echo "host-side netns service must not run through aos-landlock" >&2
            exit 1
          fi
          grep -q 'PartOf=aos-pkg-expose-smoke.target' "$private_outbound_netns"
          grep -q 'WantedBy=aos-pkg-expose-smoke.target' "$private_outbound_netns"
          grep -q 'Before=expose-smoke-private-outbound.service' "$private_outbound_netns"
          grep -q 'After=nftables.service' "$private_outbound_netns"
          grep -q 'Requires=nftables.service' "$private_outbound_netns"
          grep -q 'ReloadPropagatedFrom=nftables.service' "$private_outbound_netns"
          grep -q 'aos-pkg-expose-smoke-netns-start' "$private_outbound_netns"
          grep -q 'aos-pkg-expose-smoke-netns-reload' "$private_outbound_netns"
          grep -q 'aos-pkg-expose-smoke-netns-stop' "$private_outbound_netns"
          grep -q 'ExecStopPost=.*aos-pkg-expose-smoke-netns-stop' "$private_outbound_netns"
          grep -q 'Description=Attach eBPF network policy for expose-smoke' \
            "$private_outbound_ebpf"
          grep -q 'Type=notify' "$private_outbound_ebpf"
          grep -q 'Slice=aos-pkg-expose-smoke.slice' "$private_outbound_ebpf"
          grep -Fq "ExecStart=${pkgs.aos-ebpf-net-policy}/bin/aos-ebpf-net-policy run --policy $privateOutboundExposePath/network-policy.json --cgroup /sys/fs/cgroup/aos.slice/aos-pkg.slice/aos-pkg-expose.slice/aos-pkg-expose-smoke.slice --object ${pkgs.aos-ebpf-net-policy}/lib/bpf/aos-ebpf-net-policy.bpf.o" \
            "$private_outbound_ebpf"
          private_outbound_start=$(
            sed -n 's|^ExecStart=||p' "$private_outbound_netns"
          )
          private_outbound_reload=$(
            sed -n 's|^ExecReload=||p' "$private_outbound_netns"
          )
          private_outbound_stop=$(
            sed -n 's|^ExecStop=||p' "$private_outbound_netns"
          )
          test -x "$private_outbound_start"
          test -x "$private_outbound_reload"
          test -x "$private_outbound_stop"
          grep -q 'index($0, needle)' "$private_outbound_start"
          grep -q 'gawk -v netns="$netns"' "$private_outbound_start"
          grep -q 'refusing to steal a private-outbound namespace' "$private_outbound_start"
          grep -q 'refusing private-outbound veth collision' "$private_outbound_start"
          grep -q 'route show exact "$cidr"' "$private_outbound_start"
          grep -q 'refusing private-outbound subnet collision' "$private_outbound_start"
          grep -q '/proc/sys/net/ipv4/ip_forward' "$private_outbound_start"
          grep -q 'ip_forward.prev' "$private_outbound_start"
          grep -q 'flock 9' "$private_outbound_start"
          grep -q 'trap.*cleanup_package_state' "$private_outbound_start"
          grep -q 'restore_ip_forward_if_last' "$private_outbound_stop"
          if grep -q 'link delete "$host_if"' "$private_outbound_reload"; then
            echo "netns reload must not recreate the veth pair" >&2
            exit 1
          fi
          if grep -q 'netns add "$netns"' "$private_outbound_reload"; then
            echo "netns reload must not recreate the namespace" >&2
            exit 1
          fi
          grep -q '"aos-pkg-expose-smoke-netns.service"' "$private_outbound_manifest"
          grep -q '"aos-pkg-expose-smoke.slice"' "$private_outbound_manifest"
          grep -q '"aos-pkg-expose-smoke-mac.service"' "$private_outbound_manifest"
          grep -q '"aos-pkg-expose-smoke-ebpf.service"' "$private_outbound_manifest"
          grep -q '"network":"private-outbound"' "$private_outbound_manifest"
          grep -q '"tcp-bind":\[8000\]' "$private_outbound_manifest"
          grep -q '"tcp-connect":\[443\]' "$private_outbound_manifest"
          grep -q '"confinement":{"class":"sandboxed-with-holes","holes":\["network:private-outbound","tcp-bind:8000","tcp-connect:443"\],"label":"sandboxed-with-holes (network:private-outbound, tcp-bind:8000, tcp-connect:443)"}' \
            "$private_outbound_manifest"
          grep -q '"version":1' "$private_outbound_policy"
          grep -q '"mode":"private-outbound"' "$private_outbound_policy"
          grep -q '"securityLabel":"aos-pkg-expose-smoke"' "$private_outbound_policy"
          grep -q '"bind":\[8000\]' "$private_outbound_policy"
          grep -q '"connect":\[443\]' "$private_outbound_policy"
          grep -q '"hooks":\["socket_bind","socket_connect"\]' "$private_outbound_policy"
          regex_name_start=$(
            sed -n 's|^ExecStart=||p' \
              "$regexNamePrivateOutboundExposePath/units/aos-pkg-expose.smoke.regex-netns.service"
          )
          test -x "$regex_name_start"
          grep -q 'index($0, needle)' "$regex_name_start"
          grep -q 'gawk -v netns="$netns"' "$regex_name_start"
          if grep -q 'grep -qx "$netns"' "$regex_name_start"; then
            echo "netns detection must not use regex grep for package names" >&2
            exit 1
          fi

          host_path_without_prepare_unit="$hostPathWithoutPrepareExposePath/units/expose-smoke-rw-host-path.service"
          host_path_without_prepare_target="$hostPathWithoutPrepareExposePath/units/aos-pkg-expose-smoke.target"
          host_path_without_prepare_policy="$hostPathWithoutPrepareExposePath/network-policy.json"
          test -f "$host_path_without_prepare_unit"
          test -f "$host_path_without_prepare_policy"
          grep -q 'BindPaths=/srv/expose-smoke-rw' "$host_path_without_prepare_unit"
          grep -q 'ExecStart=.*/bin/aos-selinux-run --context system_u:system_r:aos_x2dpkg_x2dexpose_x2dsmoke_t -- .*/bin/aos-landlock --require-abi 4 --fs-ro / --fs-rw /tmp --fs-rw /var/tmp --fs-rw /var/lib/aos-pkg-expose-smoke --fs-rw /srv/expose-smoke-rw -- ${pkgs.bash}/bin/bash -c true' \
            "$host_path_without_prepare_unit"
          grep -q '"fs":{"readOnly":\[\],"readWrite":\["/srv/expose-smoke-rw"\]}' \
            "$host_path_without_prepare_policy"
          grep -q '"readWrite":\["/tmp","/var/tmp","/var/lib/aos-pkg-expose-smoke","/srv/expose-smoke-rw"\]' \
            "$host_path_without_prepare_policy"
          test ! -f "$hostPathWithoutPrepareExposePath/units/aos-pkg-expose-smoke-host-paths.service"
          if grep -q 'aos-pkg-expose-smoke-host-paths.service' "$host_path_without_prepare_target"; then
            echo "rw host paths must not implicitly synthesize host directory preparation" >&2
            exit 1
          fi

          k3s_worker_unit="$k3sWorkerExposePath/units/k3s.service"
          k3s_worker_target="$k3sWorkerExposePath/units/aos-pkg-k3s-worker.target"
          k3s_worker_host_paths="$k3sWorkerExposePath/units/aos-pkg-k3s-worker-host-paths.service"
          k3s_worker_modules="$k3sWorkerExposePath/units/aos-pkg-k3s-worker-modules.service"
          k3s_worker_manifest="$k3sWorkerExposePath/manifest.json"
          k3s_control_plane_unit="$k3sControlPlaneExposePath/units/k3s.service"
          k3s_control_plane_target="$k3sControlPlaneExposePath/units/aos-pkg-k3s-control-plane.target"
          k3s_control_plane_host_paths="$k3sControlPlaneExposePath/units/aos-pkg-k3s-control-plane-host-paths.service"
          k3s_control_plane_manifest="$k3sControlPlaneExposePath/manifest.json"
          k3s_combined_unit="$k3sCombinedExposePath/units/k3s.service"
          k3s_combined_target="$k3sCombinedExposePath/units/aos-pkg-k3s-combined.target"
          k3s_combined_host_paths="$k3sCombinedExposePath/units/aos-pkg-k3s-combined-host-paths.service"
          k3s_combined_manifest="$k3sCombinedExposePath/manifest.json"
          require_host_unit() {
            service_name="$1"
            unit_path="$2"
            for directive in RootDirectory MountAPIVFS ProtectSystem NoNewPrivileges BindPaths BindReadOnlyPaths ProtectKernelModules ProtectKernelTunables ProtectKernelLogs ProtectClock ProtectHostname MemoryDenyWriteExecute LockPersonality CapabilityBoundingSet AmbientCapabilities DeviceAllow DevicePolicy PrivateDevices RestrictAddressFamilies ProtectControlGroups SystemCallFilter SystemCallErrorNumber; do
              if grep -q "^$directive=" "$unit_path"; then
                echo "$service_name must be an unconfined host unit; found $directive" >&2
                exit 1
              fi
            done
          }
          test -f "$k3s_worker_unit"
          test -f "$k3sWorkerExposePath/units/k3s-preflight.service"
          test -f "$k3s_worker_target"
          test -f "$k3s_worker_host_paths"
          test -f "$k3s_worker_modules"
          test -f "$k3s_control_plane_unit"
          test -f "$k3s_control_plane_target"
          test -f "$k3s_control_plane_host_paths"
          test -f "$k3s_combined_unit"
          test -f "$k3s_combined_target"
          test -f "$k3s_combined_host_paths"
          test ! -f "$k3sWorkerExposePath/units/aos-pkg-k3s-worker-netns.service"

          grep -q 'Description=Lightweight Kubernetes (agent / worker)' "$k3s_worker_unit"
          if grep -q 'X-OnlyManualStart=true' "$k3s_worker_unit"; then
            echo "k3s worker service must start with the package target" >&2
            exit 1
          fi
          grep -q 'WantedBy=aos-pkg-k3s-worker.target' "$k3s_worker_unit"
          grep -q 'ExecStart=${pkgs.k3s}/bin/k3s agent' "$k3s_worker_unit"
          grep -q 'KillMode=process' "$k3s_worker_unit"
          grep -q 'Requisite=k3s-preflight.service' "$k3s_worker_unit"
          grep -q 'After=.*k3s-preflight.service' "$k3s_worker_unit"
          grep -q 'Wants=network-online.target' "$k3s_worker_unit"
          grep -q 'Environment="PATH=.*${pkgs.k3s}/bin' "$k3s_worker_unit"
          grep -q 'EnvironmentFile=/etc/rancher/k3s/k3s.env' "$k3s_worker_unit"
          grep -q 'LimitNOFILE=1048576' "$k3s_worker_unit"
          grep -q 'LimitNPROC=infinity' "$k3s_worker_unit"
          grep -q 'LimitCORE=infinity' "$k3s_worker_unit"
          grep -q 'TasksMax=infinity' "$k3s_worker_unit"
          grep -q 'TimeoutStartSec=infinity' "$k3s_worker_unit"
          grep -q 'Restart=always' "$k3s_worker_unit"
          grep -q 'RestartSec=5s' "$k3s_worker_unit"
          grep -q 'ConditionPathExists=/etc/rancher/k3s/k3s.env' "$k3sWorkerExposePath/units/k3s-preflight.service"
          grep -q 'EnvironmentFile=/etc/rancher/k3s/k3s.env' "$k3sWorkerExposePath/units/k3s-preflight.service"
          # Script-derived Exec directives point at the
          # gen-local `aos-job-scripts/<unit>:<slot>.<index>` materialization
          # (derivation `aos-job-script-<scriptName>`) instead of the legacy
          # `unit-script-<name>/bin/<name>` path. See lib/modules/systemd/lib.nix.
          grep -q 'ExecStart=.*aos-job-script-k3s-preflight-start/aos-job-scripts/' "$k3sWorkerExposePath/units/k3s-preflight.service"
          if grep -q 'NetworkNamespacePath=' "$k3s_worker_unit"; then
            echo "k3s worker must stay on host networking" >&2
            exit 1
          fi
          grep -q 'Delegate=true' "$k3s_worker_unit"
          grep -q 'PrivateUsers=false' "$k3s_worker_unit"
          grep -q 'DynamicUser=false' "$k3s_worker_unit"
          if grep -q 'ProtectProc=' "$k3s_worker_unit"; then
            echo "root-equivalent k3s worker must not get ProtectProc= hardening" >&2
            exit 1
          fi
          if grep -q 'ProcSubset=' "$k3s_worker_unit"; then
            echo "root-equivalent k3s worker must not get ProcSubset= hardening" >&2
            exit 1
          fi
          require_host_unit "k3s worker" "$k3s_worker_unit"
          require_host_unit "k3s worker preflight" "$k3sWorkerExposePath/units/k3s-preflight.service"
          grep -q 'StateDirectory=rancher/k3s kubelet' "$k3s_worker_unit"
          grep -q 'PartOf=aos-pkg-k3s-worker.target' "$k3sWorkerExposePath/units/k3s-preflight.service"
          if grep -q 'SystemCallFilter=' "$k3s_worker_unit"; then
            echo "k3s worker privileged syscall profile must not render a restrictive SystemCallFilter" >&2
            exit 1
          fi
          grep -q 'Wants=aos-pkg-k3s-worker.slice k3s-preflight.service k3s.service aos-pkg-k3s-worker-host-paths.service aos-pkg-k3s-worker-modules.service aos-pkg-k3s-worker-sysctl.service aos-pkg-k3s-worker-firewall.service' \
            "$k3s_worker_target"
          test -L "$k3sWorkerExposePath/units/aos-pkg-k3s-worker.target.wants/k3s.service"
          grep -q 'Description=Prepare host path directories for k3s-worker' \
            "$k3s_worker_host_paths"
          grep -q "ExecStart=${pkgs.coreutils}/bin/mkdir -p '/var/lib/rancher' '/var/lib/kubelet' '/etc/rancher/k3s' '/etc/rancher/node'" \
            "$k3s_worker_host_paths"
          grep -q 'ExecStart=${pkgs.kmod}/sbin/modprobe -a br_netfilter vxlan ip_set' \
            "$k3s_worker_modules"
          grep -q '"confinement":{"class":"unconfined"' "$k3s_worker_manifest"
          grep -q '"label":"unconfined"' "$k3s_worker_manifest"
          grep -q '"network":"host"' "$k3s_worker_manifest"
          grep -q '"privileged-users":true' "$k3s_worker_manifest"
          grep -q '"cgroup-delegate":true' "$k3s_worker_manifest"
          grep -q '"kernel-modules":\["br_netfilter","vxlan","ip_set"\]' "$k3s_worker_manifest"
          grep -q '"security-label":"aos-pkg-k3s-worker"' "$k3s_worker_manifest"
          grep -q '"allowedTCP":\[10250\]' "$k3s_worker_manifest"
          grep -q '"allowedUDP":\[8472\]' "$k3s_worker_manifest"
          grep -q '"forwardPolicy":"accept"' "$k3s_worker_manifest"

          grep -q 'Description=Lightweight Kubernetes (control plane, no agent)' \
            "$k3s_control_plane_unit"
          grep -q 'WantedBy=aos-pkg-k3s-control-plane.target' "$k3s_control_plane_unit"
          grep -q 'ExecStart=${pkgs.k3s}/bin/k3s server --disable-agent' \
            "$k3s_control_plane_unit"
          require_host_unit "k3s control-plane" "$k3s_control_plane_unit"
          grep -q 'Environment="PATH=.*${pkgs.k3s}/bin' "$k3s_control_plane_unit"
          grep -q 'EnvironmentFile=/etc/rancher/k3s/k3s.env' "$k3s_control_plane_unit"
          grep -q 'LimitNOFILE=1048576' "$k3s_control_plane_unit"
          grep -q 'LimitNPROC=infinity' "$k3s_control_plane_unit"
          grep -q 'LimitCORE=infinity' "$k3s_control_plane_unit"
          grep -q 'TasksMax=infinity' "$k3s_control_plane_unit"
          grep -q 'TimeoutStartSec=infinity' "$k3s_control_plane_unit"
          grep -q 'Restart=always' "$k3s_control_plane_unit"
          grep -q 'RestartSec=5s' "$k3s_control_plane_unit"
          grep -q 'StateDirectory=rancher/k3s' "$k3s_control_plane_unit"
          grep -q 'Wants=aos-pkg-k3s-control-plane.slice k3s-preflight.service k3s.service aos-pkg-k3s-control-plane-host-paths.service aos-pkg-k3s-control-plane-modules.service aos-pkg-k3s-control-plane-sysctl.service aos-pkg-k3s-control-plane-firewall.service' \
            "$k3s_control_plane_target"
          grep -q 'Description=Prepare host path directories for k3s-control-plane' \
            "$k3s_control_plane_host_paths"
          grep -q "ExecStart=${pkgs.coreutils}/bin/mkdir -p '/var/lib/rancher' '/etc/rancher/k3s' '/etc/rancher/node'" \
            "$k3s_control_plane_host_paths"
          grep -q '"allowedTCP":\[6443\]' "$k3s_control_plane_manifest"
          grep -q '"allowedUDP":\[\]' "$k3s_control_plane_manifest"
          grep -q '"forwardPolicy":"drop"' "$k3s_control_plane_manifest"

          grep -q 'Description=Lightweight Kubernetes (combined: server + agent)' \
            "$k3s_combined_unit"
          grep -q 'WantedBy=aos-pkg-k3s-combined.target' "$k3s_combined_unit"
          grep -Fxq 'ExecStart=${pkgs.k3s}/bin/k3s server' "$k3s_combined_unit"
          require_host_unit "k3s combined" "$k3s_combined_unit"
          grep -q 'Environment="PATH=.*${pkgs.k3s}/bin' "$k3s_combined_unit"
          grep -q 'EnvironmentFile=/etc/rancher/k3s/k3s.env' "$k3s_combined_unit"
          grep -q 'LimitNOFILE=1048576' "$k3s_combined_unit"
          grep -q 'LimitNPROC=infinity' "$k3s_combined_unit"
          grep -q 'LimitCORE=infinity' "$k3s_combined_unit"
          grep -q 'TasksMax=infinity' "$k3s_combined_unit"
          grep -q 'TimeoutStartSec=infinity' "$k3s_combined_unit"
          grep -q 'Restart=always' "$k3s_combined_unit"
          grep -q 'RestartSec=5s' "$k3s_combined_unit"
          grep -q 'StateDirectory=rancher/k3s kubelet' "$k3s_combined_unit"
          grep -q 'Wants=aos-pkg-k3s-combined.slice k3s-preflight.service k3s.service aos-pkg-k3s-combined-host-paths.service aos-pkg-k3s-combined-modules.service aos-pkg-k3s-combined-sysctl.service aos-pkg-k3s-combined-firewall.service' \
            "$k3s_combined_target"
          grep -q 'Description=Prepare host path directories for k3s-combined' \
            "$k3s_combined_host_paths"
          grep -q "ExecStart=${pkgs.coreutils}/bin/mkdir -p '/var/lib/rancher' '/var/lib/kubelet' '/etc/rancher/k3s' '/etc/rancher/node'" \
            "$k3s_combined_host_paths"
          grep -q '"allowedTCP":\[6443,10250\]' "$k3s_combined_manifest"
          grep -q '"allowedUDP":\[8472\]' "$k3s_combined_manifest"
          grep -q '"forwardPolicy":"accept"' "$k3s_combined_manifest"

          if grep -R "$exposePath" "$payload"; then
            echo "payload output must not contain a reference to its expose path" >&2
            exit 1
          fi

          mkdir -p "$out"
          echo "PASS" > "$out/result"
        '';
      }
    ];

    meta.description = "RFC-0001 package expose renderer regression check";
  }
