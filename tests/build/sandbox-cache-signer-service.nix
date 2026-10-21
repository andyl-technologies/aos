# Resolved custody contract for the separate, nonauthorizing Cache signer.
{
  pkgs,
  lib,
  mkSystem,
}: let
  baseImage = mkSystem [../../systems/server-test.nix];
  selectedManager = baseImage.config.aos.manager.selected;
  onlineDomain = "01010101010101010101010101010101";
  onlineImage = baseImage.extendModules {
    modules = [
      {
        aos.sandbox.nixBroker = {
          enable = true;
          domainIdHex = onlineDomain;
        };
      }
    ];
  };
  sharedPackages = image:
    map (role: image.config.aos.sandbox.${role}.package)
    ["controllerService" "policyAuthority" "sourceSignerService" "cacheSignerService"];
  onlinePackage = pkgs.aosNixOnlineControllerWith {domainIdHex = onlineDomain;};
  otherOnlinePackage = pkgs.aosNixOnlineControllerWith {
    domainIdHex = "02020202020202020202020202020202";
  };
  managerOptions = import ../../modules/base/_manager-selection.nix {inherit lib;};

  systemdOptions = {lib, ...}: {
    options.assertions = lib.mkOption {
      type = lib.types.listOf lib.types.anything;
      default = [];
    };
    # Reuse both the actual provider's projection and the production schema.
    # This fixture checks directives; the record does not enroll a process.
    options.aos.manager.selected =
      managerOptions.options.aos.manager.selected
      // {
        default = selectedManager;
      };
    options.systemd.services = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        freeformType = lib.types.attrsOf lib.types.anything;
        options.serviceConfig = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = {};
        };
      });
      default = {};
    };
    options.systemd.sockets = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
    };
    options.aos.users.users = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
    };
    options.aos.users.groups = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
    };
    options.aos.security.selinux.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
    };
    options.aos.security.selinux.bootMode = lib.mkOption {
      type = lib.types.enum ["legacy" "immutable-stage0"];
      default = "legacy";
    };
  };
  evaluation = lib.evalModules {
    specialArgs = {inherit pkgs;};
    modules = [
      systemdOptions
      ({
        config,
        lib,
        ...
      }: let
        parentModule = import ../../modules/sandbox/component-parent-enclosure.nix {inherit config lib pkgs;};
      in {
        # The fixture imports the real nullable Parent schema and evaluates
        # service directives. These DATA do not enroll a running process.
        options.aos.sandbox.resourceBank.parentEnclosure = parentModule.options.aos.sandbox.resourceBank.parentEnclosure;
        options.aos.sandbox.policyAuthority._normalStartupProfile = lib.mkOption {
          type = lib.types.nullOr lib.types.package;
          internal = true;
          readOnly = true;
          default = null;
        };
        options.aos.sandbox.controller.uid = lib.mkOption {type = lib.types.int;};
        options.aos.sandbox.controller.gid = lib.mkOption {type = lib.types.int;};
        options.aos.sandbox.controllerService.enable = lib.mkOption {type = lib.types.bool;};
        options.aos.sandbox.controllerService.credentials.cacheOwnerReadbackSigningKey = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
        };
        options.aos.sandbox.controllerService.credentials.cacheOwnerReadbackPublicKey = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
        };
        options.aos.sandbox.policyAuthority.enable = lib.mkOption {type = lib.types.bool;};
        options.aos.sandbox.policyAuthority.credentials.cacheOwnerReadbackPublicKey = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = null;
        };

        config.aos.security.selinux = {
          enable = true;
          bootMode = "immutable-stage0";
        };
        config.aos.sandbox = {
          controller = {
            uid = 811;
            gid = 811;
          };
          controllerService.enable = true;
          resourceBank.parentEnclosure = {
            manager = {};
            fixedServices = {};
            managerOpenFilesPerProcess = 1;
            fixedOpenFilesPerProcess = 1;
            cacheSignerReceiving = {};
            cacheSignerSender = {};
            journal = lib.genAttrs ["systemMaxUse" "systemMaxFileSize" "runtimeMaxUse" "runtimeMaxFileSize"] (_: 1);
            audit = lib.genAttrs ["maxLogFileMiB" "numLogs" "maximumRules" "maximumRuleBytes" "maximumBacklog"] (_: 1);
          };
          policyAuthority = {
            enable = true;
            _normalStartupProfile = pkgs.aos-sandboxd;
            credentials.cacheOwnerReadbackPublicKey = "cache-public-pin";
          };
          cacheSignerView.enable = true;
          cacheSignerService = {
            enable = true;
            credentials = {
              seed = "cache-private-seed";
              publicKey = "cache-public-pin";
              memoryCeiling = "cache-memory-ceiling";
            };
          };
        };
      })
      ../../modules/sandbox/cache-signer-view.nix
      ../../modules/sandbox/cache-signer-service.nix
    ];
  };
  config = evaluation.config;
  view = config.systemd.services.aos-sandbox-cache-signer-views;
  service = config.systemd.services.aos-sandbox-cache-signerd;
  socket = config.systemd.sockets.aos-sandbox-cache-signerd;
  serviceConfig = service.serviceConfig;
  socketConfig = socket.socketConfig;
  viewSource = builtins.readFile ../../modules/sandbox/cache-signer-view.nix;
  weakened = evaluation.extendModules {
    modules = [
      ({lib, ...}: {
        systemd.services.aos-sandbox-cache-signerd.serviceConfig.ReadWritePaths = lib.mkForce ["/var/lib/aos/sandbox"];
      })
    ];
  };
  badPin = evaluation.extendModules {
    modules = [
      ({lib, ...}: {
        aos.sandbox.cacheSignerService.credentials.publicKey = lib.mkForce "wrong-cache-pin";
      })
    ];
  };
  controllerSigning = evaluation.extendModules {
    modules = [
      ({lib, ...}: {
        aos.sandbox.controllerService.credentials.cacheOwnerReadbackSigningKey = lib.mkForce "controller-seed";
      })
    ];
  };
  missingMemory = evaluation.extendModules {
    modules = [
      ({lib, ...}: {
        aos.sandbox.cacheSignerService.credentials.memoryCeiling = lib.mkForce null;
      })
    ];
  };
  wrongPackage = evaluation.extendModules {
    modules = [
      ({lib, ...}: {
        aos.sandbox.cacheSignerService.package = lib.mkForce pkgs.coreutils;
      })
    ];
  };
  onlineEvaluation = evaluation.extendModules {
    # These are selection-only fixtures; no credential or native original is
    # created by changing a package's public domain comparison input.
    modules = [
      ({lib, ...}: {
        options.aos.sandbox.nixBroker = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
        };
        config.aos.sandbox.nixBroker = {
          enable = true;
          domainIdHex = onlineDomain;
        };
      })
    ];
  };
  otherDomainSigner = onlineEvaluation.extendModules {
    modules = [{aos.sandbox.cacheSignerService.package = lib.mkForce otherOnlinePackage;}];
  };
  missingParent = evaluation.extendModules {
    modules = [{aos.sandbox.resourceBank.parentEnclosure = lib.mkForce null;}];
  };
  missingReceiving = evaluation.extendModules {
    modules = [{aos.sandbox.resourceBank.parentEnclosure.cacheSignerReceiving = lib.mkForce null;}];
  };
  missingSender = evaluation.extendModules {
    modules = [{aos.sandbox.resourceBank.parentEnclosure.cacheSignerSender = lib.mkForce null;}];
  };
  missingProfile = evaluation.extendModules {
    modules = [{aos.sandbox.policyAuthority._normalStartupProfile = lib.mkForce null;}];
  };
  wrongSystemd = evaluation.extendModules {
    # The genuine projection is an option default, so one explicit definition
    # replaces it without wrapping the discriminated submodule in mkForce.
    modules = [{aos.manager.selected = selectedManager // {package = toString pkgs.coreutils;};}];
  };
  refuses = message: result:
    lib.any (check: check.message == message && !check.assertion) result.config.assertions;
  parentMessage = "installed Cache signer requires its genuine Parent and distinct explicit Cache receiving/sender F/M slices";
  profileMessage = "installed Cache signer requires its exact image-delivered Root profile and all PID1 pre-listen subject options";
  signerMessage = "protected Cache signer requires the immutable selected image and its exact single signer role without helper commands or namespaces";
  exactPackageAssertion = check:
    check.message == "confined Cache signer requires the exact evaluated policy-labelled AOS executable";
in
  assert lib.all (package: package == pkgs.aos-sandboxd) (sharedPackages baseImage);
  assert lib.all (package: package == onlinePackage) (sharedPackages onlineImage);
  assert onlinePackage != otherOnlinePackage;
  assert lib.all (check: check.assertion) config.assertions;
  assert lib.all (check: check.assertion) onlineEvaluation.config.assertions;
  assert refuses signerMessage otherDomainSigner;
  assert lib.any (check: !check.assertion) (lib.filter exactPackageAssertion otherDomainSigner.config.assertions);
  assert lib.any (check: !check.assertion) weakened.config.assertions;
  assert lib.any (check: !check.assertion) badPin.config.assertions;
  assert lib.any (check: !check.assertion) controllerSigning.config.assertions;
  assert lib.any (check: !check.assertion) missingMemory.config.assertions;
  assert lib.length (lib.filter exactPackageAssertion config.assertions) == 1;
  assert lib.any (check: !check.assertion) (lib.filter exactPackageAssertion wrongPackage.config.assertions);
  assert refuses parentMessage missingParent;
  assert refuses parentMessage missingReceiving;
  assert refuses parentMessage missingSender;
  assert refuses profileMessage missingProfile;
  assert refuses signerMessage wrongSystemd;
  assert serviceConfig.SELinuxContext == "system_u:system_r:aos_sandbox_cache_signer_t";
  assert serviceConfig.ExecStart == "${pkgs.aos-sandboxd}/bin/aos-sandbox-cache-signerd 811 811 813 813";
  assert config.aos.users.users.aos-cache-signer.uid == 813;
  assert config.aos.users.users.aos-cache-signer.extraGroups == [];
  assert config.aos.users.groups.aos-cache-signer.gid == 813;
  assert view.serviceConfig.User == "root";
  assert view.serviceConfig.CapabilityBoundingSet == ["CAP_CHOWN" "CAP_DAC_READ_SEARCH" "CAP_SETGID" "CAP_SETUID" "CAP_SYS_ADMIN"];
  assert lib.hasInfix "--options ro,nosuid,nodev,noexec,nosymfollow" viewSource;
  assert lib.hasInfix "--map-users \"$controller_uid:$signer_uid:1\"" viewSource;
  assert lib.hasInfix "--map-groups \"$controller_gid:$signer_gid:1\"" viewSource;
  assert socketConfig.ListenStream == "/run/aos/sandbox-cache-signerd.sock";
  assert socketConfig.SocketUser == "aos-cache-signer";
  assert socketConfig.SocketGroup == "aos-sandboxd";
  assert socketConfig.SocketMode == "0660";
  assert serviceConfig.User == "aos-cache-signer" && serviceConfig.Group == "aos-cache-signer";
  assert serviceConfig.CapabilityBoundingSet == "" && serviceConfig.NoNewPrivileges;
  assert serviceConfig.ProtectSystem == "strict" && serviceConfig.PrivateNetwork;
  assert serviceConfig.ReadWritePaths or [] == [];
  assert serviceConfig.BindPaths or [] == [];
  assert serviceConfig.InaccessiblePaths == ["/run/aos/sandbox-policy-cache-journals"];
  assert serviceConfig.LoadCredential
  == [
    "cache-signer-v2-seed:/run/credentials/@system/cache-private-seed"
    "cache-owner-readback-public-key:/run/credentials/@system/cache-public-pin"
    "cache-signer-v2-memory-ceiling:/run/credentials/@system/cache-memory-ceiling"
  ];
    pkgs.mkDerivation {
      pname = "sandbox-cache-signer-service-eval";
      version = "0";
      src = null;
      buildDeps = [];
      runtimeDeps = [];
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
