# Resolved custody contract for the separate, nonauthorizing Cache signer.
{
  pkgs,
  lib,
}: let
  systemdOptions = {lib, ...}: {
    options.assertions = lib.mkOption {
      type = lib.types.listOf lib.types.anything;
      default = [];
    };
    options.systemd.services = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
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
  };
  evaluation = lib.evalModules {
    specialArgs = {inherit pkgs;};
    modules = [
      systemdOptions
      ({lib, ...}: {
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

        config.aos.sandbox = {
          controller = {
            uid = 811;
            gid = 811;
          };
          controllerService.enable = true;
          policyAuthority = {
            enable = true;
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
in
  assert lib.all (check: check.assertion) config.assertions;
  assert lib.any (check: !check.assertion) weakened.config.assertions;
  assert lib.any (check: !check.assertion) badPin.config.assertions;
  assert lib.any (check: !check.assertion) controllerSigning.config.assertions;
  assert lib.any (check: !check.assertion) missingMemory.config.assertions;
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
