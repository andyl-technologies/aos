# Evaluation contract for credential-independent Root Cache settlement recovery.
{
  pkgs,
  lib,
}: let
  serviceName = "aos-sandbox-policy-cache-recovery";
  recoveryCommand = "${pkgs.aos-sandboxd}/bin/aos-sandbox-policy-authorityd --serve-cache-signer-recovery 811 811";

  systemdOptions = {lib, ...}: {
    options.assertions = lib.mkOption {
      type = lib.types.listOf lib.types.anything;
      default = [];
    };
    options.systemd.services = lib.mkOption {
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

        config.aos.sandbox = {
          controller = {
            uid = 811;
            gid = 811;
          };
          policyAuthority = {
            enable = true;
            credentials = {
              deploymentPublicKey = "deployment-key";
              deploymentHeadPacket = "deployment-packet";
              nodePolicy = "node-policy";
              sitePolicy = "site-policy";
              backendCapabilities = "backend-capabilities";
              catalogs = "catalogs";
              projectPublicKey = "project-key";
              projectHeadPacketV2 = "project-packet-v2";
              projectLayerV2 = "project-layer-v2";
            };
          };
        };
      })
      ../../modules/sandbox/policy-authority.nix
    ];
  };

  recovery = evaluation.config.systemd.services.${serviceName};
  service = recovery.serviceConfig;
  normal = evaluation.config.systemd.services.aos-sandbox-policy-authorityd.serviceConfig;
  weakened = evaluation.extendModules {
    modules = [
      ({lib, ...}: {
        systemd.services = lib.mkForce (evaluation.config.systemd.services
          // {
            ${serviceName} =
              recovery
              // {
                serviceConfig =
                  service
                  // {
                    LoadCredential = [
                      "deployment-head.packet:/run/credentials/@system/missing-policy-source"
                    ];
                  };
              };
          });
      })
    ];
  };
  weakenedAssertions = builtins.filter (check: !check.assertion) weakened.config.assertions;
in
  assert lib.all (check: check.assertion) evaluation.config.assertions;
  assert recovery.wantedBy == ["multi-user.target"];
  assert recovery.after == ["local-fs.target"];
  assert recovery.unitConfig.RequiresMountsFor == ["/var/lib/aos/sandbox/policy-compiler"];
  assert (recovery.requires or []) == [];
  assert (recovery.unitConfig.BindsTo or []) == [];
  assert service.ExecStart == recoveryCommand;
  assert service.User == "root" && service.Group == "aos-sandboxd";
  assert service.UMask == "0007";
  assert service.RuntimeDirectory == "aos/sandbox-policy-cache-recovery";
  assert service.RuntimeDirectoryMode == "0710";
  assert service.StateDirectory == "aos/sandbox/policy-compiler";
  assert service.StateDirectoryMode == "0700";
  assert (service.LoadCredential or []) == [];
  assert service.ProtectSystem == "strict" && service.CapabilityBoundingSet == "";
  assert lib.any (check: lib.hasInfix "must not depend on policy credentials" check.message) weakenedAssertions;
  assert builtins.length normal.LoadCredential == 9;
    pkgs.mkDerivation {
      pname = "sandbox-policy-cache-recovery-service-eval";
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
