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
        resourceModule = import ../../modules/sandbox/controller-resource-bank.nix {inherit config lib pkgs;};
        hostModule = import ../../modules/sandbox/host-broker.nix {inherit config lib pkgs;};
        mountModule = import ../../modules/sandbox/mount-broker.nix {inherit config lib pkgs;};
        cacheModule = import ../../modules/sandbox/cache-signer-service.nix {inherit config lib pkgs;};
      in {
        # This isolated fixture bypasses module discovery. Import the real
        # nullable schemas used by Root without enabling their native roles.
        options.aos.sandbox.resourceBank.policy = resourceModule.options.aos.sandbox.resourceBank.policy;
        options.aos.sandbox.hostBroker.credentials = hostModule.options.aos.sandbox.hostBroker.credentials;
        options.aos.sandbox.mountBroker.credentials = mountModule.options.aos.sandbox.mountBroker.credentials;
        options.aos.sandbox.cacheSignerService.credentials = cacheModule.options.aos.sandbox.cacheSignerService.credentials;
        options.aos.sandbox.controller.uid = lib.mkOption {type = lib.types.int;};
        options.aos.sandbox.controller.gid = lib.mkOption {type = lib.types.int;};

        # Recovery custody is checked without selecting the confined normal role.
        config.aos.security.selinux = {
          enable = false;
          bootMode = "legacy";
        };
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

  noApplyEvaluation = signing: public:
    evaluation.extendModules {
      modules = [
        {
          aos.sandbox.policyAuthority.credentials.rootNoApplyFloorSigningKey = signing;
          aos.sandbox.hostBroker.credentials.rootNoApplyFloorPublicKey = public;
        }
      ];
    };
  withNoApply = noApplyEvaluation "root-noapply-private" "root-noapply-public";
  noApplyNormal = withNoApply.config.systemd.services.aos-sandbox-policy-authorityd.serviceConfig;
  noApplyRecovery = withNoApply.config.systemd.services.${serviceName}.serviceConfig;
  # This isolated legacy fixture checks delivery and the pairing assertion only;
  # it does not select or qualify the confined Root signing role.
  acceptsNoApplyPair = result:
    (lib.findFirst
      (check: check.message == "Root NoApply floor signing and Host public pin require distinct external credential names provisioned together")
      (throw "missing Root NoApply pairing assertion")
      result.config.assertions).assertion;

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
  withoutPacket = evaluation.extendModules {
    modules = [{aos.sandbox.policyAuthority.credentials.projectHeadPacketV2 = lib.mkForce null;}];
  };
  withoutInput = evaluation.extendModules {
    modules = [{aos.sandbox.policyAuthority.credentials.projectLayerV2 = lib.mkForce null;}];
  };
  withoutPair = evaluation.extendModules {
    modules = [
      {
        aos.sandbox.policyAuthority.credentials = {
          projectHeadPacketV2 = lib.mkForce null;
          projectLayerV2 = lib.mkForce null;
        };
      }
    ];
  };
  hasRefusal = result:
    lib.any (check:
      !check.assertion
      && lib.hasInfix "V2 project" check.message)
    result.config.assertions;
  # Check the actual credential schema without forcing unrelated service builders.
  strictOptionAccepted = extraModule:
    (builtins.tryEval (builtins.deepSeq
      (lib.evalModules {
        modules = [
          {
            options.aos.sandbox.policyAuthority.credentials =
              evaluation.options.aos.sandbox.policyAuthority.credentials;
            config._module.strict = true;
          }
          extraModule
        ];
      }).config.aos.sandbox.policyAuthority.credentials
      true)).success;
in
  assert lib.all (check: check.assertion) evaluation.config.assertions;
  assert evaluation.config.aos.sandbox.resourceBank.policy == null;
  assert lib.all (value: value == null) (builtins.attrValues evaluation.config.aos.sandbox.hostBroker.credentials);
  assert lib.all (value: value == null) (builtins.attrValues evaluation.config.aos.sandbox.mountBroker.credentials);
  assert lib.all (value: value == null) (builtins.attrValues evaluation.config.aos.sandbox.cacheSignerService.credentials);
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
  assert builtins.length noApplyNormal.LoadCredential == 11;
  assert lib.elem "root-noapply-floor-signing:/run/credentials/@system/root-noapply-private" noApplyNormal.LoadCredential;
  assert lib.elem "root-noapply-floor-public:/run/credentials/@system/root-noapply-public" noApplyNormal.LoadCredential;
  assert (noApplyRecovery.LoadCredential or []) == [];
  assert acceptsNoApplyPair withNoApply;
  assert !(acceptsNoApplyPair (noApplyEvaluation "private-only" null));
  assert !(acceptsNoApplyPair (noApplyEvaluation null "public-only"));
  assert !(acceptsNoApplyPair (noApplyEvaluation "same-source" "same-source"));
  assert hasRefusal withoutPacket && hasRefusal withoutInput && hasRefusal withoutPair;
  assert strictOptionAccepted {};
  assert strictOptionAccepted {
    aos.sandbox.policyAuthority.credentials = {
      projectHeadPacketV2 = "project-packet-v2";
      projectLayerV2 = "project-layer-v2";
    };
  };
  assert !(strictOptionAccepted {aos.sandbox.policyAuthority.credentials.projectHeadPacket = "retired-input";});
  assert !(strictOptionAccepted {aos.sandbox.policyAuthority.credentials.projectLayer = "retired-input";});
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
