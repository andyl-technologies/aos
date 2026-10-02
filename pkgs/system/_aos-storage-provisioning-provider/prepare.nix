##! Composes native detection, authorization, evaluation, and durable disk commit.
{
  config,
  lib,
  dependencies,
  packageName,
  evaluationInput,
  ...
}: let
  types = import ./types.nix {inherit lib;};
  abilities = config.aos.abilities;
  metadata = abilities.metadata.operations;
  network = abilities.network.operations;
  content = abilities.contentAddressedObject.operations.commit;
  marker = abilities.provisioningMarker.operations.observe;
  evaluate = abilities.provisioningEvaluation.operations.evaluate;
  commit = abilities.storageProvisioning.operations.commit;
  cfg = config.aos.storageProvisioning;
  evaluationContext =
    if cfg.evaluationContext == null
    then evaluationInput
    else cfg.evaluationContext;
  field = type: description: lib.mkOption {inherit type description;};
  tools = {
    systemd_repart = "${dependencies.systemd}/bin/systemd-repart";
    blkid = "${dependencies.util-linux}/sbin/blkid";
    lsblk = "${dependencies.util-linux}/bin/lsblk";
    sfdisk = "${dependencies.util-linux}/sbin/sfdisk";
    udevadm = "${dependencies.systemd}/bin/udevadm";
    mdadm = "${dependencies.mdadm}/sbin/mdadm";
    mkfs_ext4 = "${dependencies.e2fsprogs}/sbin/mkfs.ext4";
    mkfs_xfs = "${dependencies.xfsprogs}/sbin/mkfs.xfs";
  };
  metadataTools = {
    inherit (tools) blkid;
    mount = "${dependencies.util-linux}/bin/mount";
    umount = "${dependencies.util-linux}/bin/umount";
  };
in {
  options.aos.storageProvisioning = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = (config.aos.boot.stage or "host") == "initrd";
      description = "Enable the authorized one-time native provisioning transaction in the selected initrd.";
    };
    evaluationContext = lib.mkOption {
      type = lib.types.nullOr lib.types.pathInStore;
      default = null;
      extensible = true;
      description = "Exact admitted host package and authored source descriptor; standalone evaluation uses its own input when absent.";
    };
    request = lib.mkOption {
      type = types.request;
      default = {
        name = "system";
        root_device = config.aos.boot.storage.resolvedDevices.rootA;
        measured_boot = config.aos.boot.secureBoot.measuredBoot.enable;
      };
      description = "Fixed storage intent checked against the authorized plan.";
    };
    authorizationConfiguration = lib.mkOption {
      type = lib.types.nullOr metadata.authorize.input.options.configuration.type;
      default = config.aos.metadata.storageProvisioning.authorizationConfiguration;
      description = "Exact metadata trust policy and immutable signature anchors.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities.network.operations.bootstrap = {
        input.options.configuration = field (lib.types.deferred metadata.acquire.result.options.network_bootstrap.type) "Optional exact static network bootstrap from metadata acquisition.";
        result.options.resource = field lib.types.str "Established bootstrap resource, or completed empty bootstrap.";
      };
      aos.abilities.storageProvisioning.operations.prepare = {
        input.options = {
          request = field types.request "Fixed one-time storage intent.";
          evaluation_context = field (lib.types.deferred lib.types.str) "Admitted pre-evaluation package and authored source descriptor.";
          authorization_configuration = field metadata.authorize.input.options.configuration.type "Metadata trust policy and immutable signature anchors.";
        };
        result.options = {
          resource = field lib.types.str "Durable verified disk transaction identity.";
          committed_plan = field lib.types.str "Immutable canonical validated provisioning plan path.";
          authorized_input = field lib.types.str "Rooted self-contained authorization receipt for checked host source adoption.";
          authorized_input_sha256 = field lib.types.str "Exact canonical authorization receipt content digest.";
          source = field (lib.types.enum ["operator" "fallback"]) "Configuration source committed by the durable marker.";
        };
        handler = {
          input,
          children,
          ...
        }: {
          children = {
            detect = {
              imports = [metadata.detect.module];
              input = metadataTools;
            };
            connectivity = {
              imports = [network.ready.module];
              input = {
                required = children.detect.outputs.need_network;
                scope = "address-configured";
              };
            };
            acquire = {
              imports = [metadata.acquire.module];
              after = [children.connectivity.outputs.resource];
              input = metadataTools // {platform = children.detect.outputs.platform;};
            };
            bootstrap = {
              imports = [network.bootstrap.module];
              input.configuration = children.acquire.outputs.network_bootstrap;
            };
            authorize = {
              imports = [metadata.authorize.module];
              after = [children.bootstrap.outputs.resource];
              input = {
                configuration = input.authorization_configuration;
                evaluation_context = input.evaluation_context;
                acquired_metadata = children.acquire.outputs.acquired_metadata;
              };
            };
            authorizedInput = {
              imports = [content.module];
              lifetime = "persistent";
              input = {
                name = "authorized-provisioning-input";
                media_type = "application/vnd.aos.metadata.authorized-provisioning-input+json;version=1";
                content = children.authorize.outputs.canonical_input;
              };
            };
            marker = {
              imports = [marker.module];
              input = {
                root_device = input.request.root_device;
                inherit (tools) lsblk;
              };
            };
            evaluate = {
              imports = [evaluate.module];
              input = {
                inherit (input) request evaluation_context;
                authorized_input = children.authorizedInput.outputs.path;
                authorized_input_sha256 = children.authorizedInput.outputs.content_sha256;
                marker = children.marker.outputs.marker;
              };
            };
            planReceipt = {
              imports = [content.module];
              lifetime = "persistent";
              input = {
                name = "authorized-provisioning-plan";
                media_type = "application/vnd.aos.provisioning-plan+json";
                content = children.evaluate.outputs.canonical_plan;
              };
            };
            commit = {
              imports = [commit.module];
              lifetime = "persistent";
              after = [children.planReceipt.outputs.path];
              input = {
                inherit (input) request;
                inherit tools;
                plan = children.evaluate.outputs.provisioning_plan;
              };
            };
          };
          exports = {
            resource = children.commit.outputs.resource;
            source = children.commit.outputs.source;
            committed_plan = children.planReceipt.outputs.path;
            authorized_input = children.authorizedInput.outputs.path;
            authorized_input_sha256 = children.authorizedInput.outputs.content_sha256;
          };
        };
      };
    }
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = evaluationContext != null && cfg.authorizationConfiguration != null;
          message = "Native storage provisioning requires an admitted evaluation input and metadata trust policy.";
        }
      ];
      aos.storage.readinessByProvider.${packageName} = [abilities.storageProvisioning.operations.prepare.effects.system.outputs.resource];
      aos.abilities.storageProvisioning.operations.prepare.effects.system = {
        # Probes and bootstrap resources belong to this configured preparation;
        # the authorization, plan receipt, and disk commit retain durable state.
        lifetime = "instance";
        input = {
          request = cfg.request;
          evaluation_context = "${evaluationContext}";
          authorization_configuration = cfg.authorizationConfiguration;
        };
      };
    })
  ];
}
