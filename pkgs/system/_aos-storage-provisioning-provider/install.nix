##! Composes unattended installation from the same authorization and evaluation as first boot.
#
# Installer media boots an initrd that runs `installation.operations.unattended`
# instead of `storageProvisioning.operations.prepare`. The children up to
# `evaluate` are the ones a normal first boot runs, so the stick's host.nix is
# authorized and evaluated exactly as the installed system will later evaluate
# it. The final child writes the release image rather than partitioning disks.
{
  config,
  lib,
  dependencies,
  package,
  evaluationInput,
  ...
}: let
  types = import ./types.nix {inherit lib;};
  abilities = config.aos.abilities;
  metadata = abilities.metadata.operations;
  network = abilities.network.operations;
  content = abilities.contentAddressedObject.operations.commit;
  evaluate = abilities.provisioningEvaluation.operations.evaluate;
  install = abilities.installation.operations.install;
  cfg = config.aos.installer;
  provisioning = config.aos.storageProvisioning;
  evaluationContext =
    if provisioning.evaluationContext == null
    then evaluationInput
    else provisioning.evaluationContext;
  field = type: description: lib.mkOption {inherit type description;};
  installerProgram = package // {meta = (package.meta or {}) // {mainProgram = "aos-installer";};};
  metadataTools = {
    blkid = "${dependencies.util-linux}/sbin/blkid";
    mount = "${dependencies.util-linux}/bin/mount";
    umount = "${dependencies.util-linux}/bin/umount";
  };
  installerTools =
    metadataTools
    // {
      openssl = "${dependencies.openssl}/bin/openssl";
      zstd = "${dependencies.zstd}/bin/zstd";
      sgdisk = "${dependencies.gptfdisk}/bin/sgdisk";
      udevadm = "${dependencies.systemd}/bin/udevadm";
      efibootmgr = "${dependencies.efibootmgr}/bin/efibootmgr";
    };
  # The image is written whole, so no committed marker can exist on the
  # target. Evaluation receives the same observation a blank disk produces.
  absentMarker = {
    schema = "aos.storage.provisioning-marker-observation/v1";
    state = "absent";
  };
in {
  options.aos.installer = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      extensible = true;
      description = "Run unattended installation from boot media instead of first-boot storage provisioning.";
    };
    trustBundle = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      extensible = true;
      description = "PEM bundle of db certificates authorized to sign the release payload.";
    };
    countdownSeconds = lib.mkOption {
      type = lib.types.ints.between 1 300;
      default = 10;
      description = "Console countdown before the target disk is erased.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities.installation.operations.install = {
        input.options = {
          install_plan = field (lib.types.deferred types.install) "Validated installation intent from the authorized fixed point.";
          provisioning_plan = field (lib.types.deferred types.plan) "Validated storage plan the installed system will provision.";
          trust_bundle = field lib.types.str "PEM db certificates authorized to sign the release payload.";
          countdown_seconds = field lib.types.int "Console countdown before the target disk is erased.";
          tools = field types.installerTools "Exact retained installation tools.";
        };
        result.options = {
          resource = field lib.types.str "Installation transaction identity.";
          release = field lib.types.str "Installed signed release identity.";
          target = field lib.types.str "Stable path of the installed disk.";
        };
        handler.program = installerProgram;
      };

      aos.abilities.installation.operations.unattended = {
        input.options = {
          request = field types.request "Fixed provisioning intent the installed system will apply.";
          evaluation_context = field (lib.types.deferred lib.types.str) "Admitted pre-evaluation package and authored source descriptor.";
          authorization_configuration = field metadata.authorize.input.options.configuration.type "Metadata trust policy and immutable signature anchors.";
          trust_bundle = field lib.types.str "PEM db certificates authorized to sign the release payload.";
          countdown_seconds = field lib.types.int "Console countdown before the target disk is erased.";
        };
        result.options = {
          release = field lib.types.str "Installed signed release identity.";
          target = field lib.types.str "Stable path of the installed disk.";
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
              input = {
                name = "authorized-installation-input";
                media_type = "application/vnd.aos.metadata.authorized-provisioning-input+json;version=1";
                content = children.authorize.outputs.canonical_input;
              };
            };
            evaluate = {
              imports = [evaluate.module];
              input = {
                inherit (input) request evaluation_context;
                authorized_input = children.authorizedInput.outputs.path;
                authorized_input_sha256 = children.authorizedInput.outputs.content_sha256;
                marker = absentMarker;
              };
            };
            install = {
              imports = [install.module];
              # Decompressing, writing, and reading back a multi-GiB image
              # takes far longer than the default one-minute handler bound.
              timeoutMs = 3600000;
              input = {
                inherit (input) trust_bundle countdown_seconds;
                install_plan = children.evaluate.outputs.install_plan;
                provisioning_plan = children.evaluate.outputs.provisioning_plan;
                tools = installerTools;
              };
            };
          };
          exports = {
            release = children.install.outputs.release;
            target = children.install.outputs.target;
          };
        };
      };
    }
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = cfg.trustBundle != null;
          message = "aos.installer requires the release trust bundle.";
        }
        {
          assertion = !provisioning.enable;
          message = "aos.installer replaces first-boot storage provisioning; disable aos.storageProvisioning.";
        }
        {
          assertion = evaluationContext != null && provisioning.authorizationConfiguration != null;
          message = "aos.installer requires an admitted evaluation input and metadata trust policy.";
        }
      ];
      aos.abilities.installation.operations.unattended.effects.media = {
        lifetime = "transaction";
        input = {
          inherit (provisioning) request;
          evaluation_context = "${evaluationContext}";
          authorization_configuration = provisioning.authorizationConfiguration;
          trust_bundle = cfg.trustBundle;
          countdown_seconds = cfg.countdownSeconds;
        };
      };
    })
  ];
}
