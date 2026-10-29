##! Unattended USB installer media for bare-metal installation.
##!
##! Installer media is built from a second evaluation of a system with
##! `aos.image.installer.media` set (see `lib.build.installerMedia`). That
##! evaluation selects installer mode for its initrd: the same metadata
##! acquisition, authorization, and host.nix evaluation as a normal first boot,
##! followed by installation of the original evaluation's release image
##! instead of storage provisioning. Its own kernel and initrd become the
##! signed installer UKI; its own images are never built.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.image.installer;
  sb = config.aos.boot.secureBoot;
  trustBundle = import ../../pkgs/system/_systemd-abilities/platform/_active-db-certs.nix {
    inherit pkgs lib config;
  };

  # The initrd fixed point admits stage policy only through packages. This
  # one publishes the release trust bundle and selects installer mode.
  installerPolicy = pkgs.mkDerivation {
    pname = "aos-installer-media-policy";
    version = "1";
    module = ../../pkgs/system/_aos-storage-provisioning-provider/installer-media-policy;
    moduleDeps = [pkgs.aos-storage-provisioning-provider pkgs.aos-boot-storage];
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp ${trustBundle}/active-db-certs.pem "$out/active-db-certs.pem"
        '';
      }
    ];
  };
in {
  options.aos.image.installer = {
    media = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = "Whether this evaluation produces installer media rather than a bootable system.";
    };
    releaseImage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      internal = true;
      description = "Raw release image output that the media installs.";
    };
    hostConfiguration = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        host.nix to place on the media's AOS-META partition. Leave null to
        ship blank media that the operator fills before installation.
      '';
    };
  };

  options.system.build.installerMedia = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    description = "Raw GPT installer media image for writing to a USB stick.";
  };

  config = lib.mkIf cfg.media {
    assertions = [
      {
        assertion = sb.enable && !sb.externalFinalization.enable;
        message = "installer media requires locally signed Secure Boot images: the payload is authenticated against the db key.";
      }
      {
        assertion = cfg.releaseImage != null;
        message = "installer media requires the raw release image it installs.";
      }
    ];

    aos.activation.stages.initrd.configurationBuilders = [
      (_: {
        packages = [installerPolicy];
        configuration = [];
      })
    ];

    # The installer UKI selects this target instead of initrd.target, so no
    # root device, switch-root, or persistent-state unit is ever started.
    boot.initrd.systemd.targets.aos-installer = {
      description = "AOS unattended installation";
      wants = [
        "aos-ability-initrd-controller.service"
        "aos-installer-reboot.service"
      ];
      unitConfig.AllowIsolate = true;
    };

    # A failed installation leaves the controller failed, so the reboot never
    # starts and the console keeps the diagnostic.
    boot.initrd.systemd.services.aos-installer-reboot = {
      description = "Reboot into the installed AOS system";
      after = ["aos-ability-initrd-controller.service"];
      requires = ["aos-ability-initrd-controller.service"];
      unitConfig.DefaultDependencies = false;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.systemd}/bin/systemctl --no-block reboot";
      };
    };
  };
}
