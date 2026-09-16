##! Systemd backend for checked initrd-to-host ability-stage ownership transfer.
{
  config,
  lib,
  pkgs,
  ...
}: let
  enabled = config.aos.boot.initrd.abilityHandoff.enable;
  packageRuntime = pkgs.aos.packageRuntime;
in {
  config = lib.mkIf enabled {
    # These units bootstrap the checked ability executor itself, so they are
    # rendered by the selected manager backend rather than by an ability whose
    # execution would depend on the same controller.
    boot.initrd.systemd.services.aos-ability-initrd-controller = {
      description = "Execute and release initrd-stage ability ownership";
      requiredBy = ["initrd-fs.target"];
      requires = [
        "sysroot.mount"
        "aos-boot-transaction-storage.service"
      ];
      after = [
        "sysroot.mount"
        "aos-boot-transaction-storage.service"
      ];
      before = [
        "mount-var.service"
        "initrd-fs.target"
        "initrd-switch-root.target"
      ];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        exec ${packageRuntime}/bin/.aos-package-runtime-unwrapped \
          __ability-stage-run \
          --stage initrd \
          --root /sysroot \
          --source-stage-bundle /lib/aos/initrd/source-stage-bundle.json \
          --static-contract-identity ${config.system.build.initrdStaticAbilityContract}/contract.json \
          --static-contract /lib/aos/initrd/static-ability-contract.json
      '';
    };

    boot.initrd.systemd.services.aos-ability-initrd-handoff-barrier = {
      description = "Authenticate released initrd ability ownership";
      requiredBy = [
        "mount-var.service"
        "initrd-fs.target"
      ];
      requires = ["aos-ability-initrd-controller.service"];
      after = ["aos-ability-initrd-controller.service"];
      before = [
        "mount-var.service"
        "initrd-fs.target"
        "initrd-switch-root.target"
      ];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        exec ${packageRuntime}/bin/.aos-package-runtime-unwrapped \
          __ability-stage-validate \
          --from-stage initrd \
          --root /sysroot \
          --source-stage-bundle /lib/aos/initrd/source-stage-bundle.json \
          --static-contract-identity ${config.system.build.initrdStaticAbilityContract}/contract.json \
          --static-contract /lib/aos/initrd/static-ability-contract.json
      '';
    };

    systemd.services.aos-ability-host-receiver = {
      description = "Revalidate and receive initrd ability ownership";
      requiredBy = [
        "aos-eval.service"
        "aos-graph-compile.service"
        "aos-config.target"
      ];
      requires = [
        "local-fs.target"
        "aos-nix-db.service"
      ];
      after = [
        "local-fs.target"
        "aos-nix-db.service"
      ];
      before = [
        "aos-eval.service"
        "aos-graph-compile.service"
        "aos-config.target"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      unitConfig.RequiresMountsFor = "/var/lib/profiles/image";
      script = ''
        exec ${packageRuntime}/bin/.aos-package-runtime-unwrapped \
          __ability-stage-receive \
          --from-stage initrd \
          --image-profile /var/lib/profiles/image \
          --source-stage-bundle /usr/lib/aos/initrd/source-stage-bundle.json \
          --static-contract-identity ${config.system.build.initrdStaticAbilityContract}/contract.json \
          --static-contract /usr/lib/aos/initrd/static-ability-contract.json
      '';
    };
  };
}
