##! Configures compressed swap through its upstream generator and setup template.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: let
  cfg = config.aos.zram;
  operations = config.aos.abilities;
  modules = operations.kernelModules.operations.ensure.effects.zram;
  generator = operations.filesystem.operations.entry.effects.zram-generator;
  configuration = operations.configuration.operations.file.effects.zram-generator;
  sizeType = lib.types.addCheck lib.types.str (value: builtins.match "[A-Za-z0-9 ()*/+.,_-]+" value != null);
  algorithmType = lib.types.addCheck lib.types.str (value: builtins.match "[A-Za-z0-9_+().,=-]+" value != null);
in {
  options.aos.zram = {
    enable = lib.mkEnableOption "compressed in-memory swap";
    size = lib.mkOption {
      type = sizeType;
      default = "min(ram / 2, 4096)";
      description = "Arithmetic expression setting zram size in MiB.";
    };
    compressionAlgorithms = lib.mkOption {
      type = lib.types.addCheck (lib.types.listOf algorithmType) (value: value != []);
      default = ["zstd"];
      description = "Compression algorithms tried in priority order.";
    };
    priority = lib.mkOption {
      type = lib.types.ints.between (-1) 32767;
      default = 100;
      description = "Swap priority assigned to the zram device.";
    };
  };
  config = lib.mkMerge [
    {
      aos.zram = {
        enable = lib.mkDefault config.aos.storage.compressedSwapRecommended;
        size = lib.mkIf config.aos.storage.compressedSwapRecommended (lib.mkDefault "min(ram / 8, 2048)");
      };
    }
    (lib.mkIf cfg.enable {
      system.checks.zram = {
        description = "Compressed swap checks";
        checks = [
          {
            name = "zram-swap-device";
            description = "The configured zram swap device is initialized";
            script = ''
              vm.wait_until_succeeds("test -b /dev/zram0", timeout=30)
              vm.succeed("test $(cat /sys/block/zram0/disksize) -gt 0")
            '';
          }
        ];
      };
      aos.abilities = {
        kernelModules.operations.ensure.effects.zram.input = {
          modules = ["zram"];
          required = true;
        };
        filesystem.operations.entry.effects.zram-generator = {
          after = [configuration.outputs.path];
          input = {
            path = "/etc/systemd/system-generators/zram-generator";
            kind = "copied-file";
            sourcePath = "${package}/bin/zram-generator";
            mode = "0555";
          };
        };
        configuration.operations.file.effects.zram-generator.input = {
          path = "/etc/systemd/zram-generator.conf";
          content = ''
            [zram0]
            zram-size = ${cfg.size}
            compression-algorithm = ${lib.concatStringsSep " " cfg.compressionAlgorithms}
            swap-priority = ${toString cfg.priority}
          '';
        };
        packagedUnit.operations.ensure.effects.zram-setup = {
          after = [modules.outputs.loaded];
          input = {
            source = "${package}/lib/systemd/system/systemd-zram-setup@.service";
            activation = "reference";
            accepted_exit_statuses = [0];
            reload_triggers = [generator.outputs.path configuration.outputs.path];
            # Upstream delegates swap formatting to systemd-makefs, which
            # resolves mkswap through the inherited unit execution search path.
            search_path = ["${dependencies.util-linux}/bin" "${dependencies.util-linux}/sbin"];
          };
        };
      };
    })
  ];
}
