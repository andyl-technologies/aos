##! modules/services/zram.nix — Compressed swap backed by zram
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.zram;

  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  filesystemEntry = interfaces.filesystemEntry;
  systemdPackage = "systemd";
  systemdPackagedUnitAlias = "systemd-packaged-unit";
  systemdPackagedUnitKey = "${systemdPackage}:${systemdPackagedUnitAlias}";
  systemdPackagedUnit = {
    alias = systemdPackagedUnitAlias;
    declaration = config.aos.abilities.interfaces.${systemdPackagedUnitKey};
  };
  resultOf = lib.abilities.resultOf;
  consumerInstance = "system:zram";
  kernelModulesRequest = "zram-kernel-modules";
  generatorConfigurationRequest = "zram-generator-config";
  generatorExecutableRequest = "zram-generator-executable";
  generatorConfigurationEntryRequest = "zram-generator-configuration";
  generatorDirectoryRequest = "zram-generator-directory";

  zramGeneratorArtifact = lib.abilities.packageOutput {
    package = "zram-generator";
  };
  utilLinuxArtifact = lib.abilities.packageOutput {
    package = "util-linux";
  };
  generatorDirectory = "/etc/systemd/system-generators";
  generatorExecutable = "${generatorDirectory}/zram-generator";
  generatorConfiguration = "/etc/systemd/zram-generator.conf";
  generatorConfigurationText = ''
    [zram0]
    zram-size = ${cfg.size}
    compression-algorithm = ${lib.concatStringsSep " " cfg.compressionAlgorithms}
    swap-priority = ${toString cfg.priority}
  '';

  producer = key: interface: parameters:
    serviceManagement.forProducer {
      inherit consumerInstance key interface parameters;
    };
  kernelReadiness = resultOf kernelModulesRequest "readiness-resource";
  retainedBy = request: resultOf request "retained-resource";
  plannedGeneratorExecutable = resultOf generatorExecutableRequest "planned-path";
  plannedGeneratorConfiguration =
    resultOf generatorConfigurationEntryRequest "planned-path";
  abilityFragments = [
    (producer kernelModulesRequest interfaces.kernelModules {
      modules = ["zram"];
      required = true;
    })
    (serviceManagement.forConfiguration {
      inherit serviceTypes consumerInstance;
      declaration = {
        name = generatorConfigurationRequest;
        source = {
          kind = "inline-text";
          content = generatorConfigurationText;
        };
        mode = "0444";
      };
    })
    (serviceManagement.forProducers {
      inherit consumerInstance;
      interface = filesystemEntry;
      methods = ["materialize" "observe" "release"];
      producers = [
        {
          key = generatorDirectoryRequest;
          parameters = {
            name = "zram-generator-directory";
            entry.kind = "directory";
            destination = generatorDirectory;
            owner = "root";
            group = "root";
            mode = "0755";
            prerequisites = [];
          };
        }
        {
          key = generatorExecutableRequest;
          parameters = {
            name = "zram-generator";
            entry = {
              kind = "copied-file";
              source = {
                kind = "artifact-file";
                reference = {
                  artifact = zramGeneratorArtifact;
                  path = "bin/zram-generator";
                };
              };
              maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
            };
            destination = generatorExecutable;
            owner = "root";
            group = "root";
            mode = "0755";
            prerequisites = [(retainedBy generatorDirectoryRequest)];
          };
        }
        {
          key = generatorConfigurationEntryRequest;
          parameters = {
            name = "zram-generator-configuration";
            entry = {
              kind = "copied-file";
              source = {
                kind = "execution-path";
                resource = resultOf generatorConfigurationRequest "retained-resource";
                path = resultOf generatorConfigurationRequest "execution-path";
              };
              maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
            };
            destination = generatorConfiguration;
            owner = "root";
            group = "root";
            mode = "0444";
            prerequisites = [(retainedBy generatorConfigurationRequest)];
          };
        }
      ];
    })
    (serviceManagement.forProducer {
      inherit consumerInstance;
      key = "zram-setup-unit";
      interface = systemdPackagedUnit;
      methods = ["observe"];
      parameters = {
        source = {
          artifact = zramGeneratorArtifact;
          unit_file = "lib/systemd/system/systemd-zram-setup@.service";
        };
        activation = "reference";
        prerequisites = [kernelReadiness];
        dependencies = {
          after = [];
          before = [];
          requires = [];
          wants = [];
        };
        drop_in = {
          accepted_exit_statuses = [0];
          reload_triggers = [
            plannedGeneratorExecutable
            plannedGeneratorConfiguration
          ];
          # The setup helper delegates swap formatting to systemd-makefs, which
          # resolves mkswap through the inherited unit's execution search path.
          search_path = [utilLinuxArtifact];
        };
      };
    })
  ];
in {
  options.aos.zram = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Create a compressed in-memory swap device.";
    };

    size = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9 ()*/+.,_-]+";
      default = "min(ram / 2, 4096)";
      description = "Arithmetic expression that sets the zram device size in MiB.";
    };

    compressionAlgorithms = lib.mkOption {
      type = lib.types.listOf (lib.types.strMatching "[A-Za-z0-9_+().,=-]+");
      default = ["zstd"];
      description = "Compression algorithms tried in priority order.";
    };

    priority = lib.mkOption {
      type = lib.types.int;
      default = 100;
      description = "Swap priority assigned to the zram device.";
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge ([
      {
        assertions = [
          {
            assertion = cfg.priority >= -1 && cfg.priority <= 32767;
            message = "aos.zram.priority must be between -1 and 32767";
          }
          {
            assertion = cfg.compressionAlgorithms != [];
            message = "aos.zram.compressionAlgorithms must contain at least one algorithm";
          }
        ];

        environment.systemPackages = [pkgs.zram-generator];
        aos.abilities.instances.${consumerInstance} = {};

        system.checks.zram = {
          description = "Compressed swap checks";
          checks = [
            {
              name = "zram-swap-active";
              description = "The generated zram swap unit activates";
              script = ''
                vm.wait_until_succeeds(
                    "systemctl is-active --quiet dev-zram0.swap", timeout=30
                )
                vm.succeed("test -b /dev/zram0")
                vm.succeed("test $(cat /sys/block/zram0/disksize) -gt 0")
              '';
            }
          ];
        };
      }
    ]
    ++ builtins.map (fragment: {aos.abilities = fragment;}) abilityFragments));
}
