##! Package-owned zram generator configuration and activation requirements.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.zram;

  serviceManagement = lib.abilities.interfaces.serviceManagement;
  serviceTypes = serviceManagement.types;
  interfaces = serviceManagement.interfaces;
  abilityTypes = lib.abilities.types;
  filesystemEntry = interfaces.filesystemEntry;
  systemdPackagedUnitAlias = "systemd-packaged-unit";
  resultOf = lib.abilities.resultOf;
  consumerInstance = "zram";
  kernelModulesRequest = "zram-kernel-modules";
  generatorConfigurationRequest = "zram-generator-config";
  generatorExecutableRequest = "zram-generator-executable";
  generatorConfigurationEntryRequest = "zram-generator-configuration";
  generatorDirectoryRequest = "zram-generator-directory";

  sizeExpression = abilityTypes.refined {
    name = "zram size expression";
    description = "a bounded zram-generator arithmetic expression";
    type = abilityTypes.string {
      maxLength = abilityTypes.limits.maxStringLength;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[A-Za-z0-9 ()*/+.,_-]+";
      }
    ];
  };
  compressionAlgorithm = abilityTypes.refined {
    name = "zram compression algorithm";
    description = "a zram compression algorithm identifier";
    type = abilityTypes.string {
      maxLength = abilityTypes.limits.maxStringLength;
      syntax = null;
    };
    constraints = [
      {
        kind = "string-pattern";
        pattern = "[A-Za-z0-9_+().,=-]+";
      }
    ];
  };
  compressionAlgorithms = abilityTypes.refined {
    name = "zram compression algorithm list";
    description = "one or more compression algorithms in priority order";
    type = abilityTypes.list {
      element = compressionAlgorithm;
      maxItems = abilityTypes.limits.maxCollectionItems;
    };
    constraints = [
      {
        kind = "minimum-size";
        minimum = 1;
      }
    ];
  };
  zramGeneratorArtifact = lib.abilities.packageOutput {};
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
  packagedUnit = {
    requirementTemplates.${systemdPackagedUnitAlias} =
      lib.abilities.interfaceSelector {
        name = "aos.systemd.packaged-unit";
        abi = 1;
      }
      // {
        description = "Observe the packaged zram setup unit and its selected augmentation.";
        methods = ["observe"];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
    requests."zram-setup-unit" = {
      requirement = systemdPackagedUnitAlias;
      consumer = consumerInstance;
      scope = ["zram-setup-unit"];
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
    };
  };
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
                path = resultOf generatorConfigurationRequest "planned-path";
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
    packagedUnit
  ];
  contributions = builtins.map serviceManagement.splitContribution abilityFragments;
in {
  options.aos.zram = {
    enable = lib.mkOption {
      type = abilityTypes.boolean;
      default = false;
      description = "Create a compressed in-memory swap device.";
    };

    size = lib.mkOption {
      type = sizeExpression;
      default = "min(ram / 2, 4096)";
      description = "Arithmetic expression that sets the zram device size in MiB.";
    };

    compressionAlgorithms = lib.mkOption {
      type = compressionAlgorithms;
      default = ["zstd"];
      description = "Compression algorithms tried in priority order.";
    };

    priority = lib.mkOption {
      type = abilityTypes.integer {
        minimum = -1;
        maximum = 32767;
      };
      default = 100;
      description = "Swap priority assigned to the zram device.";
    };
  };

  config = lib.mkMerge [
    {
      aos.abilities = lib.mkMerge (
        builtins.map (contribution: contribution.declarations) contributions
      );
    }
    (lib.mkIf cfg.enable {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (contribution: contribution.configured) contributions
      );
    })
  ];
}
