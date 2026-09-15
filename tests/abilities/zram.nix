##! Checks zram integration at its typed resource boundaries.
{
  lib,
  pkgs,
}: let
  zramGenerator = builtins.toFile "zram-generator" "";
  utilLinux = builtins.toFile "util-linux" "";
  evaluate = {
    enable ? true,
    size ? "min(ram / 2, 4096)",
  }:
    lib.evalModules {
      specialArgs = {
        inherit lib;
        pkgs = {
          zram-generator = zramGenerator;
          util-linux = utilLinux;
        };
      };
      modules = [
        ../../modules/abilities/default.nix
        ../../modules/services/zram.nix
        ({lib, ...}: {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.attrs;
              default = [];
            };
            environment.systemPackages = lib.mkOption {
              type = lib.types.listOf lib.types.anything;
              default = [];
            };
            system.checks = lib.mkOption {
              type = lib.types.attrsOf lib.types.anything;
              default = {};
            };
          };
          config = {
            aos.abilities.environment = {
              authority = "deployment";
              key = "zram-test";
              stage = "host";
            };
            aos.zram = {
              inherit enable size;
            };
          };
        })
      ];
      packageModules = [
        {
          name = "zram-generator";
          module.imports = [../../pkgs/system/_zram-generator/module.nix];
        }
        {
          name = "systemd";
          module.imports = [../../pkgs/system/_systemd-abilities.nix];
        }
      ];
    };
  baseline = evaluate {};
  changed = evaluate {size = "2048";};
  disabled = evaluate {enable = false;};
  packageProjection = pkgs.zram-generator.abilities;
  packageContract = pkgs.zram-generator.contract.value;
  documentedOptionPaths =
    builtins.map
    (option: lib.concatStringsSep "." option.path)
    packageContract.option_declarations;
  requests = baseline.config.aos.abilities.requests;
  filesystemRequirement =
    baseline.config.aos.abilities.requirementTemplates."zram-generator:filesystem-entry";
  packagedUnitRequirement =
    baseline.config.aos.abilities.requirementTemplates."zram-generator:systemd-packaged-unit";
  kernelModules = requests."zram-generator:zram-kernel-modules".parameters;
  configuration = requests."zram-generator:zram-generator-config".parameters;
  directory = requests."zram-generator:zram-generator-directory".parameters;
  executable = requests."zram-generator:zram-generator-executable".parameters;
  configurationEntry = requests."zram-generator:zram-generator-configuration".parameters;
  packagedUnit = requests."zram-generator:zram-setup-unit".parameters;
  kernelReadiness = {
    _type = "aos-request-output-reference";
    request = "zram-generator:zram-kernel-modules";
    output = "readiness-resource";
  };
in
  assert baseline.config.environment.systemPackages == [zramGenerator];
  assert builtins.attrNames packageProjection.interfaces == [];
  assert builtins.attrNames packageProjection.implementations == [];
  assert builtins.attrNames packageProjection.requirementTemplates
  == [
    "configuration-materialization"
    "filesystem-entry"
    "kernel-modules"
    "systemd-packaged-unit"
  ];
  assert builtins.map (requirement: requirement.alias) packageContract.requirements
  == builtins.attrNames packageProjection.requirementTemplates;
  assert packageProjection.requirementTemplates."systemd-packaged-unit".accepted_interfaces
  == [
    {
      name = "aos.systemd.packaged-unit";
      abi = 1;
    }
  ];
  assert documentedOptionPaths
  == [
    "aos.zram.compressionAlgorithms"
    "aos.zram.enable"
    "aos.zram.priority"
    "aos.zram.size"
  ];
  assert builtins.all
  (option: option.source.path == "module.nix" && option.description != "")
  packageContract.option_declarations;
  assert packageContract.package_module
  == {
    artifact = {
      package = "self";
      output = "module";
    };
    path = "module.nix";
  };
  assert pkgs.zram-generator ? module;
  assert disabled.config.aos.abilities.instances == {};
  assert disabled.config.aos.abilities.requests == {};
  assert builtins.attrNames disabled.config.aos.abilities.requirementTemplates
  == [
    "zram-generator:configuration-materialization"
    "zram-generator:filesystem-entry"
    "zram-generator:kernel-modules"
    "zram-generator:systemd-packaged-unit"
  ];
  assert filesystemRequirement.methods == ["materialize" "observe" "release"];
  assert packagedUnitRequirement.methods == ["observe"];
  assert builtins.all (assertion: assertion.assertion) baseline.config.assertions;
  assert builtins.attrNames requests
  == [
    "zram-generator:zram-generator-config"
    "zram-generator:zram-generator-configuration"
    "zram-generator:zram-generator-directory"
    "zram-generator:zram-generator-executable"
    "zram-generator:zram-kernel-modules"
    "zram-generator:zram-setup-unit"
  ];
  assert kernelModules
  == {
    modules = ["zram"];
    required = true;
  };
  assert configuration.source.kind == "inline-text";
  assert lib.hasInfix "zram-size = min(ram / 2, 4096)" configuration.source.content;
  assert configuration.source.content
  != changed.config.aos.abilities.requests."zram-generator:zram-generator-config".parameters.source.content;
  assert directory.entry.kind == "directory";
  assert directory.destination == "/etc/systemd/system-generators";
  assert directory.prerequisites == [];
  assert executable.entry
  == {
    kind = "copied-file";
    source = {
      kind = "artifact-file";
      reference = {
        artifact = lib.abilities.packageOutput {package = "zram-generator";};
        path = "bin/zram-generator";
      };
    };
    maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
  };
  assert executable.destination == "/etc/systemd/system-generators/zram-generator";
  assert executable.prerequisites
  == [
    {
      _type = "aos-request-output-reference";
      request = "zram-generator:zram-generator-directory";
      output = "retained-resource";
    }
  ];
  assert configurationEntry.entry
  == {
    kind = "copied-file";
    source = {
      kind = "execution-path";
      resource = {
        _type = "aos-request-output-reference";
        request = "zram-generator:zram-generator-config";
        output = "retained-resource";
      };
      path = {
        _type = "aos-request-output-reference";
        request = "zram-generator:zram-generator-config";
        output = "planned-path";
      };
    };
    maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
  };
  assert configurationEntry.destination == "/etc/systemd/zram-generator.conf";
  assert configurationEntry.prerequisites
  == [
    {
      _type = "aos-request-output-reference";
      request = "zram-generator:zram-generator-config";
      output = "retained-resource";
    }
  ];
  assert packagedUnit
  == {
    source = {
      artifact = lib.abilities.packageOutput {package = "zram-generator";};
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
        {
          _type = "aos-request-output-reference";
          request = "zram-generator:zram-generator-executable";
          output = "planned-path";
        }
        {
          _type = "aos-request-output-reference";
          request = "zram-generator:zram-generator-configuration";
          output = "planned-path";
        }
      ];
      search_path = [(lib.abilities.packageOutput {package = "util-linux";})];
    };
  };
  assert !(baseline.config ? systemd);
  assert !(baseline.config.aos ? kernel); true
