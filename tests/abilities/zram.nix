##! Checks zram integration at its typed resource boundaries.
{lib}: let
  zramGenerator = builtins.toFile "zram-generator" "";
  utilLinux = builtins.toFile "util-linux" "";
  evaluate = size:
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
              enable = true;
              inherit size;
            };
          };
        })
      ];
      packageModules = [
        {
          name = "systemd";
          module.imports = [../../pkgs/system/_systemd-abilities.nix];
        }
      ];
    };
  baseline = evaluate "min(ram / 2, 4096)";
  changed = evaluate "2048";
  requests = baseline.config.aos.abilities.requests;
  filesystemRequirement =
    baseline.config.aos.abilities.requirementTemplates."system:filesystem-entry";
  packagedUnitRequirement =
    baseline.config.aos.abilities.requirementTemplates."system:systemd-packaged-unit";
  kernelModules = requests."system:zram-kernel-modules".parameters;
  configuration = requests."system:zram-generator-config".parameters;
  directory = requests."system:zram-generator-directory".parameters;
  executable = requests."system:zram-generator-executable".parameters;
  configurationEntry = requests."system:zram-generator-configuration".parameters;
  packagedUnit = requests."system:zram-setup-unit".parameters;
  kernelReadiness = {
    _type = "aos-request-output-reference";
    request = "system:zram-kernel-modules";
    output = "readiness-resource";
  };
in
  assert baseline.config.environment.systemPackages == [zramGenerator];
  assert filesystemRequirement.methods == ["materialize" "observe" "release"];
  assert packagedUnitRequirement.methods == ["observe"];
  assert builtins.all (assertion: assertion.assertion) baseline.config.assertions;
  assert builtins.attrNames requests
  == [
    "system:zram-generator-config"
    "system:zram-generator-configuration"
    "system:zram-generator-directory"
    "system:zram-generator-executable"
    "system:zram-kernel-modules"
    "system:zram-setup-unit"
  ];
  assert kernelModules
  == {
    modules = ["zram"];
    required = true;
  };
  assert configuration.source.kind == "inline-text";
  assert lib.hasInfix "zram-size = min(ram / 2, 4096)" configuration.source.content;
  assert configuration.source.content
  != changed.config.aos.abilities.requests."system:zram-generator-config".parameters.source.content;
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
      request = "system:zram-generator-directory";
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
        request = "system:zram-generator-config";
        output = "retained-resource";
      };
      path = {
        _type = "aos-request-output-reference";
        request = "system:zram-generator-config";
        output = "execution-path";
      };
    };
    maximum_size_bytes = lib.abilities.types.limits.maxSafeInteger;
  };
  assert configurationEntry.destination == "/etc/systemd/zram-generator.conf";
  assert configurationEntry.prerequisites
  == [
    {
      _type = "aos-request-output-reference";
      request = "system:zram-generator-config";
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
          request = "system:zram-generator-executable";
          output = "planned-path";
        }
        {
          _type = "aos-request-output-reference";
          request = "system:zram-generator-configuration";
          output = "planned-path";
        }
      ];
      search_path = [(lib.abilities.packageOutput {package = "util-linux";})];
    };
  };
  assert !(baseline.config ? systemd);
  assert !(baseline.config.aos ? kernel); true
