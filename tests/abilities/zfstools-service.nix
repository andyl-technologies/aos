##! Fixed-point checks for package-owned scheduled ZFS snapshots.
{
  lib,
  pkgs,
}: let
  evaluate = enabled:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          aos.abilities.environment = {
            authority = "test";
            key = "zfstools";
            stage = "host";
          };
          aos.services.zfsAutoSnapshot = {
            enable = enabled;
            datasets = ["tank/data"];
            intervals.hourly = {
              calendar = "hourly";
              keep = 24;
            };
          };
        }
      ];
      packageModules = [
        {
          name = "zfstools";
          version = pkgs.zfstools.version;
          module = ../../pkgs/storage/_zfstools/module.nix;
        }
      ];
    };
  disabled = evaluate false;
  enabled = evaluate true;
  requests = enabled.config.aos.abilities.requests;
  outputReference = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  snapshotLifecycle = requests."zfstools:zfs-auto-snapshot-hourly-lifecycle".parameters;
  prepareLifecycle = requests."zfstools:prepare-lifecycle".parameters;
  schedule = requests."zfstools:hourly-schedule".parameters;
  activation = requests."zfstools:zfs-auto-snapshot-hourly-activation".parameters;
  portableOptionTree = options:
    builtins.all
    (name: let
      option = options.${name};
    in
      if option ? type
      then option.type ? _abilitySchema
      else portableOptionTree option)
    (builtins.attrNames options);
in
  assert disabled.config.aos.abilities.requests == {};
  assert disabled.config.aos.abilities.requirementTemplates != {};
  assert enabled.config.aos.abilities.instances ? "zfstools:zfs-auto-snapshot";
  assert (builtins.head snapshotLifecycle.start).executable
  == {
    artifact = lib.abilities.packageOutput {package = "zfstools";};
    entry_point = "bin/zfs-auto-snapshot";
    arguments = ["--utc" "hourly" "24"];
  };
  assert prepareLifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "zfs";};
        entry_point = "sbin/zfs";
        arguments = ["set" "com.sun:auto-snapshot=true" "tank/data"];
      };
      ignore_failure = false;
    }
  ];
  assert schedule
  == {
    name = "zfs-auto-snapshot-hourly";
    enabled = true;
    schedule = {
      kind = "calendar";
      expression = "hourly";
    };
    persistent = true;
    accuracy_millis = 60000;
    randomized_delay_millis = 300000;
  };
  assert activation.bindings
  == [
    {
      name = "schedule";
      resource = outputReference "zfstools:hourly-schedule" "activation-resource";
      relationship = "resource-triggers-service";
    }
  ];
  assert requests."zfstools:zfs-auto-snapshot-hourly-dependencies".parameters.requires
  == [(outputReference "zfstools:prepare-lifecycle" "service-resource")];
  assert requests."zfstools:zfs-auto-snapshot-hourly-scheduling".parameters
  == {
    service = "zfs-auto-snapshot-hourly";
    enabled = false;
    nice = 10;
    io_class = "idle";
    io_priority = 7;
  };
  assert portableOptionTree enabled.options.aos.services.zfsAutoSnapshot;
  assert !(enabled.config ? systemd); true
