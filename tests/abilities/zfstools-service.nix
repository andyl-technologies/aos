##! Fixed-point checks for package-owned scheduled ZFS snapshots.
{
  lib,
  pkgs,
}: let
  packageModule = package: {
    inherit (package) version;
    name = package.pname;
    module = package.module + "/module.nix";
    outputs = {
      self = builtins.toString package;
      dependencies = {};
    };
  };
  evaluate = enabled:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        ../../modules/services/zfs-auto-snapshot.nix
        {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.anything;
              default = [];
            };
            environment.systemPackages = lib.mkOption {
              type = lib.types.listOf lib.types.package;
              default = [];
            };
          };
          aos.abilities.environment = {
            authority = "test";
            key = "zfstools";
            stage = "host";
          };
          aos.filesystems.zfs = {
            enable = true;
            poolName = "tank";
            datasets.data = {mountpoint = "/tank/data";};
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
      packageModules = builtins.map packageModule [pkgs.aos-zfs-provider pkgs.zfstools];
    };
  disabled = evaluate false;
  enabled = evaluate true;
  disabledZfstoolsRequests = lib.filterAttrs (name: _: lib.hasPrefix "zfstools:" name) disabled.config.aos.abilities.requests;
  requests = enabled.config.aos.abilities.requests;
  outputReference = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  snapshotLifecycle = requests."zfstools:zfs-auto-snapshot-hourly-lifecycle".parameters;
  prepareLifecycle = requests."zfstools:prepare-lifecycle".parameters;
  schedule = requests."zfstools:hourly-schedule".parameters;
  activation = requests."zfstools:zfs-auto-snapshot-hourly-activation".parameters;
  storageReadiness = enabled.config.aos.filesystems.zfs.readinessResources;
  datasetRequests = builtins.filter (name: lib.hasPrefix "aos-zfs-provider:dataset-" name) (builtins.attrNames requests);
  datasetRequest = builtins.head datasetRequests;
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
  assert disabledZfstoolsRequests == {};
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
  assert storageReadiness
  == [
    (outputReference "aos-zfs-provider:pool" "readiness-resource")
    (outputReference datasetRequest "readiness-resource")
  ];
  assert requests."zfstools:prepare-dependencies".parameters.requires == storageReadiness;
  assert requests."zfstools:zfs-auto-snapshot-hourly-dependencies".parameters.after == storageReadiness;
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
