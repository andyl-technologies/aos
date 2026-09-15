##! Pure evaluation checks for the native Docker service declaration.
{
  lib,
  pkgs,
}: let
  evaluate = serviceConfig:
    lib.evalModules {
      inherit lib;
      specialArgs = {inherit pkgs;};
      modules = [
        ../../modules/abilities/default.nix
        ../../modules/services/docker.nix
        ({lib, ...}: {
          options.environment.systemPackages = lib.mkOption {
            type = lib.types.listOf lib.types.package;
            default = [];
          };
          options.system.checks = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };

          config = {
            aos.abilities.environment = {
              authority = "deployment";
              key = "docker-service-test";
              stage = "host";
            };
            aos.services.docker = serviceConfig;
          };
        })
      ];
      packageModules = [
        {
          name = "docker-engine";
          inherit (pkgs.docker-engine) version;
          module = pkgs.docker-engine.module + "/module.nix";
        }
      ];
    };

  disabled = evaluate {enable = false;};
  enabled = evaluate {
    enable = true;
    dataRoot = "/srv/docker";
    storageDriver = "btrfs";
    liveRestore = false;
    extraOptions = ["--debug"];
  };
  packageProjection = pkgs.docker-engine.abilities;
  packageContract = pkgs.docker-engine.contract.value;
  documentedOptionPaths =
    builtins.map
    (option: lib.concatStringsSep "." option.path)
    packageContract.option_declarations;
  requests = enabled.config.aos.abilities.requests;
  lifecycle = requests."docker-engine:docker-lifecycle".parameters;
  start = (builtins.head lifecycle.start).executable;
in
  assert enabled.config.environment.systemPackages == [pkgs.docker-engine pkgs.docker];
  assert builtins.attrNames packageProjection.interfaces == [];
  assert builtins.attrNames packageProjection.implementations == [];
  assert builtins.attrNames packageProjection.guarantees == [];
  assert builtins.attrNames packageProjection.requirementTemplates
  == [
    "linux-service-isolation"
    "network-readiness"
    "persistent-storage-allocation"
    "service-dependencies"
    "service-isolation"
    "service-lifecycle"
    "service-logging"
    "service-readiness"
    "service-reload"
    "service-resources"
    "service-storage"
    "service-supervision"
    "service-termination"
    "storage-allocation"
  ];
  assert builtins.map (requirement: requirement.alias) packageContract.requirements
  == builtins.attrNames packageProjection.requirementTemplates;
  assert documentedOptionPaths
  == [
    "aos.services.docker.dataRoot"
    "aos.services.docker.enable"
    "aos.services.docker.extraOptions"
    "aos.services.docker.liveRestore"
    "aos.services.docker.storageDriver"
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
  assert pkgs.docker-engine ? module;
  assert disabled.config.aos.abilities.requests == {};
  assert disabled.config.aos.abilities.instances == {};
  assert builtins.attrNames disabled.config.aos.abilities.requirementTemplates
  == builtins.map
  (name: "docker-engine:${name}")
  (builtins.attrNames packageProjection.requirementTemplates);
  assert builtins.attrNames requests
  == [
    "docker-engine:docker-data-storage"
    "docker-engine:docker-dependencies"
    "docker-engine:docker-isolation"
    "docker-engine:docker-lifecycle"
    "docker-engine:docker-linux_isolation"
    "docker-engine:docker-logging"
    "docker-engine:docker-network-readiness"
    "docker-engine:docker-readiness"
    "docker-engine:docker-reload"
    "docker-engine:docker-resources"
    "docker-engine:docker-runtime-storage"
    "docker-engine:docker-storage"
    "docker-engine:docker-supervision"
    "docker-engine:docker-termination"
  ];
  assert requests."docker-engine:docker-data-storage".parameters.requested_path == "/srv/docker";
  assert requests."docker-engine:docker-runtime-storage".parameters.requested_path == "/run/docker";
  assert requests."docker-engine:docker-storage".parameters.mounts
  == [
    {
      name = "data";
      source = {
        _type = "aos-request-output-reference";
        request = "docker-engine:docker-data-storage";
        output = "planned-path";
      };
      access = "read-write";
      ownership = "provider";
    }
    {
      name = "runtime";
      source = {
        _type = "aos-request-output-reference";
        request = "docker-engine:docker-runtime-storage";
        output = "planned-path";
      };
      access = "read-write";
      ownership = "provider";
    }
  ];
  assert start.artifact == lib.abilities.packageOutput {package = "docker-engine";};
  assert start.arguments
  == [
    "--host=unix:///run/docker.sock"
    "--data-root=/srv/docker"
    "--exec-root=/run/docker"
    "--pidfile=/run/docker/docker.pid"
    "--group=root"
    "--storage-driver=btrfs"
    "--debug"
  ];
  assert requests."docker-engine:docker-resources".parameters.open_files.kind == "unbounded";
  assert requests."docker-engine:docker-resources".parameters.processes.kind == "unbounded";
  assert requests."docker-engine:docker-resources".parameters.tasks.kind == "unbounded";
  assert requests."docker-engine:docker-linux_isolation".parameters.capability_bounds.kind == "unrestricted";
  assert !requests."docker-engine:docker-termination".parameters.send_to_all_processes; true
