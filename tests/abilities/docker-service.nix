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
    };

  disabled = evaluate {enable = false;};
  enabled = evaluate {
    enable = true;
    dataRoot = "/srv/docker";
    storageDriver = "btrfs";
    liveRestore = false;
    extraOptions = ["--debug"];
  };
  requests = enabled.config.aos.abilities.requests;
  lifecycle = requests."system:docker-lifecycle".parameters;
  start = (builtins.head lifecycle.start).executable;
in
  assert disabled.config.aos.abilities.requests == {};
  assert builtins.attrNames requests
  == [
    "system:docker-data-storage"
    "system:docker-dependencies"
    "system:docker-isolation"
    "system:docker-lifecycle"
    "system:docker-linux_isolation"
    "system:docker-logging"
    "system:docker-network-readiness"
    "system:docker-readiness"
    "system:docker-reload"
    "system:docker-resources"
    "system:docker-runtime-storage"
    "system:docker-storage"
    "system:docker-supervision"
    "system:docker-termination"
  ];
  assert requests."system:docker-data-storage".parameters.requested_path == "/srv/docker";
  assert requests."system:docker-runtime-storage".parameters.requested_path == "/run/docker";
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
  assert requests."system:docker-resources".parameters.open_files.kind == "unbounded";
  assert requests."system:docker-resources".parameters.processes.kind == "unbounded";
  assert requests."system:docker-resources".parameters.tasks.kind == "unbounded";
  assert requests."system:docker-linux_isolation".parameters.capability_bounds.kind == "unrestricted";
  assert !requests."system:docker-termination".parameters.send_to_all_processes; true
