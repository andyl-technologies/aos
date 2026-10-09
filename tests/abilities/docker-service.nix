##! Checks native Docker configuration, persistent storage, and command artifacts.
{
  lib,
  pkgs,
}: let
  evaluate = settings:
    lib.evalPackageModules {
      scope = ["test" "docker"];
      packages = [pkgs.docker-engine];
      operatorModules = [{aos.services.docker = settings;}];
    };
  disabled = evaluate {enable = false;};
  enabled = evaluate {
    enable = true;
    dataRoot = "/srv/docker";
    storageDriver = "btrfs";
    liveRestore = false;
    extraOptions = ["--debug"];
  };
  config = enabled.config;
  command = builtins.head config.aos.services.docker.lifecycle.start;
  directories = config.aos.abilities.filesystem.operations.directory.effects;
  documentation = builtins.filter (option: option.owner == "docker-engine") enabled.documentation.options;
in
  assert pkgs.docker-engine ? module;
  assert disabled.config.aos.abilities.serviceManagement.operations.realize.effects == {};
  assert disabled.config.aos.abilities.filesystem.operations.directory.effects == {};
  assert directories.docker-data.input.path == "/srv/docker";
  assert directories.docker-data.lifetime == "persistent";
  assert directories.docker-runtime.input.path == "/run/docker";
  assert builtins.length config.aos.services.docker.storage.mounts == 2;
  assert command.executable.path == "${pkgs.docker-engine}/bin/dockerd";
  assert builtins.elem "--storage-driver=btrfs" command.executable.arguments;
  assert builtins.elem "--debug" command.executable.arguments;
  assert !(builtins.elem "--live-restore" command.executable.arguments);
  assert builtins.all (option: option.description != "") documentation;
  assert (import ../../pkgs/containers/_docker-engine/runtime-tests.nix {cfg = config.aos.services.docker;}).description == "Docker service checks"; true
