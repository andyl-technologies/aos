##! modules/services/docker.nix — Selects Docker packages for host integration
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.services.docker or {};
  storageDriver = cfg.storageDriver or "overlay2";
in {
  # docker-engine contributes the daemon contract; docker supplies the user
  # CLI and plugins exercised by the host qualification checks.
  environment.systemPackages = [pkgs.docker-engine pkgs.docker];

  system.checks.docker = lib.mkIf (cfg.enable or false) {
    description = "Docker service checks";
    checks = [
      {
        name = "docker-active";
        description = "Docker reaches its ready state";
        script = ''
          vm.wait_until_succeeds(
              "systemctl is-active --quiet docker.service", timeout=60
          )
        '';
      }
      {
        name = "docker-api";
        description = "The Docker CLI reaches the local daemon and plugins";
        script = ''
          vm.succeed("docker version --format '{{.Server.Version}}'")
          vm.succeed("docker info --format '{{.Driver}}' | grep -Fx '${storageDriver}'")
          vm.succeed("docker buildx version")
          vm.succeed("docker compose version")
        '';
      }
    ];
  };
}
