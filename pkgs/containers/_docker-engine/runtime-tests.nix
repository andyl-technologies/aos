##! Focused VM checks for the package service.
{cfg}: {
  description = "Docker service checks";
  checks = [
    {
      name = "docker-api";
      description = "The Docker CLI reaches the local daemon and plugins";
      script = ''
        vm.wait_until_succeeds(
            "docker version --format '{{.Server.Version}}'", timeout=60
        )
        vm.succeed("docker info --format '{{.Driver}}' | grep -Fx '${cfg.storageDriver}'")
        vm.succeed("docker buildx version")
        vm.succeed("docker compose version")
      '';
    }
  ];
}
