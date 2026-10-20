##! Shared paths for the package-owned Ability Crucible service and endpoint.
{socketName}: rec {
  runtimePath = "/run/aos/ability-crucible";
  socketPath = "${runtimePath}/${socketName}";
}
