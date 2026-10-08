##! Checks native broker composition and package-owned installation preparation.
{pkgs}: let
  lib = import ../../lib {system = pkgs.bash.system;};
  evaluate = limit:
    lib.evalPackageModules {
      scope = ["profile" "/var/lib/profiles/per-user/root"];
      packages = [pkgs.systemd pkgs.aos-init-provider pkgs.nginx];
      operatorModules = [
        {
          aos.initSystem = {
            container = true;
            containerStartupExecutable = "/nix/store/00000000000000000000000000000000-runtime/bin/aos-package-runtime";
          };
          aos.dbus.openFileLimit = limit;
          aos.services.nginx.virtualHosts.default.listen = [8080];
        }
      ];
    };
  evaluated = evaluate null;
  graph = evaluated.deployment.graph;
  prepared = evaluated.config.aos.abilities.systemdBootstrap.operations.prepare.effects.container;
  preparedKey = builtins.hashString "sha256" (builtins.toJSON prepared.contract.identity);
  live = builtins.filter (node:
    builtins.elemAt node.identity (builtins.length node.identity - 3)
    == "serviceManagement"
    && builtins.elem (builtins.elemAt node.identity (builtins.length node.identity - 2)) ["realize" "resourceGroup"])
  (builtins.attrValues graph.nodes);
  configured = evaluate 8192;
in {
  brokerSelectedWithProvider = builtins.hasAttr "dbus" prepared.input.services;
  installationOwnsPreparation = graph.nodes.${preparedKey}.phase == "installation";
  liveHandlersDependOnPreparation = builtins.length live >= 3 && builtins.all (node: builtins.elem preparedKey node.dependencies) live;
  projectionDoesNotDependOnItself = prepared.input.services.dbus.bootstrapResource == null && !(builtins.elem preparedKey graph.nodes.${preparedKey}.dependencies);
  mergedBrokerPolicyIsReused = configured.config.aos.abilities.systemdBootstrap.operations.prepare.effects.container.input.services.dbus.resources.open_files.value == 8192;
  brokerStartupPrecedesActivation = let
    unit = evaluated.config.aos.abilities.configuration.operations.file.effects.systemd-container-startup.input.content;
  in
    lib.hasInfix "Requires=dbus.service" unit && lib.hasInfix "After=basic.target dbus.service" unit;
}
