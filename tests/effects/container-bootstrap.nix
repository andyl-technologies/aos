##! Checks native broker composition and package-owned installation preparation.
{pkgs}: let
  lib = import ../../lib {system = pkgs.bash.system;};
  evaluate = limit:
    lib.evalPackageModules {
      scope = ["profile" "/var/lib/profiles/per-user/root"];
      packages = [pkgs.systemd pkgs.aos-init-provider pkgs.nginx];
      operatorModules = [
        ({config, ...}: {
          aos.abilities.identity.operations.membership.effects.bootstrap-phase-test.input = {
            group = config.aos.abilities.identity.operations.group.effects.dbus.outputs.name;
            members = [config.aos.abilities.identity.operations.principal.effects.dbus.outputs.name];
          };
          aos.initSystem = {
            container = true;
            containerStartupExecutable = "/nix/store/00000000000000000000000000000000-runtime/bin/aos-package-runtime";
          };
          aos.dbus.openFileLimit = limit;
          aos.services.nginx.virtualHosts.default.listen = [8080];
        })
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
  identity = evaluated.config.aos.abilities.identity.operations;
  key = effect: builtins.hashString "sha256" (builtins.toJSON effect.contract.identity);
  dbusGroup = key identity.group.effects.dbus;
  dbusPrincipal = key identity.principal.effects.dbus;
  membership = key identity.membership.effects.bootstrap-phase-test;
  dbusService = key evaluated.config.aos.abilities.serviceManagement.operations.realize.effects.dbus;
  configured = evaluate 8192;
in {
  brokerAccountsAreInstalledBeforeStartup =
    graph.nodes.${dbusGroup}.phase
    == "installation"
    && graph.nodes.${dbusPrincipal}.phase == "installation"
    && graph.nodes.${dbusService}.phase == "startup";
  brokerAccountDependenciesAreRetained =
    builtins.elem dbusGroup graph.nodes.${dbusPrincipal}.dependencies
    && builtins.elem dbusPrincipal graph.nodes.${dbusService}.dependencies;
  membershipsAreInstalledAfterTheirAccounts =
    graph.nodes.${membership}.phase
    == "installation"
    && builtins.elem dbusGroup graph.nodes.${membership}.dependencies
    && builtins.elem dbusPrincipal graph.nodes.${membership}.dependencies;
  nativeIdentityReceiptsRemainOwned =
    graph.nodes.${dbusGroup}.handler.executable
    == "${pkgs.systemd.handlers}/bin/aos-systemd-native-resources"
    && graph.nodes.${dbusPrincipal}.handler.executable == "${pkgs.systemd.handlers}/bin/aos-systemd-native-resources";
  containerStartupRetainsRuntimeAndNixPolicy = let
    unit = evaluated.config.aos.abilities.configuration.operations.file.effects.systemd-container-startup.input.content;
  in
    lib.hasInfix "\nEnvironment=AOS_RUNTIME=container\n" unit
    && lib.hasInfix "\nPassEnvironment=NIX_CONFIG\n" unit;
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
