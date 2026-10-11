##! Checks shared initial commands and unmanaged nginx package materialization.
let
  repo = ../..;
  lib = import (repo + /lib) {system = "x86_64-linux";};
  artifact = name: {
    inherit name;
    version = "1";
    path = "/nix/store/00000000000000000000000000000000-${name}";
    outputs.out = "/nix/store/00000000000000000000000000000000-${name}";
    mainProgram = name;
  };
  record = name: original: let
    source = builtins.path {
      path = original;
      name = "${name}-module";
    };
  in {
    inherit name;
    version = "1";
    configRoot = toString source;
    module = "${source}/module.nix";
    artifacts = {
      package = artifact name;
      dependencies = {};
    };
  };
  modules = [
    (record "service-management" (repo + /pkgs/system/_service-management))
    (record "init-system" (repo + /pkgs/system/_init-system))
    (record "aos-init-provider" (repo + /pkgs/system/_aos-init-provider))
    (record "aos-configuration-provider" (repo + /pkgs/system/_aos-configuration-provider))
    (record "aos-filesystem-provider" (repo + /pkgs/filesystem/_aos-filesystem-provider))
    (record "nginx" (repo + /pkgs/networking/_nginx))
  ];
  evaluate = operators:
    lib.evalPackageModules {
      scope = ["test" "init-nginx"];
      packageModules = modules;
      operatorModules = operators;
    };
  base = {
    aos.abilities.initSystem.operations.install.effects.default.input = {
      executable = lib.mkDefault "/nix/store/00000000000000000000000000000000-bash/bin/bash";
      arguments = lib.mkDefault ["-l"];
    };
    aos.services.nginx.virtualHosts.default.listen = [8080];
  };
  unmanaged = evaluate [base];
  managed = evaluate [
    base
    {
      aos.abilities.serviceManagement.operations.realize.handler.program = (import (repo + /lib/packages/artifacts.nix) {}).value (artifact "manager");
      aos.abilities.serviceManagement.operations.resourceGroup.handler.program = (import (repo + /lib/packages/artifacts.nix) {}).value (artifact "groups");
    }
  ];
  duplicate = evaluate [base {aos.abilities.initSystem.operations.install.effects.second.input = base.aos.abilities.initSystem.operations.install.effects.default.input;}];
  replacedInit = evaluate [
    base
    {
      aos.abilities.initSystem.operations.install.effects.default.input = {
        executable = "/nix/store/00000000000000000000000000000000-systemd/lib/systemd/systemd";
        arguments = [];
      };
    }
  ];
  systemdConfiguration = evaluate [
    base
    (import (repo + /pkgs/system/_systemd-abilities/core.nix) {
      inherit lib;
      package = {
        outPath = (artifact "systemd").path;
        handlers.outPath = (artifact "systemd-handlers").path;
      };
    })
  ];
  explicitUnsupported = evaluate [base {aos.services.nginx.enable = true;}];
  containerStartup = evaluate [
    (import (repo + /pkgs/system/_systemd-abilities/container-startup.nix))
    base
    {
      aos.initSystem = {
        container = true;
        containerStartupExecutable = "/nix/store/00000000000000000000000000000000-runtime/bin/aos-package-runtime";
      };
    }
  ];
  allAssertions = result: builtins.all (assertion: assertion.assertion) result.assertions;
  nodes = builtins.attrValues unmanaged.deployment.graph.nodes;
in {
  unmanaged = assert !unmanaged.config.aos.services.nginx.enable; assert allAssertions unmanaged; true;
  usableConfiguration = assert unmanaged.config.aos.abilities.configuration.operations.file.effects ? nginx; true;
  managedDefault = assert managed.config.aos.services.nginx.enable; assert allAssertions managed; true;
  explicitUnsupportedRejected = assert !allAssertions explicitUnsupported; true;
  singletonRejected = assert !allAssertions duplicate; true;
  selectedInitReplacesFallback = assert allAssertions replacedInit;
  assert builtins.attrNames replacedInit.config.aos.abilities.initSystem.operations.install.effects == ["default"];
  assert replacedInit.config.aos.abilities.initSystem.operations.install.effects.default.input.arguments == []; true;
  initComposed = assert builtins.any (node: builtins.elem "initSystem" node.identity && node.handler.kind == "composition" && node.phase == "installation") nodes; true;
  preparedCommand = assert builtins.any (node: node.input.path or null == "/etc/aos/init.json" && node.input.value.arguments or null == ["-l"]) nodes; true;
  selectedCredentialProviderIsRetained = let
    locator = systemdConfiguration.config.aos.abilities.configuration.operations.file.effects.systemd-credential-encrypt-provider.input;
  in
    assert locator.path == "/etc/aos/providers/credential-encrypt";
    assert locator.content == "/nix/store/00000000000000000000000000000000-systemd-handlers/bin/aos-systemd-credential-encrypt\n";
    assert locator.mode == "0444";
    assert systemdConfiguration.config.aos.abilities.initSystem.operations.install.effects.default.input.arguments == []; true;
  bootstrapPreparedBeforeManager = let
    startupNodes = builtins.filter (node: lib.hasPrefix "systemd-container-startup" (lib.last node.identity)) (builtins.attrValues containerStartup.deployment.graph.nodes);
  in
    assert builtins.length startupNodes == 2;
    assert builtins.all (node: node.phase == "installation" && builtins.elem "configuration" node.identity) startupNodes;
    assert lib.hasInfix "container-startup" containerStartup.config.aos.abilities.configuration.operations.file.effects.systemd-container-startup.input.content;
    assert containerStartup.config.aos.abilities.serviceManagement.operations.realize.effects == {}; true;
}
