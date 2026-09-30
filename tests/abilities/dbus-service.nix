##! Checks native D-Bus service configuration and shared registration ownership.
{lib}: let
  payload = import ../effects/_fixture-payload.nix;
  artifactLib = import ../../lib/packages/artifacts.nix {};
  artifact = name: {
    inherit name;
    version = "1";
    path = toString (payload name);
    outputs.out = toString (payload name);
    mainProgram = name;
  };
  record = name: source: let
    retained = builtins.path {
      path = source;
      name = "${name}-module";
    };
  in {
    inherit name;
    version = "1";
    configRoot = toString retained;
    module = "${retained}/module.nix";
    artifacts = {
      package = artifact name;
      dependencies = {};
    };
  };
  evaluate = enable: openFileLimit:
    lib.evalPackageModules {
      scope = ["test" "native-dbus"];
      packageModules = [
        (record "service-management" ../../pkgs/system/_service-management)
        (record "dbus" ../../pkgs/system/_dbus)
      ];
      operatorModules = [
        {
          aos.services.dbus = {inherit enable;};
          aos.dbus.openFileLimit = openFileLimit;
          aos.dbus.activationDirectories = ["${payload "polkit"}/share/dbus-1/system-services"];
          aos.abilities = {
            serviceManagement.operations.realize.handler.program = artifactLib.value (artifact "service-handler");
            configuration.operations.file.handler.program = artifactLib.value (artifact "file-handler");
            identity.operations.group.handler.program = artifactLib.value (artifact "identity-handler");
            identity.operations.principal.handler.program = artifactLib.value (artifact "identity-handler");
          };
        }
      ];
    };
  default = evaluate true null;
  limited = evaluate true 1024;
  disabled = evaluate false null;
  service = default.config.aos.services.dbus;
  realization = default.config.aos.abilities.serviceManagement.operations.realize.effects.dbus;
  file = default.config.aos.abilities.configuration.operations.file.effects.dbus;
in
  assert service.lifecycle.configuration_change_action == "reload";
  assert service.manager_identity
  == {
    name = "dbus";
    aliases = ["messagebus"];
  };
  assert (builtins.head service.socket_activation.sockets).mode == "0666";
  assert service.resources.open_files == null;
  assert limited.config.aos.services.dbus.resources.open_files
  == {
    kind = "maximum";
    value = 1024;
  };
  assert limited.config.aos.services.dbus.resources.processes.kind == "unbounded";
  assert realization.input.instance == "dbus";
  assert builtins.any (fragment: lib.hasInfix "${payload "polkit"}/share/dbus-1/system-services" fragment) file.input.fragments;
  assert disabled.deployment.graph.order == [];
  assert builtins.length default.deployment.graph.order == 4; true
