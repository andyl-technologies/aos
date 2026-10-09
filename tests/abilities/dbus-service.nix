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
  systemdRegistration = {options, ...}:
    import ../../pkgs/system/_systemd-abilities/dbus-registrations.nix {
      inherit lib options;
      package = artifactLib.value (artifact "systemd");
    };
  standalone = lib.evalModules {
    inherit lib;
    modules = [../../lib/effects/module.nix systemdRegistration];
  };
  evaluate = enable: openFileLimit:
    lib.evalPackageModules {
      scope = ["test" "native-dbus"];
      packageModules = [
        (record "service-management" ../../pkgs/system/_service-management)
        (record "dbus" ../../pkgs/system/_dbus)
      ];
      operatorModules = [
        systemdRegistration
        {
          aos.services.dbus = {inherit enable;};
          aos.dbus.openFileLimit = openFileLimit;
          aos.dbus.policyDirectories = ["${payload "polkit"}/share/dbus-1/system.d"];
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
  identities = default.config.aos.abilities.identity.operations;
  effectId = ability: operation:
    builtins.head (builtins.attrNames (lib.filterAttrs (_: node:
      builtins.elem ability node.identity && builtins.elem operation node.identity)
    default.deployment.graph.nodes));
  serviceNode = default.deployment.graph.nodes.${effectId "serviceManagement" "realize"};
  seed = import ../../pkgs/system/_systemd-abilities/platform/_identity-bootstrap.nix {
    inherit lib identities;
    principalReferences = service.bootstrapPrincipals;
    accounts = {
      users = {};
      groups = {};
    };
    shells = {
      nologin = "${payload "util-linux"}/sbin/nologin";
      login = "${payload "bash"}/bin/bash";
    };
  };
in
  assert !(standalone.config.aos or {} ? dbus);
  assert standalone.config.aos.activation.graph.order == [];
  assert default.config.aos.dbus.policyDirectories == ["${payload "systemd"}/share/dbus-1/system.d" "${payload "polkit"}/share/dbus-1/system.d"];
  assert default.config.aos.dbus.activationDirectories == ["${payload "systemd"}/share/dbus-1/system-services" "${payload "polkit"}/share/dbus-1/system-services"];
  assert service.bootstrap;
  assert service.activationOwner == "ability";
  assert service.activationAfter == [];
  assert service.bootstrapPrincipals == [identities.principal.effects.dbus.outputs.name];
  assert service.activationInputs == [file.outputs.resource];
  assert builtins.elem (effectId "configuration" "file") serviceNode.dependencies;
  assert builtins.elem (effectId "identity" "principal") serviceNode.dependencies;
  assert builtins.length serviceNode.dependencies == 2;
  assert identities.group.effects.dbus.input.requested_id == 81;
  assert identities.principal.effects.dbus.input.requested_id == 81;
  assert seed.passwd == "messagebus:x:81:81:D-Bus Message Bus:/var/run/dbus:${payload "util-linux"}/sbin/nologin\n";
  assert seed.group == "messagebus:x:81:\n";
  assert (builtins.head service.lifecycle.start).executable.arguments
  == [
    "--address=systemd:"
    "--nofork"
    "--nopidfile"
    "--systemd-activation"
    "--config-file"
    file.input.path
  ];
  assert (builtins.head service.configuration.views).source == file.input.path;
  assert builtins.all builtins.isString service.dependencies.prerequisites;
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
  assert file.input.fragments == [];
  assert file.input.content
  == lib.concatStringsSep "" [
    "<busconfig>\n<include>${payload "dbus"}/share/dbus-1/aos-system-base.conf</include>\n"
    "<servicedir>${payload "systemd"}/share/dbus-1/system-services</servicedir>\n"
    "<servicedir>${payload "polkit"}/share/dbus-1/system-services</servicedir>\n"
    "<includedir>${payload "systemd"}/share/dbus-1/system.d</includedir>\n"
    "<includedir>${payload "polkit"}/share/dbus-1/system.d</includedir>\n"
    "<includedir>/etc/dbus-1/system.d</includedir>\n<include ignore_missing=\"yes\">/etc/dbus-1/system-local.conf</include>\n</busconfig>\n"
  ];
  assert disabled.deployment.graph.order == [];
  assert builtins.length default.deployment.graph.order == 4; true
