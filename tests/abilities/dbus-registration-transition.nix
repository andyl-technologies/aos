##! A D-Bus registration transition ignores other resources of its provider.
{lib}: let
  provider = "dbus:manager";
  registration = {
    inherit provider;
    key = "system-bus";
  };
  configuration = {
    inherit provider;
    key = "system-bus-configuration";
  };
  unrelated = {
    inherit provider;
    key = "dbus-service";
  };
  configurationInterface = {
    name = "aos.service.managed-configuration";
    abi = 1;
    descriptor = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  };
  transition = import ../../pkgs/system/_dbus/registration-transition.nix {
    inherit configurationInterface;
    registrationResourceKind = "aos.dbus.system-registration";
    inherit (lib.abilities) transitionFragment;
  };
  context = {
    inherit provider;
    operation_scope = ["registration"];
    before = null;
    after.resources = [
      {
        resource = registration;
        kind = "aos.dbus.system-registration";
        lifetime = "instance";
      }
      {
        resource = configuration;
        kind = configurationInterface.name;
        lifetime = "instance";
        value = {text = "[D-BUS Service]";};
      }
      {
        resource = unrelated;
        kind = "aos.service.instance";
        lifetime = "instance";
      }
    ];
    changes = [
      {
        resource = registration;
        kind = "create";
      }
      {
        resource = unrelated;
        kind = "create";
      }
    ];
    authorized_bindings = [
      {
        authority.role = "desired";
        binding = {
          id = "configuration-binding";
          interface = configurationInterface;
          caller_grant = {
            methods = ["materialize" "observe"];
            resources = [
              {
                resource = configuration;
                access = "exclusive-write";
                operations = ["materialize"];
              }
            ];
          };
        };
      }
    ];
    controllers = [
      {
        resource = registration;
        controller = {
          inherit provider;
          group = "system-registration";
        };
      }
    ];
  };
  operations = (transition context).operations;
in
  assert builtins.length operations == 1;
  assert (builtins.head operations).target.resource == configuration; true
