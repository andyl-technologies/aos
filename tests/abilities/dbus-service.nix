##! Checks that D-Bus service settings and ability requests share one fixed point.
{lib}: let
  evaluate = openFileLimit:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../modules/abilities/default.nix
        {
          aos.abilities.environment = {
            authority = "test";
            key = "dbus-service";
            stage = "host";
          };
          aos.services.dbus.openFileLimit = openFileLimit;
        }
      ];
      packageModules = [
        {
          name = "dbus";
          version = "1";
          module = ../../pkgs/system/_dbus/module.nix;
        }
      ];
    };

  defaultRequests = (evaluate null).config.aos.abilities.requests;
  limitedRequests = (evaluate 1024).config.aos.abilities.requests;
in
  assert !(defaultRequests ? "dbus:dbus-resources");
  assert limitedRequests."dbus:dbus-resources".parameters
  == {
    service = "dbus";
    enabled = true;
    open_files = {
      kind = "maximum";
      value = 1024;
    };
    processes.kind = "unbounded";
    tasks.kind = "unbounded";
  };
  assert defaultRequests ? "dbus:dbus-lifecycle"; true
