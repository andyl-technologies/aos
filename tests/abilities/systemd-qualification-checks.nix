##! Systemd qualification derives exact manager subjects from realizations.
{lib}: let
  qualification = import ../../pkgs/system/_systemd-abilities/provider/_systemd-qualification-checks.nix {inherit lib;};
  unit = unit_name: {
    kind = "unit";
    inherit unit_name;
  };
  resource = {
    resource = {
      provider = "systemd:manager";
      key = "example";
    };
    revision = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    value = {
      service = "example";
      lifecycle = {
        execution_model = "foreground";
        remain_after_exit = false;
      };
    };
    realization = {
      enabled = true;
      systemd_unit = unit "example.service";
      links = [
        {
          parent = unit "sockets.target";
          child = unit "example.socket";
          relationship = "wants";
        }
        {
          parent = unit "multi-user.target";
          child = unit "example.service";
          relationship = "wants";
        }
      ];
    };
  };
  foregroundIdentities = qualification.unitIdentitiesFor resource;
  completedOneshotIdentities = qualification.unitIdentitiesFor (
    resource
    // {
      value =
        resource.value
        // {
          lifecycle = {
            execution_model = "oneshot";
            remain_after_exit = false;
          };
        };
    }
  );
  retainedOneshotIdentities = qualification.unitIdentitiesFor (
    resource
    // {
      value =
        resource.value
        // {
          lifecycle = {
            execution_model = "oneshot";
            remain_after_exit = true;
          };
        };
    }
  );
  check = qualification.serviceCheck resource;
in
  assert foregroundIdentities
  == [
    (unit "example.service")
    (unit "example.socket")
  ];
  assert completedOneshotIdentities == [(unit "example.socket")];
  assert retainedOneshotIdentities == foregroundIdentities;
  assert lib.hasInfix "example.service" check.script;
  assert lib.hasInfix "example.socket" check.script; true
