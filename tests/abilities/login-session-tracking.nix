##! Provider-neutral login-session tracking and systemd PAM projection checks.
{
  lib,
  pkgs,
}: let
  interface = lib.abilities.interfaces.loginSessionTracking.interface;
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  consumer = {
    config.aos.abilities = {
      instances."pam:session" = {};
      requirementTemplates."pam:login-session-tracking" = {
        interface = interface.identity.name;
        inherit (interface.identity) abi descriptor;
      };
      requests."pam:login-session-tracking" = {
        requirement = "pam:login-session-tracking";
        consumer = "pam:session";
        scope = ["login-sessions"];
        parameters.enabled = true;
      };
    };
  };
  evaluated = evaluate {
    name = "login-session-tracking";
    module = consumer;
    packages = [pkgs.systemd];
  };
  implementation = evaluated.config.aos.abilities.implementations."systemd:login-session-tracking";
  selectedProjection = lib.evalModules {
    inherit lib;
    modules = [
      {
        options = {
          aos.abilities.implementations = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };
          aos.pam.sessionTrackingRule = lib.mkOption {
            type = lib.types.nullOr lib.types.anything;
            default = null;
          };
          environment.etc = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };
        };
      }
      ../../pkgs/system/_systemd-abilities/platform/pam.nix
    ];
    specialArgs = {
      abilitySelection.bindingsForImplementation = alias:
        lib.optional (alias == interface.alias) {
          request.value.parameters.enabled = true;
        };
      packageArtifactFor = selector:
        if selector.package == "self"
        then "/systemd"
        else "/${selector.package}";
    };
  };
in
  assert evaluated.config.aos.abilities.requests."pam:login-session-tracking".parameters.enabled;
  assert implementation.interface == interface.identity;
  assert selectedProjection.config.aos.pam.sessionTrackingRule.modulePath
  == "/systemd/lib/security/pam_systemd.so";
  assert lib.hasInfix "/systemd/lib/security/pam_systemd.so"
  selectedProjection.config.environment.etc."pam.d/systemd-user".text; true
