##! Checks that BIND service settings project into one typed ability graph.
{lib}: let
  evaluate = {
    enable,
    port,
  }:
    lib.evalModules {
      specialArgs = {inherit lib;};
      modules = [
        ../../modules/abilities/default.nix
        {
          aos.abilities.environment = {
            authority = "test";
            key = "bind-service";
            stage = "host";
          };
          aos.services.bind = {inherit enable port;};
        }
      ];
      packageModules = [
        {
          name = "bind";
          module = ../../pkgs/networking/_bind/module.nix;
        }
      ];
    };

  enabled =
    (evaluate {
      enable = true;
      port = 1053;
    }).config.aos.abilities;
  disabled =
    (evaluate {
      enable = false;
      port = 53;
    }).config.aos.abilities;
  combined = lib.evalModules {
    specialArgs = {inherit lib;};
    modules = [
      ../../modules/abilities/default.nix
      {
        aos.abilities.environment = {
          authority = "test";
          key = "multiple-services";
          stage = "host";
        };
        aos.services.bind.enable = true;
        aos.services.tailscale.enable = true;
      }
    ];
    packageModules = [
      {
        name = "bind";
        module = ../../pkgs/networking/_bind/module.nix;
      }
      {
        name = "tailscale";
        module = ../../pkgs/networking/_tailscale/module.nix;
      }
    ];
  };
in
  assert enabled.requests ? "bind:named-lifecycle";
  assert enabled.requests ? "bind:listener-tcp-1053";
  assert enabled.requests ? "bind:listener-udp-1053";
  assert enabled.requests ? "bind:named-hardening";
  assert enabled.requests."bind:named-lifecycle".parameters.service == "named";
  assert enabled.requests."bind:named-lifecycle".authority
  == {
    kind = "package";
    package = "bind";
  };
  assert disabled.requests == {};
  assert disabled.requirementTemplates ? "bind:named-service-lifecycle";
  assert combined.config.aos.abilities.instances ? "bind:service";
  assert combined.config.aos.abilities.instances ? "tailscale:service"; true
