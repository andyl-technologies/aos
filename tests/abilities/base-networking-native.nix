##! Checks base networking through native systemd and tunable providers.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "base-networking";
    module = ../../modules/base/networking.nix;
    packages = [pkgs.systemd pkgs.aos-kernel-tunable-provider];
    extraModules = [../../modules/base/host-facts.nix];
  };
  config = evaluated.config;
  withStaticFacts = evaluate {
    name = "base-networking-static-facts";
    module = ../../modules/base/networking.nix;
    packages = [pkgs.systemd pkgs.aos-kernel-tunable-provider];
    extraModules = [
      ../../modules/base/host-facts.nix
      {
        host.facts.static_network = {
          mac = "02:00:00:00:00:01";
          addresses = ["192.0.2.10/24"];
          gateway = "192.0.2.1";
          dns = ["192.0.2.53"];
        };
      }
    ];
  };
  requests = config.aos.abilities.requests;
  network = requests."aos:host-network".parameters;
in
  assert requests ? "aos:host-network";
  assert requests ? "aos:network-tunables";
  assert requests."aos:network-tunables".parameters.values == {"kernel.hostname" = "aos";};
  assert network.authority == "image";
  assert network.links
  == [
    {
      kind = "ethernet";
      name = "default-dhcp";
      selector.kind = "ethernet";
      addressing = {
        dhcp = true;
        addresses = [];
        dns = [];
      };
    }
  ];
  assert withStaticFacts.config.aos.abilities.requests."aos:host-network".parameters == network;
  assert !(withStaticFacts.config.aos.abilities.requests."aos:host-network".parameters ? bootstrap);
  assert (config.systemd.services or {}) == {};
  assert !(config.environment.etc ? "systemd/network/80-dhcp.network");
  assert !(config.environment.etc ? "systemd/resolved.conf");
  assert !(config.environment.etc ? "sysctl.d/50-aos-network-tuning.conf"); true
