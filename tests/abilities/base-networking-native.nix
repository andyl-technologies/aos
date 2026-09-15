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
  networkd = requests."system:networkd".parameters;
  resolved = requests."system:resolved".parameters;
  network = requests."system:host-network".parameters;
in
  assert builtins.attrNames requests
  == [
    "system:host-network"
    "system:network-tunables"
    "system:networkd"
    "system:resolved"
  ];
  assert requests."system:network-tunables".parameters.values == {"kernel.hostname" = "aos";};
  assert networkd.source
  == {
    artifact = lib.abilities.packageOutput {package = "systemd";};
    unit_file = "lib/systemd/system/systemd-networkd.service";
    unit_name = "systemd-networkd.service";
  };
  assert resolved.source
  == {
    artifact = lib.abilities.packageOutput {package = "systemd";};
    unit_file = "lib/systemd/system/systemd-resolved.service";
    unit_name = "systemd-resolved.service";
  };
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
  assert withStaticFacts.config.aos.abilities.requests."system:host-network".parameters.links
  == [
    {
      kind = "ethernet";
      name = "provisioning-bootstrap";
      selector = {
        kind = "mac";
        value = "02:00:00:00:00:01";
      };
      addressing = {
        dhcp = false;
        addresses = ["192.0.2.10/24"];
        gateway = "192.0.2.1";
        dns = ["192.0.2.53"];
      };
    }
  ];
  assert !(withStaticFacts.config.aos.abilities.requests."system:host-network".parameters ? bootstrap);
  assert config.systemd.services == {};
  assert !(config.environment.etc ? "systemd/network/80-dhcp.network");
  assert !(config.environment.etc ? "systemd/resolved.conf");
  assert !(config.environment.etc ? "sysctl.d/50-aos-network-tuning.conf"); true
