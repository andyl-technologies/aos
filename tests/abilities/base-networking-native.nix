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
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  networkd = requests."system:networkd".parameters;
  resolved = requests."system:resolved".parameters;
in
  assert builtins.attrNames requests
  == [
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
  assert config.systemd.services == {};
  assert !(config.environment.etc ? "sysctl.d/50-aos-network-tuning.conf"); true
