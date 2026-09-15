##! Checks base kernel policy through the native kmod and tunable providers.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "base-kernel";
    module = ../../modules/base/kernel.nix;
    packages = [pkgs.kmod pkgs.aos-kernel-tunable-provider];
    extraModules = [
      {aos.kernel.sysctl."vm.vfs_cache_pressure" = "50";}
    ];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
in
  assert builtins.attrNames requests
  == [
    "system:kernel-modules"
    "system:kernel-tunables"
  ];
  assert requests."system:kernel-modules".parameters
  == {
    modules = ["tcp_bbr"];
    required = false;
  };
  assert requests."system:kernel-tunables".parameters.dependencies
  == [
    {
      _type = "aos-request-output-reference";
      request = "system:kernel-modules";
      output = "readiness-resource";
    }
  ];
  assert requests."system:kernel-tunables".parameters.values."net.core.default_qdisc" == "fq";
  assert requests."system:kernel-tunables".parameters.values."net.ipv4.tcp_congestion_control" == "bbr";
  assert requests."system:kernel-tunables".parameters.values."vm.swappiness" == "10";
  assert requests."system:kernel-tunables".parameters.values."vm.vfs_cache_pressure" == "50";
  assert requests."system:kernel-tunables".parameters.values."net.core.somaxconn" == "32768";
  assert config.systemd.services == {};
  assert !(config.environment.etc ? "modules-load.d/10-aos-kernel.conf");
  assert !(config.environment.etc ? "sysctl.d/10-aos-kernel.conf");
  assert !(config.environment.etc ? "sysctl.d/60-aos-bbr.conf"); true
