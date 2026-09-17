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
    extraPackageModules = [
      {
        name = "aos";
        version = pkgs.aos.version;
        module = pkgs.aos.module + "/kernel-policy.nix";
      }
    ];
    extraModules = [
      {aos.kernel.sysctl."vm.vfs_cache_pressure" = "50";}
    ];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
in
  assert builtins.attrNames requests
  == [
    "aos:kernel-modules"
    "aos:kernel-tunables"
  ];
  assert requests."aos:kernel-modules".parameters
  == {
    modules = ["tcp_bbr"];
    required = false;
  };
  assert requests."aos:kernel-tunables".parameters.dependencies
  == [
    {
      _type = "aos-request-output-reference";
      request = "aos:kernel-modules";
      output = "resource";
    }
  ];
  assert requests."aos:kernel-tunables".parameters.values."net.core.default_qdisc" == "fq";
  assert requests."aos:kernel-tunables".parameters.values."net.ipv4.tcp_congestion_control" == "bbr";
  assert requests."aos:kernel-tunables".parameters.values."vm.swappiness" == "10";
  assert requests."aos:kernel-tunables".parameters.values."vm.vfs_cache_pressure" == "50";
  assert requests."aos:kernel-tunables".parameters.values."net.core.somaxconn" == "32768";
  assert (config.systemd.services or {}) == {};
  assert !(config.environment.etc ? "modules-load.d/10-aos-kernel.conf");
  assert !(config.environment.etc ? "sysctl.d/10-aos-kernel.conf");
  assert !(config.environment.etc ? "sysctl.d/60-aos-bbr.conf"); true
