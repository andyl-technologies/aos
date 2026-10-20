##! System-owned kernel policy derived from the final merged configuration.
{
  config,
  lib,
  ...
}: let
  inherit (config.aos.kernel) bbr;
  moduleNames = lib.unique (lib.optional bbr "tcp_bbr" ++ config.aos.kernel.modules);
  moduleEffect = config.aos.abilities.kernelModules.operations.ensure.effects.kernel-policy;
in {
  config = {
    aos.kernel.sysctl = lib.mkIf bbr {
      "net.core.default_qdisc" = "fq";
      "net.ipv4.tcp_congestion_control" = "bbr";
    };
    aos.kernel.tunablePrerequisites = lib.optional (moduleNames != []) moduleEffect.outputs.loaded;
    aos.abilities.kernelModules.operations.ensure.effects.kernel-policy = lib.mkIf (moduleNames != []) {
      input = {
        modules = moduleNames;
        required = false;
      };
    };
  };
}
