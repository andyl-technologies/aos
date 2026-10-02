##! External kernel-module packages contributed by native package modules.
{lib, ...}: {
  options.aos.kernel.externalPackages = lib.mkOption {
    type = lib.types.attrsOf (lib.types.listOf lib.types.package);
    default = {};
    extensible = true;
    description = ''
      Package-owned source packages rebuilt against the selected kernel and
      retained in the running and recovery environments.
    '';
  };
}
