##! Declares shared policy without choosing a Linux artifact variant.
{lib, ...}: {
  options.aos.kernel.commandLineParts = lib.mkOption {
    type = lib.types.attrsOf (lib.types.listOf lib.types.str);
    default = {};
    extensible = true;
    description = "Kernel command-line fragments contributed by native package modules.";
  };
}
