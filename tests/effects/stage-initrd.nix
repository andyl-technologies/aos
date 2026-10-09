##! Retained early-boot policy with its own isolated declaration.
{lib, ...}: {
  options.marker = lib.mkOption {type = lib.types.str;};
  config.marker = "initrd";
}
