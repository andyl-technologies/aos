##! Keeps interactive debug gettys out of the fleet's initrd serial transport.
{
  lib,
  options,
  ...
}: {
  # Some initrd closures do not select util-linux's optional getty contract.
  config = lib.mkIf ((options.aos.getty.autologin.enable or null) != null) {
    aos.getty.autologin.enable = lib.mkForce false;
  };
}
