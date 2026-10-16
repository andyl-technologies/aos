##! Terrane host feature options and isolated process roles (PKG-8).
{lib, ...}: {
  options.aos.terrane.enable = lib.mkEnableOption "the Terrane host tier";
}
