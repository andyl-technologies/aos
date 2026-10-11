##! Retains development-only privileged network tools for native host replay.
{lib, ...}: {
  aos.inetutils.privilegedPing.enable = lib.mkDefault true;
}
