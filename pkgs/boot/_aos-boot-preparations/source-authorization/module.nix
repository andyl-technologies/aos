##! Declares the retained OS proof locator shared with native source replay.
{lib, ...}: {
  options.aos.boot.sourceAuthorization = lib.mkOption {
    type = lib.types.nullOr lib.types.pathInStore;
    default = null;
    readOnly = true;
    internal = true;
    description = "Retained OS authorization proof for the initial metadata source adoption.";
  };
}
