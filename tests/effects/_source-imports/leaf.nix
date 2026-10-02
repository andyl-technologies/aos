##! Shared leaf includes a read-only value that cannot be JSON encoded.
{lib, ...}: {
  options.platform = lib.mkOption {
    type = lib.types.functionTo lib.types.str;
    readOnly = true;
  };
  config = {
    importVisits = ["leaf"];
    platform = value: value;
  };
}
