{lib, ...}: {
  options.aos.moduleLayoutProbe = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = "Retained private option in the native module layout fixture.";
  };
}
