{lib, ...}: {
  options.aos.moduleLayoutProbe = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = "Native option whose single-file layout remains invalid.";
  };
}
