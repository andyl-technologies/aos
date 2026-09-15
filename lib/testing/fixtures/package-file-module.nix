##! Exact-file package module confinement fixture.
{lib, ...}: {
  options.fileBoundary.value = lib.mkOption {type = lib.types.str;};
  config.fileBoundary.value = "confined";
}
