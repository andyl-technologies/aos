##! Retains the selected debug security preset for native host re-evaluation.
{lib, ...}: {
  aos.security.level = lib.mkDefault "debug";
}
