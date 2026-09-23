##! Canonical typed ability configuration.
##!
##! The schema lives in `lib.abilities` so package and system evaluation use
##! the same option types. Auto-discovery imports it into every system fixed
##! point exactly once.
{lib, ...}: {
  imports = [lib.abilities.module ./_service.nix];
}
