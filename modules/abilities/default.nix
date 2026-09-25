##! Canonical typed ability configuration.
##!
##! The portable schema lives in `lib.abilities`. Selected domains add their
##! own option trees to the same fixed point without making them core types.
{lib, ...}: {
  imports =
    [lib.abilities.module]
    ++ lib.optional (lib.abilities.interfaces ? serviceManagement) ./_service.nix;
}
