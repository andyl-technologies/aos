# Registration precedes implementation; the module task replaces this refusal.
{
  pkgs,
  lib,
  mkSystem,
}:
pkgs.mkDerivation {
  pname = "terrane-module-eval-pending";
  version = "0";
  src = null;
  phases = [
    {
      name = "pending";
      script = ''
        printf '%s\n' 'T-PKG-3: module evaluation check awaits implementation' >&2
        exit 1
      '';
    }
  ];
}
