# Registration does not qualify the local repository milestone. The concrete
# VM workflow must replace this failing check before it can report success.
{
  pkgs,
  lib,
}:
pkgs.mkDerivation {
  pname = "terrane-local-workflow-ext4-pending";
  version = "0";
  src = null;
  phases = [
    {
      name = "pending";
      script = ''
        printf '%s\n' ${lib.escapeShellArg "Terrane T1 local ext4 workflow: pending implementation and qualification"} >&2
        exit 1
      '';
    }
  ];
}
