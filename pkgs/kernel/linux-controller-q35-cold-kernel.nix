##! Build a complete source-guarded Q35 constructor kernel; execution is unsupported.
{
  lib,
  callPackage,
  linuxSource,
  patch,
  python3,
}: let
  fixtures = ./_crucible-q35-cold-source;
  sourcePatches = import (fixtures + "/patches.nix");
in
  # This variant preserves the ordinary configuration, features and artifacts.
  # The native cold source does not confer active clock, RUN or Ready authority.
  callPackage ./linux.nix {
    inherit linuxSource;
    sourcePatchScript = ''
      ${python3}/bin/python3 -I -B ${fixtures}/check-disk.py "$PWD"
      ${python3}/bin/python3 -I -B ${fixtures}/apply-kernel-source.py \
        "$PWD" ${patch}/bin/patch \
        ${lib.concatMapStringsSep " " (sourcePatch: lib.escapeShellArg "${sourcePatch}") sourcePatches}
    '';
  }
