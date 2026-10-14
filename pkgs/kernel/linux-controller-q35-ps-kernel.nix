##! Build a complete source-guarded Q35 PS source kernel; execution is unsupported.
{
  lib,
  callPackage,
  linuxSource,
  patch,
  python3,
}: let
  fixtures = ./_crucible-q35-ps-source;
  sourcePatches = import (fixtures + "/patches.nix");
  aosBuildSource = import (fixtures + "/build-source.nix") {inherit lib;};
  companion = ''"$source/share/aos/linux-controller-corresponding-source"'';
  collector = "${python3}/bin/python3 -I -B ${fixtures}/corresponding-source.py";
in
  # This variant preserves the ordinary configuration, features and artifacts.
  # The native PS source does not confer active clock, RUN or Ready authority.
  callPackage ./linux.nix {
    inherit linuxSource;
    sourcePatchScript = ''
      ${python3}/bin/python3 -I -B ${fixtures}/check-disk.py "$PWD"
      ${python3}/bin/python3 -I -B ${fixtures}/apply-kernel-source.py \
        "$PWD" ${patch}/bin/patch \
        ${lib.concatMapStringsSep " " (sourcePatch: lib.escapeShellArg "${sourcePatch}") sourcePatches}
    '';
    sourceArtifact = {
      prepare = ''
        ${collector} prepare "$PWD" ${companion} ${aosBuildSource} ${linuxSource.src} ${fixtures}
      '';
      configured = ''
        ${collector} configured "$PWD" ${companion}
      '';
      built = ''
        ${collector} built "$PWD" ${companion}
      '';
      finish = ''
        ${collector} finish ${companion} "$out" "$dev" "$vmlinux" "$source"
      '';
    };
  }
