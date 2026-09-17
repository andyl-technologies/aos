{
  mkDerivation,
  bash,
  coreutils,
  grep,
  sed,
}:
mkDerivation {
  pname = "nuke-references";
  version = "0";
  src = builtins.path {
    path = ./.;
    name = "nuke-references-src";
  };
  runtimeDeps = [bash coreutils grep];
  dontStrip = true;
  dontNukeRefs = true; # avoid self-application during fixup
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        ${sed}/bin/sed \
          -e "s|@shell@|${bash}/bin/bash|g" \
          -e "s|@chmod@|${coreutils}/bin/chmod|g" \
          -e "s|@dd@|${coreutils}/bin/dd|g" \
          -e "s|@grep@|${grep}/bin/grep|g" \
          -e "s|@stat@|${coreutils}/bin/stat|g" \
          $src/nuke-refs > $out/bin/nuke-refs
        chmod 755 $out/bin/nuke-refs
      '';
    }
  ];
  meta = {
    description = "Remove selected Nix store references from package outputs";
    license = "MIT";
  };
}
