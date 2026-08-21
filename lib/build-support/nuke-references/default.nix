{
  mkDerivation,
  bash,
  gawk,
  sed,
}:
mkDerivation {
  pname = "nuke-references";
  version = "0";
  src = builtins.path {
    path = ./.;
    name = "nuke-references-src";
  };
  runtimeDeps = [bash gawk sed];
  dontStrip = true;
  dontNukeRefs = true; # avoid self-application during fixup
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        ${sed}/bin/sed \
          -e "s|@shell@|${bash}/bin/bash|g" \
          -e "s|@awk@|${gawk}/bin/awk|g" \
          -e "s|@sed@|${sed}/bin/sed|g" \
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
