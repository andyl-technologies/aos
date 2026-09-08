{
  mkDerivation,
  fetchurl,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  gnumake,
  sed,
  bash,
  coreutils,
}: let
  version = "4.11.0";
in
  mkDerivation {
    pname = "findutils";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/findutils/findutils-${version}.tar.xz"];
      hash = "sha256-v9GcsGzHHzNS1WfpAoTYzawCrIl3S76t8LUzsMEUMv0=";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake sed];
    runtimeDeps = [bash coreutils];
    configureFlags = "--disable-nls";
    postInstall = ''
      if [ -f "$out/bin/updatedb" ]; then
        sed -i \
          -e "1s|^#!.*|#!${bash}/bin/bash|" \
          -e 's|sort="[^"]*/bin/sort\([^"]*\)"|sort="${coreutils}/bin/sort\1"|g' \
          "$out/bin/updatedb"
      fi
    '';

    meta = {
      description = "GNU find, xargs, and locate utilities";
      homepage = "https://www.gnu.org/software/findutils/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
