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
}: let
  version = "5.4.1";
in
  mkDerivation {
    pname = "gawk";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/gawk/gawk-${version}.tar.xz"];
      hash = "sha256-B/b3NCt/6+QxP8LCVCrZPWT+IK2HFyABCfEFqCb1/Tc=";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake sed];
    runtimeDeps = [bash];
    configureFlags = "--disable-nls";
    postInstall = ''
      [ -f "$out/bin/gawk" ] && [ ! -e "$out/bin/awk" ] && ln -s gawk "$out/bin/awk"
      if [ -f "$out/bin/gawkbug" ]; then
        sed -i \
          -e "1s|^#!.*|#!${bash}/bin/bash|" \
          -e 's|^CC=.*|CC="gcc"|' \
          -e 's|^CFLAGS=.*|CFLAGS=""|' \
          "$out/bin/gawkbug"
      fi
    '';

    meta = {
      description = "GNU pattern scanning and processing language";
      homepage = "https://www.gnu.org/software/gawk/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
