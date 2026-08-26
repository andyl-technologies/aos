{mkDerivation, fetchurl, m4, flex, bison, autoconf, automake, texinfo, gnumake}:
let
  version = "5.2.37";
in
  mkDerivation {
    pname = "bash";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/bash/bash-${version}.tar.gz"];
      hash = "1zr1lr6h397qs5fig0g2s6b36arikz2z0yrvgnnqfmqxrlpb56cm";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
    runtimeDeps = [];
    configureFlags = "--without-bash-malloc --disable-nls";
    makeFlags = "-j1";
    postInstall = ''
      [ -f "$out/bin/bash" ] && [ ! -e "$out/bin/sh" ] && ln -s bash "$out/bin/sh"
      rm -f "$out/bin/bashbug"
    '';

    meta = {
      description = "GNU Bourne-Again SHell";
      homepage = "https://www.gnu.org/software/bash/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
