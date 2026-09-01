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
  perl,
}: let
  version = "9.5";
in
  mkDerivation {
    pname = "coreutils";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/coreutils/coreutils-${version}.tar.xz"];
      hash = "12hv193nj10hyzrqh39fpic1ibqjny9kqclzvrjsdxljmkg8wcnd";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake perl];
    runtimeDeps = [];
    configureFlags = "--disable-nls --enable-single-binary=symlinks";

    meta = {
      description = "GNU core utilities";
      homepage = "https://www.gnu.org/software/coreutils/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
