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
}: let
  version = "4.10";
in
  mkDerivation {
    pname = "sed";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/sed/sed-${version}.tar.xz"];
      hash = "sha256-biJrcy4c1zlGStaGK9Ghq6QteYKSLaelNRljHSSXUYE=";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
    runtimeDeps = [];
    configureFlags = "--disable-nls";

    meta = {
      description = "GNU stream editor";
      homepage = "https://www.gnu.org/software/sed/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
