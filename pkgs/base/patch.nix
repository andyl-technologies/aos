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
  version = "2.7.6";
in
  mkDerivation {
    pname = "patch";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/patch/patch-${version}.tar.xz"];
      hash = "1zfqy4rdcy279vwn2z1kbv19dcfw25d2aqy9nzvdkq5bjzd0nqdc";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
    runtimeDeps = [];

    meta = {
      description = "GNU file patching utility";
      homepage = "https://www.gnu.org/software/patch/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
