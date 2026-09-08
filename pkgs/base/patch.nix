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
  version = "2.8";
in
  mkDerivation {
    pname = "patch";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/patch/patch-${version}.tar.xz"];
      hash = "sha256-rGEL2per4Nn2t8ljJVoR3LGWwl4zfGH5Tkd41jLx2P0=";
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
