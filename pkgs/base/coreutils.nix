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
  version = "9.11";
in
  mkDerivation {
    pname = "coreutils";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/coreutils/coreutils-${version}.tar.xz"];
      hash = "sha256-OUAk7aCllVIXztqc0SAeZdyPo6opwpURNaSVIdV8PMM=";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake perl];
    runtimeDeps = [];
    # Coreutils 9.10 made these commands opt-in; retain the AOS command set
    # and the server PATH's coreutils precedence over util-linux's kill.
    configureFlags = "--disable-nls --enable-single-binary=symlinks --enable-install-program=kill,uptime";

    meta = {
      description = "GNU core utilities";
      homepage = "https://www.gnu.org/software/coreutils/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
