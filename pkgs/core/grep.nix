# GNU Grep — Pattern matching utility
{ mkDerivation, fetchurl, make }:

let version = "3.11"; in
mkDerivation {
  pname = "grep";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/grep/grep-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/grep/grep-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/grep/grep-${version}.tar.xz"
    ];
    hash = "sha256-HbKu3eidDepCsW2VKPiUyNFdrk4ZC1muzHj1qVEnbqs=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd grep-${version}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-nls
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install
      '';
    }
  ];

  meta = {
    description = "GNU Grep — search for patterns in files";
    homepage = "https://www.gnu.org/software/grep/";
    license = "GPL-3.0-or-later";
  };
}
