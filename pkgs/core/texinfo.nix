# GNU Texinfo — Documentation system
{ mkDerivation, fetchurl, make, perl }:

let version = "7.1"; in
mkDerivation {
  pname = "texinfo";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/texinfo/texinfo-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/texinfo/texinfo-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/texinfo/texinfo-${version}.tar.xz"
    ];
    hash = "sha256-3u7J8Z8VngRv34rSIjGYGAbawzLMNy8cdjUErYKzCVM=";
  };

  buildDeps = [ make perl ];
  runtimeDeps = [ perl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd texinfo-${version}
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
    description = "GNU Texinfo — documentation system for online and printed output";
    homepage = "https://www.gnu.org/software/texinfo/";
    license = "GPL-3.0-or-later";
  };
}
