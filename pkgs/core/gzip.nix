# GNU Gzip — Compression utility
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.13";
in
mkDerivation {
  pname = "gzip";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/gzip/gzip-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/gzip/gzip-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/gzip/gzip-${version}.tar.xz"
    ];
    hash = "sha256-dFTraTXbF8ZlVXbC4bD6vv04tNCTbg+H9IzQYs6RoFc=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd gzip-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        make install
      '';
    }
  ];

  meta = {
    description = "GNU Gzip — data compression program";
    homepage = "https://www.gnu.org/software/gzip/";
    license = "GPL-3.0-or-later";
  };
}
