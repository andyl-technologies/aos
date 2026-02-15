##! GNU Bison — Parser generator
{
  mkDerivation,
  fetchurl,
  make,
  m4,
}:

let
  version = "3.8.2";
in
mkDerivation {
  pname = "bison";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/bison/bison-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/bison/bison-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/bison/bison-${version}.tar.xz"
    ];
    hash = "sha256-m7oCFMz38QecXVkhAEUie89hlRmEDr+oDNOEnP9aW/I=";
  };

  buildDeps = [
    make
    m4
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ m4 ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd bison-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-nls
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
    description = "GNU Bison — general-purpose parser generator";
    homepage = "https://www.gnu.org/software/bison/";
    license = "GPL-3.0-or-later";
  };
}
