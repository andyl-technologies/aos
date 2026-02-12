# GNU Sed — Stream editor
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "4.9";
in
mkDerivation {
  pname = "sed";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/sed/sed-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/sed/sed-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/sed/sed-${version}.tar.xz"
    ];
    hash = "sha256-biJrcy4c1zlGStaGK9Ghq6QteYKSLaelNRljHSSXUYE=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd sed-${version}
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
    description = "GNU Sed — stream editor for filtering and transforming text";
    homepage = "https://www.gnu.org/software/sed/";
    license = "GPL-3.0-or-later";
  };
}
