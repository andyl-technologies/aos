# GNU Awk — Pattern scanning and processing language
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "5.3.1";
in
mkDerivation {
  pname = "gawk";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/gawk/gawk-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/gawk/gawk-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/gawk/gawk-${version}.tar.xz"
    ];
    hash = "sha256-aU23ZIEqYjZCPU/0DOt7bExEEwG3KtUCu1wn4AzVb3g=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd gawk-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-nls \
          --without-readline
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
    description = "GNU Awk — pattern scanning and processing language";
    homepage = "https://www.gnu.org/software/gawk/";
    license = "GPL-3.0-or-later";
  };
}
