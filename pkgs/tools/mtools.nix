##! mtools — utilities for accessing MS-DOS disks
{
  mkDerivation,
  fetchurl,
  gnumake,
}:
let
  version = "4.0.44";
in
mkDerivation {
  pname = "mtools";
  inherit version;

  src = fetchurl {
    urls = [
      "https://ftp.gnu.org/gnu/mtools/mtools-${version}.tar.gz"
      "https://mirrors.kernel.org/gnu/mtools/mtools-${version}.tar.gz"
    ];
    hash = "sha256-EL52FIhw+YT6RN8pdHOk5FGERyzbGaTQXvF/21m11aQ=";
  };

  buildDeps = [ gnumake ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd mtools-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --without-x
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
    description = "mtools — utilities for accessing MS-DOS disks";
    homepage = "https://www.gnu.org/software/mtools/";
    license = "GPL-3.0-or-later";
  };
}
