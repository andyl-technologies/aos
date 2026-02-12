# GNU Findutils — find, xargs, and locate
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "4.10.0";
in
mkDerivation {
  pname = "findutils";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/findutils/findutils-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/findutils/findutils-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/findutils/findutils-${version}.tar.xz"
    ];
    hash = "sha256-E4fgtn/yR9Kr3pmPkN+/cMFJE5Glnd/suK5ph4nwpPU=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd findutils-${version}
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
    description = "GNU Findutils — find, xargs, and locate utilities";
    homepage = "https://www.gnu.org/software/findutils/";
    license = "GPL-3.0-or-later";
  };
}
