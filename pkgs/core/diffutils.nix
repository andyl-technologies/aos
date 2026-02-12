# GNU Diffutils — File comparison utilities
{ mkDerivation, fetchurl, make }:

let version = "3.10"; in
mkDerivation {
  pname = "diffutils";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/diffutils/diffutils-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/diffutils/diffutils-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/diffutils/diffutils-${version}.tar.xz"
    ];
    hash = "sha256-kOXpPMck5OvhLt6A3xY0Bjx6hVaSaFkZv+YLVWyb0J4=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd diffutils-${version}
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
    description = "GNU Diffutils — file comparison utilities (diff, cmp, sdiff, diff3)";
    homepage = "https://www.gnu.org/software/diffutils/";
    license = "GPL-3.0-or-later";
  };
}
