# GNU Patch — Apply diff files to originals
{ mkDerivation, fetchurl, make }:

let version = "2.7.6"; in
mkDerivation {
  pname = "patch";
  inherit version;

  src = fetchurl {
    urls = [
      "https://gnu.mirror.constant.com/patch/patch-${version}.tar.xz"
      "https://mirrors.kernel.org/gnu/patch/patch-${version}.tar.xz"
      "https://ftp.gnu.org/gnu/patch/patch-${version}.tar.xz"
    ];
    hash = "sha256-rGEL2per4Nn2t8ljJVoR3LGWwl4zfGH5Tkd41jLx2P0=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd patch-${version}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out
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
    description = "GNU Patch — apply diff files to originals";
    homepage = "https://www.gnu.org/software/patch/";
    license = "GPL-3.0-or-later";
  };
}
