# XZ Utils — LZMA compression utilities
{ mkDerivation, fetchurl, make }:

let version = "5.6.4"; in
mkDerivation {
  pname = "xz";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/tukaani-project/xz/releases/download/v${version}/xz-${version}.tar.xz"
    ];
    hash = "sha256-gpzP5512l0j3VX56RCmmTQaFjifh42LiXQGre5MdnJU=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd xz-${version}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-nls \
          --disable-static \
          --enable-shared
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
    description = "XZ Utils — LZMA compression utilities";
    homepage = "https://tukaani.org/xz/";
    license = "GPL-2.0-or-later";
  };
}
