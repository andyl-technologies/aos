# XZ Utils — LZMA compression utilities
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "xz-${versions.core.xz}";
  version = versions.core.xz;

  src = fetchurl {
    inherit (sources.xz) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd xz-${versions.core.xz}
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
