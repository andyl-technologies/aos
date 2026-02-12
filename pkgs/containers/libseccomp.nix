# libseccomp — Seccomp (secure computing) userspace library
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "libseccomp-2.5.5";
  version = "2.5.5";

  src = fetchurl {
    inherit (sources.libseccomp) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd libseccomp-2.5.5
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
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
    description = "libseccomp — enhanced seccomp (mode 2) userspace library";
    homepage = "https://github.com/seccomp/libseccomp";
    license = "LGPL-2.1-only";
  };
}
