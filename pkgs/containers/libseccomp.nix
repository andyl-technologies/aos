# libseccomp — Seccomp (secure computing) userspace library
{ mkDerivation, fetchurl, make }:

let version = "2.5.5"; in
mkDerivation {
  pname = "libseccomp";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/seccomp/libseccomp/releases/download/v${version}/libseccomp-${version}.tar.gz"
    ];
    hash = "sha256-JIosik2bmFiqa69ScSw0r+/PnJ6Ut23OAsHJqiX7M3U=";
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd libseccomp-${version}
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
