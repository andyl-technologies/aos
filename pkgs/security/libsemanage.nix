# libsemanage — SELinux policy management library
{ mkDerivation, fetchurl, make, pkg-config,
  libsepol, libselinux, audit }:

let version = "3.7"; in
mkDerivation {
  pname = "libsemanage";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
    ];
    hash = "sha256-pZdVqeMfrvEKaNOscWmlx6ubI742J7Z1pcOECgXYKS4=";
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libsepol libselinux audit ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd selinux-${version}/libsemanage
      '';
    }
    { name = "build";
      script = ''
        make PREFIX=$out SHLIBDIR=$out/lib \
          CFLAGS="-I${libsepol}/include -I${libselinux}/include -I${audit}/include" \
          LDFLAGS="-L${libsepol}/lib -L${libselinux}/lib -L${audit}/lib" \
          -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install PREFIX=$out SHLIBDIR=$out/lib
      '';
    }
  ];

  meta = {
    description = "libsemanage — SELinux policy management library";
    homepage = "https://github.com/SELinuxProject/selinux";
    license = "LGPL-2.1-or-later";
  };
}
