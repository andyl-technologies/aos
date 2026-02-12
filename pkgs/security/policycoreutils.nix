# policycoreutils — SELinux core policy utilities
{ mkDerivation, fetchurl, make, pkg-config,
  libsepol, libselinux, libsemanage, audit }:

let version = "3.7"; in
mkDerivation {
  pname = "policycoreutils";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
    ];
    hash = "sha256-pZdVqeMfrvEKaNOscWmlx6ubI742J7Z1pcOECgXYKS4=";
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libsepol libselinux libsemanage audit ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd selinux-${version}/policycoreutils
      '';
    }
    { name = "build";
      script = ''
        make PREFIX=$out SBINDIR=$out/sbin \
          CFLAGS="-I${libsepol}/include -I${libselinux}/include -I${libsemanage}/include -I${audit}/include" \
          LDFLAGS="-L${libsepol}/lib -L${libselinux}/lib -L${libsemanage}/lib -L${audit}/lib" \
          -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install PREFIX=$out SBINDIR=$out/sbin
      '';
    }
  ];

  meta = {
    description = "policycoreutils — SELinux core policy management utilities";
    homepage = "https://github.com/SELinuxProject/selinux";
    license = "GPL-2.0-or-later";
  };
}
