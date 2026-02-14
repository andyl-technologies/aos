# policycoreutils — SELinux core policy utilities
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  gettext,
  libsepol,
  libselinux,
  libsemanage,
  libxcrypt,
  audit,
}:

let
  version = "3.7";
in
mkDerivation {
  pname = "policycoreutils";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
    ];
    hash = "sha256-pZdVqeMfrvEKaNOscWmlx6ubI742J7Z1pcOECgXYKS4=";
  };

  buildDeps = [
    make
    pkg-config
    gettext
  ];
  runtimeDeps = [
    libsepol
    libselinux
    libsemanage
    libxcrypt
    audit
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd selinux-${version}/policycoreutils
      '';
    }
    {
      name = "build";
      script = ''
        make PREFIX=$out SBINDIR=$out/sbin \
          CFLAGS="-I${libsepol}/include -I${libselinux}/include -I${libsemanage}/include -I${audit}/include -I${libxcrypt}/include" \
          LDFLAGS="-L${libsepol}/lib -L${libselinux}/lib -L${libsemanage}/lib -L${audit}/lib -L${libxcrypt}/lib" \
          -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        # Fix po/Makefile: replace hardcoded /usr/bin/install with install
        sed -i 's|/usr/bin/install|install|g' po/Makefile
        make install PREFIX=$out SBINDIR=$out/sbin ETCDIR=$out/etc \
          DESTDIR=""
      '';
    }
  ];

  meta = {
    description = "policycoreutils — SELinux core policy management utilities";
    homepage = "https://github.com/SELinuxProject/selinux";
    license = "GPL-2.0-or-later";
  };
}
