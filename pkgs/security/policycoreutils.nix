# policycoreutils — SELinux core policy utilities
{ mkDerivation, fetchurl, sources, versions, make, pkg-config,
  libsepol, libselinux, libsemanage, audit }:

mkDerivation {
  name = "policycoreutils-${versions.security.selinux-userspace}";
  version = versions.security.selinux-userspace;

  src = fetchurl {
    inherit (sources.selinux-userspace) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libsepol libselinux libsemanage audit ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd selinux-${versions.security.selinux-userspace}/policycoreutils
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
