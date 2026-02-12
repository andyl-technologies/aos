# libsemanage — SELinux policy management library
{ mkDerivation, fetchurl, sources, versions, make, pkg-config,
  libsepol, libselinux, audit }:

mkDerivation {
  name = "libsemanage-${versions.security.selinux-userspace}";
  version = versions.security.selinux-userspace;

  src = fetchurl {
    inherit (sources.selinux-userspace) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libsepol libselinux audit ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd selinux-${versions.security.selinux-userspace}/libsemanage
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
