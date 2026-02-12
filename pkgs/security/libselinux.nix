# libselinux — SELinux userspace library
{ mkDerivation, fetchurl, sources, versions, make, pkg-config, libsepol }:

mkDerivation {
  name = "libselinux-${versions.security.selinux-userspace}";
  version = versions.security.selinux-userspace;

  src = fetchurl {
    inherit (sources.selinux-userspace) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libsepol ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd selinux-${versions.security.selinux-userspace}/libselinux
      '';
    }
    { name = "build";
      script = ''
        make PREFIX=$out SHLIBDIR=$out/lib \
          CFLAGS="-I${libsepol}/include" \
          LDFLAGS="-L${libsepol}/lib" \
          USE_PCRE2=n \
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
    description = "libselinux — SELinux userspace runtime library";
    homepage = "https://github.com/SELinuxProject/selinux";
    license = "LGPL-2.1-or-later";
  };
}
