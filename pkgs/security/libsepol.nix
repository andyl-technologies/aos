# libsepol — SELinux binary policy manipulation library
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "libsepol-${versions.security.selinux-userspace}";
  version = versions.security.selinux-userspace;

  src = fetchurl {
    inherit (sources.selinux-userspace) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd selinux-${versions.security.selinux-userspace}/libsepol
      '';
    }
    { name = "build";
      script = ''
        make PREFIX=$out SHLIBDIR=$out/lib -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install PREFIX=$out SHLIBDIR=$out/lib
      '';
    }
  ];

  meta = {
    description = "libsepol — SELinux binary policy manipulation library";
    homepage = "https://github.com/SELinuxProject/selinux";
    license = "LGPL-2.1-or-later";
  };
}
