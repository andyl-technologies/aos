# SETools — SELinux policy analysis tools
{ mkDerivation, fetchurl, sources, versions, make, pkg-config,
  libsepol, libselinux }:

mkDerivation {
  name = "setools-${versions.security.setools}";
  version = versions.security.setools;

  src = fetchurl {
    inherit (sources.setools) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libsepol libselinux ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd setools-${versions.security.setools}
      '';
    }
    { name = "build";
      script = ''
        # setools uses a Python/Cython build system
        export CFLAGS="-I${libsepol}/include -I${libselinux}/include"
        export LDFLAGS="-L${libsepol}/lib -L${libselinux}/lib"
        python3 setup.py build
      '';
    }
    { name = "install";
      script = ''
        python3 setup.py install --prefix=$out --optimize=1
      '';
    }
  ];

  meta = {
    description = "SETools — policy analysis tools for SELinux";
    homepage = "https://github.com/SELinuxProject/setools";
    license = "GPL-2.0-or-later";
  };
}
