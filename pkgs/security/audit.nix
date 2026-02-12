# Audit — Linux auditing framework
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "audit-${versions.security.audit}";
  version = versions.security.audit;

  src = fetchurl {
    inherit (sources.audit) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd audit-${versions.security.audit}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=$out/etc \
          --sbindir=$out/sbin \
          --disable-zos-remote \
          --without-python \
          --without-python3 \
          --without-golang \
          --enable-shared \
          --disable-static
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
    description = "Linux Audit — userspace auditing framework";
    homepage = "https://people.redhat.com/sgrubb/audit/";
    license = "LGPL-2.1-or-later";
  };
}
