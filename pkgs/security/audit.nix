##! Audit — Linux auditing framework
{
  mkDerivation,
  fetchurl,
  make,
  libcap,
}: let
  version = "4.0.2";
in
  mkDerivation {
    pname = "audit";
    inherit version;

    src = fetchurl {
      urls = [
        "https://people.redhat.com/sgrubb/audit/audit-${version}.tar.gz"
      ];
      hash = "sha256-1dG11Q7kotDReHW8aua9an1bNNlVfqhHo5+uxTH6qgo=";
    };

    buildDeps = [make];
    runtimeDeps = [libcap];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd audit-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --sysconfdir=$out/etc \
            --sbindir=$out/sbin \
            --runstatedir=/run \
            --disable-zos-remote \
            --without-python \
            --without-python3 \
            --without-golang \
            --enable-shared \
            --disable-static
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
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
