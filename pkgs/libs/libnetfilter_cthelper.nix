##! libnetfilter_cthelper — User-space connection tracking helper library
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  libmnl,
}: let
  version = "1.0.1";
in
  mkDerivation {
    pname = "libnetfilter_cthelper";
    inherit version;

    src = fetchurl {
      urls = [
        "https://netfilter.org/projects/libnetfilter_cthelper/files/libnetfilter_cthelper-${version}.tar.bz2"
      ];
      hash = "sha256-FAc9VIcjOJc1XT/wTdwcjQPMW6jSNWI2qogWGp8tyRI=";
    };

    buildDeps = [
      make
      pkg-config
    ];
    runtimeDeps = [libmnl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libnetfilter_cthelper-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-static \
            --enable-shared
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
      description = "libnetfilter_cthelper — user-space connection tracking helper library";
      homepage = "https://www.netfilter.org/projects/libnetfilter_cthelper/";
      license = "GPL-2.0-or-later";
    };
  }
