##! libnetfilter_cttimeout — Connection tracking timeout policy library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libmnl,
}: let
  version = "1.0.1";
in
  mkDerivation {
    pname = "libnetfilter_cttimeout";
    inherit version;

    src = fetchurl {
      urls = [
        "https://netfilter.org/projects/libnetfilter_cttimeout/files/libnetfilter_cttimeout-${version}.tar.bz2"
      ];
      hash = "sha256-C1naLzIE4cgMuF0fbXIoX8B7AaL1Z4q/Xcz7vv1lAyU=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [libmnl];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libnetfilter_cttimeout-${version}
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
      description = "libnetfilter_cttimeout — connection tracking timeout policy library";
      homepage = "https://netfilter.org/projects/libnetfilter_cttimeout/";
      license = "GPL-2.0-or-later";
    };
  }
