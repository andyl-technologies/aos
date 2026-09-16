##! tcpdump — Network packet analyzer
{
  mkDerivation,
  fetchurl,
  gnumake,
  libpcap,
}: let
  version = "4.99.6";
in
  mkDerivation {
    pname = "tcpdump";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.tcpdump.org/release/tcpdump-${version}.tar.gz"
      ];
      hash = "sha256-WDmSGg9n19j6PazZzUHkTInMuGfoptshbWJijH/RSwk=";
    };

    buildDeps = [
      gnumake
    ];
    runtimeDeps = [libpcap];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd tcpdump-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out
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
      description = "tcpdump — network packet analyzer";
      homepage = "https://www.tcpdump.org";
      license = "BSD-3-Clause";
    };
  }
