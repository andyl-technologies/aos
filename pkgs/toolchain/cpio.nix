##! cpio — GNU cpio archive utility
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2.15";
in
  mkDerivation {
    pname = "cpio";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/cpio/cpio-${version}.tar.gz"
      ];
      hash = "sha256-76UO+YMTfu/AoC/bUVCdYkteMpXJgKoSfO7kGDRVSZ4=";
    };

    buildDeps = [
      gnumake
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd cpio-${version}
        '';
      }
      {
        name = "build";
        script = ''
          $CONFIG_SHELL ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-nls
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
      description = "GNU cpio — archive utility";
      homepage = "https://www.gnu.org/software/cpio/";
      license = "GPL-3.0-or-later";
    };
  }
