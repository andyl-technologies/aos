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
          # The trailing symlink-name buffer is larger than one byte. Give it
          # a flexible-array type so Fortify 3 accepts valid link targets.
          sed -i 's/char target\[1\];/char target[];/' src/copyin.c
          sed -i 's/sizeof (\*p) + strlen (oldpath) + newlen + 1/sizeof (*p) + strlen (oldpath) + newlen + 2/' src/copyin.c
          grep -Fq 'char target[];' src/copyin.c
        '';
      }
      {
        name = "build";
        script = ''
          CFLAGS="-O2 -std=gnu17" $CONFIG_SHELL ./configure \
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
