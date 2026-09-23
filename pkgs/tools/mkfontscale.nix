##! X font index generator.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  libfontenc,
  freetype,
  zlib,
  bzip2,
  xorgproto,
}: let
  version = "1.2.4";
in
  mkDerivation {
    pname = "mkfontscale";
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/app/mkfontscale-${version}.tar.xz"];
      hash = "0phsn0fvbm0wd805znlqyawialrh1s2pir9fz7ihwv4vgahr4550";
    };
    buildDeps = [buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [libfontenc freetype zlib bzip2 xorgproto];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd mkfontscale-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out"
          '';
        }
        {
          name = "build";
          script = ''
            make -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              make check
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            make install
            mkdir -p "$out/share/licenses/mkfontscale"
            cp COPYING "$out/share/licenses/mkfontscale/"
          '';
        }
      ];
    meta = {
      description = "X font index generator";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
