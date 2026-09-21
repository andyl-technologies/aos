##! X11 authorization-file library and manual pages.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  xorgproto,
}: let
  version = "1.0.12";
in
  mkDerivation {
    pname = "libxau";
    inherit version;
    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libXau-${version}.tar.xz"];
      hash = "1yy0gx3psxyjcj284xhh44labav7b5zs7gcrks9xi6nklggy9l3l";
    };
    buildDeps = [buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [xorgproto];
    propagatedDeps = [xorgproto];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libXau-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out" --enable-shared --enable-static
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
            mkdir -p "$out/share/licenses/libxau"
            cp COPYING "$out/share/licenses/libxau/"
          '';
        }
      ];
    meta = {
      description = "X11 authorization-file library";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
