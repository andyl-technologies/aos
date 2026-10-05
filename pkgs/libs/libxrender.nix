##! X11 rendering extension library
{
  mkDerivation,
  libxcb,
  libxau,
  libxdmcp,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  xorgproto,
  libx11,
}: let
  version = "0.9.12";
in
  mkDerivation {
    pname = "libxrender";
    inherit version;

    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libXrender-${version}.tar.xz"];
      hash = "sha256-uDISjaSLOcjWCCJEgXQ0A60Wkb9OVU5L6cF03xcdG5c=";
    };

    buildDeps = [buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [xorgproto libx11];
    # Libtool archives carry the complete static-link transport closure.
    # Preserve those library references through the runtime scrub phase.
    propagatedDeps = [libxcb libxau libxdmcp xorgproto libx11];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libXrender-${version}
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
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            make check
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            make install
            mkdir -p "$out/share/licenses/libxrender"
            cp COPYING "$out/share/licenses/libxrender/"
          '';
        }
      ];

    meta = {
      description = "X11 rendering extension library";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
