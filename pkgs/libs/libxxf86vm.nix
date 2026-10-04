##! X11 video mode extension library
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
  libxext,
}: let
  version = "1.1.6";
in
  mkDerivation {
    pname = "libxxf86vm";
    inherit version;

    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libXxf86vm-${version}.tar.xz"];
      hash = "sha256-lq9BTHPOHVRJrQS+f58n+oMw+ES23ahD7yLj4b77PuM=";
    };

    buildDeps = [buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [xorgproto libx11 libxext];
    # Libtool archives carry the complete static-link transport closure.
    # Preserve those library references through the runtime scrub phase.
    propagatedDeps = [libxcb libxau libxdmcp xorgproto libx11 libxext];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libXxf86vm-${version}
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
            mkdir -p "$out/share/licenses/libxxf86vm"
            cp COPYING "$out/share/licenses/libxxf86vm/"
          '';
        }
      ];

    meta = {
      description = "X11 video mode extension library";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
