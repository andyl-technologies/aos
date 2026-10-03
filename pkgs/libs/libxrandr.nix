##! X11 resize, rotate and reflection extension library
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
  libxrender,
}: let
  version = "1.5.4";
in
  mkDerivation {
    pname = "libxrandr";
    inherit version;

    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libXrandr-${version}.tar.xz"];
      hash = "sha256-GtWwZTdfSoWRWqYGEcxkB8BgSSohTX+dryFL51LDtNM=";
    };

    buildDeps = [buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [xorgproto libx11 libxext libxrender];
    # Libtool archives carry the complete static-link transport closure.
    # Preserve those library references through the runtime scrub phase.
    propagatedDeps = [libxcb libxau libxdmcp xorgproto libx11 libxext libxrender];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libXrandr-${version}
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
            mkdir -p "$out/share/licenses/libxrandr"
            cp COPYING "$out/share/licenses/libxrandr/"
          '';
        }
      ];

    meta = {
      description = "X11 resize, rotate and reflection extension library";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
