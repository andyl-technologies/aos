##! X11 client library with XCB transport
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
  xtrans,
}: let
  version = "1.8.10";
in
  mkDerivation {
    pname = "libx11";
    inherit version;

    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libX11-${version}.tar.xz"];
      hash = "sha256-Kzs9rZNH20HcpWvrfbWHjyg73hFC8E2fjkeK9DXf3FM=";
    };

    buildDeps = [buildPackages.gnumake buildPackages.pkg-config buildPackages.perl buildPackages.xmlto buildPackages.libxslt buildPackages.xorg-util-macros];
    runtimeDeps = [xorgproto xtrans libxcb];
    # Libtool archives carry the complete static-link transport closure.
    # Preserve those library references through the runtime scrub phase.
    propagatedDeps = [libxcb libxau libxdmcp xorgproto];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libX11-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            # Xlib feeds text to the preprocessor on stdin, whereas gcc -E
            # requires an explicit input operand. Keep the selected compiler.
            export RAWCPP="$CC -E -x c -"
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
            mkdir -p "$out/share/licenses/libx11"
            cp COPYING "$out/share/licenses/libx11/"
          '';
        }
      ];

    meta = {
      description = "X11 client library with XCB transport";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
