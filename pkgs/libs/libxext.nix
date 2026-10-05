##! X11 extension client library
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
  version = "1.3.6";

  # XORG_CHECK_MALLOC_ZERO runs a target program, so cross builds state the
  # answer a native build would detect. glibc's realloc(p, 0) frees and
  # returns NULL, while Darwin returns a minimum-sized allocation.
  malloc0Flag =
    lib.optionalString stdenv.isCross
    (
      if stdenv.hostPlatform.isDarwin
      then " --disable-malloc0returnsnull"
      else " --enable-malloc0returnsnull"
    );
in
  mkDerivation {
    pname = "libxext";
    inherit version;

    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libXext-${version}.tar.xz"];
      hash = "sha256-7bWfojmU5AX9xbQAr99YIK5hYLlPNePcPaRFehbol1M=";
    };

    buildDeps = [buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [xorgproto libx11];
    # Libtool archives carry the complete static-link transport closure.
    # Preserve those library references through the runtime scrub phase.
    propagatedDeps = [libxcb libxau libxdmcp libx11];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libXext-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            $CONFIG_SHELL ./configure $configureFlags --prefix="$out"${malloc0Flag}
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
            mkdir -p "$out/share/licenses/libxext"
            cp COPYING "$out/share/licenses/libxext/"
          '';
        }
      ];

    meta = {
      description = "X11 extension client library";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
