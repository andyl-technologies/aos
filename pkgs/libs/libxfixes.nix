##! X11 region and cursor extension library
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
  version = "6.0.1";
in
  mkDerivation {
    pname = "libxfixes";
    inherit version;

    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libXfixes-${version}.tar.xz"];
      hash = "sha256-tpX5PNJJlCGrAtInREWOZQzMiMHUyBMNYCACE6vALVg=";
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
            cd libXfixes-${version}
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
            mkdir -p "$out/share/licenses/libxfixes"
            cp COPYING "$out/share/licenses/libxfixes/"
          '';
        }
      ];

    meta = {
      description = "X11 region and cursor extension library";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
