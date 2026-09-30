##! Shared-memory X11 synchronization fences
{
  mkDerivation,
  stdenv,
  lib,
  fetchurl,
  buildPackages,
  xorgproto,
}: let
  version = "1.3.3";
in
  mkDerivation {
    pname = "libxshmfence";
    inherit version;

    src = fetchurl {
      urls = ["https://www.x.org/releases/individual/lib/libxshmfence-${version}.tar.xz"];
      hash = "sha256-1KTfCWq6lv6gLAKe46ROEaR+t/chPBpym+g+hew/3hA=";
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
            cd libxshmfence-${version}
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
            mkdir -p "$out/share/licenses/libxshmfence"
            cp COPYING "$out/share/licenses/libxshmfence/"
          '';
        }
      ];

    meta = {
      description = "Shared-memory X11 synchronization fences";
      homepage = "https://www.x.org/";
      license = "MIT";
    };
  }
