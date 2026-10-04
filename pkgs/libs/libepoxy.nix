##! OpenGL and EGL function pointer dispatch library
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  libx11,
  libglvnd,
}: let
  version = "1.5.10";
in
  mkDerivation {
    pname = "libepoxy";
    inherit version;

    src = fetchurl {
      urls = ["https://download.gnome.org/sources/libepoxy/1.5/libepoxy-${version}.tar.xz"];
      hash = "sha256-ByzaS1ndCYu6jCNjpiRymdsfqJQR3CIci4G47oGS5iM=";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.pkg-config buildPackages.python3];
    runtimeDeps = [libx11 libglvnd];
    propagatedDeps = [libx11 libglvnd];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libepoxy-${version}
            patchShebangs src/gen_dispatch.py test
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib \
              --buildtype=release -Dglx=yes -Degl=yes -Dx11=true
          '';
        }
        {
          name = "build";
          script = ''
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              meson test -C build --print-errorlogs
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            PYTHONPATH="${buildPackages.meson}/lib/python3/site-packages" \
              ninja -C build install
            mkdir -p "$out/share/licenses/libepoxy"
            cp COPYING "$out/share/licenses/libepoxy/"
          '';
        }
      ];

    meta = {
      description = "OpenGL and EGL function pointer dispatch library";
      homepage = "https://github.com/anholt/libepoxy";
      license = "MIT";
    };
  }
