##! wayland-protocols - source-built Wayland protocol infrastructure
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  wayland,
}: let
  version = "1.43";
in
  mkDerivation {
    pname = "wayland-protocols";
    inherit version;

    src = fetchurl {
      urls = ["https://gitlab.freedesktop.org/wayland/wayland-protocols/-/releases/${version}/downloads/wayland-protocols-${version}.tar.xz"];
      hash = "sha256-ujw0Jd0nxXtSkek9upe+EkeWAeALyrJNJkcZSMtkNlM=";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.pkg-config buildPackages.python3 buildPackages.wayland wayland];
    runtimeDeps = [];
    propagatedDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd wayland-protocols-${version}
            sed -i '1c#!${buildPackages.python3}/bin/python3' tests/replace.py
            sed -i '1c#!${buildPackages.bash}/bin/bash -e' tests/scan.sh
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib \
              --buildtype=release -Dc_link_args=-Wl,-rpath,${wayland}/lib
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
            mkdir -p "$out/lib/pkgconfig"
            ln -s ../../share/pkgconfig/wayland-protocols.pc "$out/lib/pkgconfig/wayland-protocols.pc"
            mkdir -p "$out/share/licenses/wayland-protocols"
            cp COPYING "$out/share/licenses/wayland-protocols/"
          '';
        }
      ];

    meta = {
      description = "Additional Wayland protocol definitions";
      homepage = "https://wayland.freedesktop.org/";
      license = "MIT";
    };
  }
