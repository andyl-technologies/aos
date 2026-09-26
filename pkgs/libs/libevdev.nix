##! Linux input event device library and inspection tools.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  check,
}: let
  version = "1.13.7";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "libevdev";
    inherit version;
    src = fetchurl {
      urls = ["https://www.freedesktop.org/software/libevdev/libevdev-${version}.tar.xz"];
      hash = "19mzc3h6kq166vv46bg8y4xpv38rmqxl6mnk5axib3qhf54q5bqc";
    };
    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.pkg-config buildPackages.doxygen check];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libevdev-${version}
            sed -i '1c#!${buildPackages.python3}/bin/python3' libevdev/make-event-names.py
            sed -i '1c#!${buildPackages.bash}/bin/bash' test/test-static-symbols-leak.sh
          '';
        }
        {
          name = "configure";
          script = ''
            # The test executables link the target Check library when cross compiling.
            export PKG_CONFIG_PATH="${check}/lib/pkgconfig:$PKG_CONFIG_PATH"
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release --wrap-mode=nofallback
          '';
        }
        {
          name = "build";
          script = ''PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages ninja -C build'';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              # Check is a test-only dependency, absent from the installed closure.
              LD_LIBRARY_PATH=${check}/lib \
                PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
                meson test -C build --print-errorlogs
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            meson install -C build
            mkdir -p "$out/share/licenses/libevdev"
            cp COPYING "$out/share/licenses/libevdev/"
          '';
        }
      ];
    meta = {
      description = "Linux input event device library and tools";
      homepage = "https://www.freedesktop.org/software/libevdev/";
      license = "MIT";
    };
  }
