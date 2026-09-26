##! Linux input event device library and inspection tools.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  check,
}: let
  version = "1.13.7";
  probeSource = builtins.readFile ./_libevdev-probe.c;
  compileProbe = {
    argv = [
      "@cc@"
      "-I@out@/include/libevdev-1.0"
      "-L@out@/lib"
      "-Wl,-rpath,@out@/lib"
      "@work@/probe.c"
      "-levdev"
      "-o"
      "@work@/probe"
    ];
    exit_code = 0;
  };
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
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "An in-memory Linux input device descriptor with one key event.";
        operation = "Compile against the installed libevdev and configure the event descriptor.";
        expected = "The library retains the device name and enabled key event.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["@work@/probe"];
            exit_code = 0;
            stdout.exact = "libevdev event descriptor passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "An invalid input-device file descriptor.";
        operation = "Ask the installed libevdev to bind the invalid descriptor.";
        expected = "The library rejects it with EBADF and no device object.";
        files."probe.c" = probeSource;
        artifacts = [];
        steps = [
          compileProbe
          {
            argv = ["@work@/probe" "invalid"];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "libevdev rejected invalid file descriptor\n";
            stderr.exact = "";
          }
        ];
      };
    };
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
