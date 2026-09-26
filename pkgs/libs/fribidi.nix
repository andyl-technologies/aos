##! fribidi — Unicode bidirectional text support for image rendering.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "1.0.16";
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
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "fribidi";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/fribidi/fribidi/releases/download/v${version}/fribidi-${version}.tar.xz"];
      hash = "0p50krd2mn244y5fqw5li9623qq9lf40wbxyj6g4fh2x4ddxw70v";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd fribidi-${version}
            # Meson runs the fixture runner during the native test suite.
            sed -i '1c#!${buildPackages.python3}/bin/python3' test/test-runner.py
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release
          '';
        }
        {
          name = "build";
          script = ''
            # Ninja invokes Meson's Python helpers without its CLI wrapper.
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages \
              ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
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
            mkdir -p "$out/share/licenses/fribidi"
            cp COPYING "$out/share/licenses/fribidi/"
          '';
        }
      ];

    meta = {
      description = "Unicode bidirectional text library and command-line tools";
      homepage = "https://github.com/fribidi/fribidi";
      license = "LGPL-2.1-or-later";
    };
  }
