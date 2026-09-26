##! libimagequant — Palette quantization for image encoders.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "2.4.1";
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
    pname = "libimagequant";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/lovell/libimagequant/archive/v${version}.tar.gz"];
      hash = "1ysdjvcylj0844qk2k2av11ppxfbrbix98shkmf9flhhgd5silj7";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libimagequant-${version}
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
            mkdir -p "$out/share/licenses/libimagequant"
            cp COPYRIGHT "$out/share/licenses/libimagequant/"
          '';
        }
      ];

    meta = {
      description = "Palette quantization library used by image encoders";
      homepage = "https://github.com/lovell/libimagequant";
      license = "BSD-2-Clause";
    };
  }
