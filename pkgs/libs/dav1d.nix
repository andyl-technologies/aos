##! AV1 decoding library and command-line decoder.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  xxhash,
}: let
  version = "1.5.4";
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
    pname = "dav1d";
    inherit version;
    src = fetchurl {
      urls = ["https://download.videolan.org/pub/videolan/dav1d/${version}/dav1d-${version}.tar.xz"];
      hash = "1id52hairrw4axf8725jld3ncfy1r8jsp4ck8m28vf4yqsvicrk8";
    };
    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.nasm buildPackages.pkg-config];
    runtimeDeps = [xxhash];
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd dav1d-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release -Dxxhash_muxer=enabled
          '';
        }
        {
          name = "build";
          script = ''
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages ninja -C build -j"$NIX_BUILD_CORES"
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
            PYTHONPATH=${buildPackages.meson}/lib/python3/site-packages ninja -C build install
            mkdir -p "$out/share/licenses/dav1d"
            cp COPYING "$out/share/licenses/dav1d/"
          '';
        }
      ];
    meta = {
      description = "AV1 decoding library and command-line decoder";
      homepage = "https://www.videolan.org/projects/dav1d.html";
      license = "BSD-2-Clause";
    };
  }
