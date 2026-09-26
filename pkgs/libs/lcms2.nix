##! lcms2 — ICC color management for image processing.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  mozjpeg,
  libtiff,
}: let
  version = "2.19.1";
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
    pname = "lcms2";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/mm2/Little-CMS/releases/download/lcms${version}/lcms2-${version}.tar.gz"];
      hash = "1j0m505qqsj1frmx8iyv8sylmfjc5q1sh51004hwkysrmdxlzidz";
    };

    buildDeps = [buildPackages.meson buildPackages.ninja buildPackages.python3 buildPackages.pkg-config];
    runtimeDeps = [mozjpeg libtiff];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd lcms2-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            meson setup build $mesonFlags --prefix="$out" --libdir=lib --buildtype=release \
              -Dutils=true -Djpeg=enabled -Dtiff=enabled
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
            mkdir -p "$out/share/licenses/lcms2"
            cp LICENSE "$out/share/licenses/lcms2/"
          '';
        }
      ];

    meta = {
      description = "ICC color management library for image processing";
      homepage = "https://www.littlecms.com/";
      license = "MIT";
    };
  }
