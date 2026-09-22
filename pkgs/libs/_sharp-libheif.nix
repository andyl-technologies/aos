##! AVIF codec library for Sharp's image-format contract.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  libaom,
  libsharpyuv,
}: let
  version = "1.23.2";
in
  mkDerivation {
    pname = "sharp-libheif";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/strukturag/libheif/releases/download/v${version}/libheif-${version}.tar.gz"];
      hash = "019l2i84dynmv8ixcrpg0ihxyi7j153pf14b25nm716w34fx9mcb";
    };
    buildDeps = [buildPackages.cmake buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = [libaom libsharpyuv];
    propagatedDeps = [libaom libsharpyuv];
    phases =
      [
        {
          name = "unpack";
          script = ''tar xf "$src"; cd libheif-${version}'';
        }
        {
          name = "configure";
          # Sharp's distributed libvips supports AVIF, not HEVC/AVC playback.
          # Keep this private variant separate from any general libheif package.
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
              -DBUILD_TESTING=ON -DENABLE_PLUGIN_LOADING=OFF \
              -DWITH_EXAMPLES=OFF -DWITH_LIBDE265=OFF -DWITH_X265=OFF \
              -DWITH_X264=OFF -DWITH_OpenH264_DECODER=OFF \
              -DWITH_AOM_DECODER=ON -DWITH_AOM_ENCODER=ON \
              -DWITH_LIBSHARPYUV=ON
          '';
        }
        {
          name = "build";
          script = ''cmake --build build --parallel "$NIX_BUILD_CORES"'';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''ctest --test-dir build --output-on-failure'';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            cmake --install build
            mkdir -p "$out/share/licenses/sharp-libheif"
            cp COPYING "$out/share/licenses/sharp-libheif/"
          '';
        }
      ];
    meta = {
      description = "AVIF encoding and decoding for Sharp";
      homepage = "https://github.com/strukturag/libheif";
      license = "LGPL-3.0-or-later";
    };
  }
