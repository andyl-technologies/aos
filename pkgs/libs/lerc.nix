##! lerc — Limited-error raster compression.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "4.2.0";
  src = fetchurl {
    urls = ["https://github.com/Esri/lerc/archive/refs/tags/v${version}.tar.gz"];
    hash = "1j8pgr282gg58pbh07cn5qh4a9w79x2w9wya024b7dgws4z5kyx1";
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
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "lerc";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A two-by-two unsigned-byte raster tile.";
        operation = "Compress and decompress the tile through Lerc's C API.";
        expected = "The decoded pixels exactly match the input.";
        files."roundtrip.cpp" = ''
          #include <Lerc_c_api.h>
          #include <array>
          #include <cstdio>
          #include <vector>

          int main() {
            std::array<unsigned char, 4> pixels{1, 2, 3, 4};
            unsigned int capacity = 0;
            if (lerc_computeCompressedSize(pixels.data(), 1, 1, 2, 2, 1, 0, nullptr, 0, &capacity) != 0)
              return 1;

            std::vector<unsigned char> encoded(capacity);
            unsigned int written = 0;
            if (lerc_encode(pixels.data(), 1, 1, 2, 2, 1, 0, nullptr, 0,
                            encoded.data(), capacity, &written) != 0)
              return 2;

            std::array<unsigned char, 4> decoded{};
            if (lerc_decode(encoded.data(), written, 0, nullptr, 1, 2, 2, 1, 1,
                            decoded.data()) != 0 || decoded != pixels)
              return 3;

            std::puts("lerc pixel round trip passed");
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cxx@"
              "-std=c++17"
              "-I@out@/include"
              "roundtrip.cpp"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lLerc"
              "-o"
              "roundtrip"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./roundtrip"];
            exit_code = 0;
            stdout.exact = "lerc pixel round trip passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A two-byte sequence without a Lerc header.";
        operation = "Read its blob metadata through Lerc's C API.";
        expected = "Lerc rejects the malformed blob.";
        files."bad.cpp" = ''
          #include <Lerc_c_api.h>
          #include <cstdio>

          int main() {
            const unsigned char bad[] = {'x', 'y'};
            unsigned int info[11]{};
            double range[3]{};
            if (lerc_getBlobInfo(bad, sizeof(bad), info, range, 11, 3) == 0)
              return 1;

            std::puts("lerc rejected malformed blob");
            return 7;
          }
        '';
        artifacts = [];
        steps = [
          {
            argv = [
              "@cxx@"
              "-std=c++17"
              "-I@out@/include"
              "bad.cpp"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lLerc"
              "-o"
              "bad"
            ];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = ["./bad"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "lerc rejected malformed blob\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version src;

    buildDeps = [buildPackages.cmake buildPackages.gnumake];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd lerc-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -DBUILD_SHARED_LIBS=ON
          '';
        }
        {
          name = "build";
          script = ''
            cmake --build build --parallel "$NIX_BUILD_CORES"
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
              # Upstream ships its codec test driver outside the CMake targets.
              $CXX -std=c++17 src/LercTest/main.cpp -Lbuild \
                -Wl,-rpath,"$PWD/build" -lLerc -o build/lerc-test
              build/lerc-test
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            cmake --install build
            mkdir -p "$out/share/licenses/lerc"
            cp LICENSE "$out/share/licenses/lerc/"
          '';
        }
      ];

    meta = {
      description = "Limited-error raster compression library";
      homepage = "https://github.com/Esri/lerc";
      license = "Apache-2.0";
    };
  }
