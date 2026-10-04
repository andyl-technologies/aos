##! LLVM and SPIR-V bidirectional translator
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  llvm,
  spirv-tools,
}: let
  version = "22.1.0";
  headersSrc = fetchurl {
    urls = ["https://github.com/KhronosGroup/SPIRV-Headers/archive/9268f3057354a2cb65991ba5f38b16d81e803692.tar.gz"];
    hash = "sha256-BFAn38xzi22XDEm5K64wzbIsMKnz6EGcPYGSE1UAS5Q=";
  };
in
  mkDerivation {
    pname = "spirv-llvm-translator";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/KhronosGroup/SPIRV-LLVM-Translator/archive/refs/tags/v${version}.tar.gz"];
      hash = "sha256-pdR2QEq4isDRSCEdpQQoF4yJyu+K+AQqPKjnHljtlCc=";
    };

    buildDeps = [buildPackages.cmake buildPackages.ninja buildPackages.python3 buildPackages.pkg-config];
    runtimeDeps = [llvm spirv-tools];
    propagatedDeps = [llvm spirv-tools];
    passthru.evidenceSources = [headersSrc];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd SPIRV-LLVM-Translator-${version}
            # Use the exact header revision pinned by this translator release.
            tar xf ${headersSrc}
            mv SPIRV-Headers-* spirv-headers
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build -G Ninja $cmakeFlags \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=ON -DLLVM_LINK_LLVM_DYLIB=ON \
              -DLLVM_DIR=${llvm}/lib/cmake/llvm \
              -DLLVM_EXTERNAL_SPIRV_HEADERS_SOURCE_DIR="$PWD/spirv-headers" \
              -DLLVM_SPIRV_ENABLE_LIBSPIRV_DIS=ON
          '';
        }
        {
          name = "build";
          script = ''
            ninja -C build -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ lib.optionals (!stdenv.isCross) [
        {
          name = "check";
          script = ''
            ctest --test-dir build --output-on-failure -j"$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ [
        {
          name = "install";
          script = ''
            ninja -C build install
            mkdir -p "$out/share/licenses/spirv-llvm-translator"
            cp -R LICENSE* "$out/share/licenses/spirv-llvm-translator/"
          '';
        }
      ];

    meta = {
      description = "LLVM and SPIR-V bidirectional translator";
      homepage = "https://github.com/KhronosGroup/SPIRV-LLVM-Translator";
      license = "NCSA";
    };
  }
