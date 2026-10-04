##! GLSL and HLSL compiler with SPIR-V generation and optimization
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  spirv-tools,
  gcc-libs,
}: let
  version = "1.4.321.0";
  googletestSrc = fetchurl {
    urls = ["https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz"];
    hash = "sha256-itWYxzrXluDYKAsILOvYKmMNc+c808cAV5OKZQG7pdc=";
  };
in
  mkDerivation {
    pname = "glslang";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/KhronosGroup/glslang/archive/refs/tags/vulkan-sdk-${version}.tar.gz"];
      hash = "sha256-yxTwWyW4MmVfRAo2sT+9Crg+UI1N5cLhnF+D62H21Vw=";
    };

    buildDeps = [buildPackages.cmake buildPackages.ninja buildPackages.python3 buildPackages.pkg-config buildPackages.bash];
    runtimeDeps = [spirv-tools gcc-libs];
    propagatedDeps = [spirv-tools];
    passthru.evidenceSources = [googletestSrc];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd glslang-vulkan-sdk-${version}
            tar xf ${googletestSrc} -C External
            mv External/googletest-* External/googletest
          '';
        }
        {
          name = "configure";
          script = ''
            export NIX_LDFLAGS="$NIX_LDFLAGS -L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib"
            # The installed optimizer is the exact SPIRV-Tools SDK revision
            # recorded in this release's known_good.json.
            cmake -S . -B build -G Ninja $cmakeFlags \
              -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=ON \
              -DALLOW_EXTERNAL_SPIRV_TOOLS=ON -DGLSLANG_TESTS=ON \
              -DSPIRV-Tools-opt_DIR=${spirv-tools}/lib/cmake/SPIRV-Tools-opt \
              -DSPIRV-Tools_DIR=${spirv-tools}/lib/cmake/SPIRV-Tools
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
            mkdir -p "$out/share/licenses/glslang"
            cp LICENSE.txt "$out/share/licenses/glslang/"
          '';
        }
      ];

    meta = {
      description = "GLSL and HLSL compiler with SPIR-V generation and optimization";
      homepage = "https://github.com/KhronosGroup/glslang";
      license = "BSD-3-Clause AND BSD-2-Clause AND MIT AND Apache-2.0";
    };
  }
