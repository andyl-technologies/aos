##! SPIR-V assembler, validator, optimizer and shared libraries
{
  mkDerivation,
  gcc-libs,
  fetchurl,
  buildPackages,
  stdenv,
  lib,
  spirv-headers,
}: let
  version = "1.4.321.0";
  googletestSrc = fetchurl {
    urls = ["https://github.com/google/googletest/archive/35b75a2cba6ef72b7ce2b6b94b05c54ca07df866.tar.gz"];
    hash = "sha256-tGqW6AJIHOKUGKAY2u68q9d+lMkf0L7Cs+qQC6qfbfA=";
  };
  effceeSrc = fetchurl {
    urls = ["https://github.com/google/effcee/archive/8ce15c424e61a94ee27b5be0ec0ed036b158e6e3.tar.gz"];
    hash = "sha256-yiKiLnlLXyqxZPQwhaHPhk2IOeP8MHM8Wqp8bVatD0E=";
  };
  re2Src = fetchurl {
    urls = ["https://github.com/google/re2/archive/c84a140c93352cdabbfb547c531be34515b12228.tar.gz"];
    hash = "sha256-lK1zvSsyF3h0I5u7ClliWQEhIlJ1FRjCf4f3jRkcNq0=";
  };
  abseilSrc = fetchurl {
    urls = ["https://github.com/abseil/abseil-cpp/archive/212fcb96c8a5218e652b8502f297d236d7fbe3af.tar.gz"];
    hash = "sha256-AM5iVgwlJFpZbd6IVprIJUD51/Cno7RJMYgGciXvz9w=";
  };
in
  mkDerivation {
    pname = "spirv-tools";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/KhronosGroup/SPIRV-Tools/archive/refs/tags/vulkan-sdk-${version}.tar.gz"];
      hash = "sha256-gyf7jz6UcjRqAEyR27g6bl87NsOEbBQs+MDcj6yHEPM=";
    };

    buildDeps = [buildPackages.cmake buildPackages.ninja buildPackages.python3 buildPackages.pkg-config];
    runtimeDeps = [spirv-headers gcc-libs];
    propagatedDeps = [spirv-headers];
    passthru.evidenceSources = [spirv-headers.src googletestSrc effceeSrc re2Src abseilSrc];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd SPIRV-Tools-vulkan-sdk-${version}
            tar xf ${spirv-headers.src} -C external
            mv external/SPIRV-Headers-* external/spirv-headers
            tar xf ${googletestSrc} -C external
            mv external/googletest-* external/googletest
            tar xf ${effceeSrc} -C external
            mv external/effcee-* external/effcee
            tar xf ${re2Src} -C external
            mv external/re2-* external/re2
            tar xf ${abseilSrc} -C external
            mv external/abseil-cpp-* external/abseil_cpp
          '';
        }
        {
          name = "configure";
          script = ''
            # GCC's bootstrap search directory contains static C++ archives.
            # Select the target's shared runtime before that fallback so its
            # private exception and allocation symbols stay out of our ABI.
            export NIX_LDFLAGS="$NIX_LDFLAGS -L${gcc-libs}/lib -Wl,-rpath,${gcc-libs}/lib"
            # GCC 16 speculatively devirtualizes Timer calls as CumulativeTimer
            # and diagnoses the unreachable derived-type access as array bounds.
            cmake -S . -B build -G Ninja $cmakeFlags \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_CXX_FLAGS=-Wno-error=array-bounds \
              -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=ON -DSPIRV-Headers_SOURCE_DIR="$PWD/external/spirv-headers"
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
            mkdir -p "$out/share/licenses/spirv-tools"
            cp -R LICENSE* "$out/share/licenses/spirv-tools/"
          '';
        }
      ];

    meta = {
      description = "SPIR-V assembler, validator, optimizer and shared libraries";
      homepage = "https://github.com/KhronosGroup/SPIRV-Tools";
      license = "Apache-2.0";
    };
  }
