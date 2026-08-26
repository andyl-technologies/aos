##! abseil-cpp — Common C++ libraries used by Protocol Buffers
{
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
}: let
  version = "20230802.0";
in
  mkDerivation {
    pname = "abseil-cpp";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/abseil/abseil-cpp/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-WdKXavnW7PABqBo1dJpuVRozW5SdNJGM+t4Hc3udk8U=";
    };

    buildDeps = [
      cmake
      gnumake
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd abseil-cpp-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_CXX_STANDARD=17 \
            -DBUILD_SHARED_LIBS=ON \
            -DABSL_ENABLE_INSTALL=ON \
            -DABSL_PROPAGATE_CXX_STD=ON \
            -DABSL_BUILD_TESTING=OFF
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build . -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install .
        '';
      }
    ];

    meta = {
      description = "Abseil common C++ libraries";
      homepage = "https://abseil.io";
      license = "Apache-2.0";
    };
  }
