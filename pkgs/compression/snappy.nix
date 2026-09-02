##! Snappy — Fast compression and decompression library
{
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
  zlib,
  lz4,
  stdenv,
}: let
  version = "1.2.2";
  benchmarkSrc = fetchurl {
    urls = [
      "https://github.com/google/benchmark/archive/d572f4777349d43653b21d6c2fc63020ab326db2.tar.gz"
    ];
    hash = "sha256-VGfKowJ1Lh9JEbCHWTZMfVcjJdS/OJO9a54JrneJdw0=";
  };
  googletestSrc = fetchurl {
    urls = [
      "https://github.com/google/googletest/archive/b796f7d44681514f58a683a3a71ff17c94edb0c1.tar.gz"
    ];
    hash = "sha256-JoHejAkwsGENxSomAvrUHQ2vo9f/EDDaZXXVb8H0ykY=";
  };
in
  mkDerivation {
    pname = "snappy";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/google/snappy/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-kPdLwfv3imxWs8SggqBRA7Ola7F7yhon4FLqEXIyktw=";
    };

    buildDeps = [cmake gnumake];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [zlib lz4]
      else [];
    propagatedDeps = [];

    # Static-only CMake cross probes do not record Clang's implicit C++
    # libraries, so shared Google Benchmark targets need them stated below.
    # The same unresolved-symbol behavior makes the optional comparison
    # harness claim unavailable lzo and librt. Darwin provides shm_open in
    # libSystem; zlib and lz4 remain enabled with explicit target inputs.
    # Map __FILE__ paths so the installed benchmark and test-support dylibs do
    # not retain their ephemeral sandbox location.
    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            mkdir -p snappy-${version}/third_party/benchmark
            tar xf ${benchmarkSrc} \
              --strip-components=1 \
              -C snappy-${version}/third_party/benchmark
            mkdir -p snappy-${version}/third_party/googletest
            tar xf ${googletestSrc} \
              --strip-components=1 \
              -C snappy-${version}/third_party/googletest
            cd snappy-${version}
          '';
        }
      ]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [
          {
            name = "postPatch";
            script = ''
              # Clang diagnoses the zlib test's uninitialized byte because it
              # is passed through a const input pointer. Its value is not
              # consumed, but initialize it to keep the test well-defined.
              sed -i 's/Bytef dummyin, dummyout;/Bytef dummyin = 0, dummyout;/' snappy-test.cc
            '';
          }
        ]
        else []
      )
      ++ [
        {
          name = "configure";
          script = ''
            cmake -S . -B build \
              $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX=$out \
              -DCMAKE_INSTALL_LIBDIR=lib \
              -DBUILD_SHARED_LIBS=ON \
              -DSNAPPY_BUILD_TESTS=ON \
              -DSNAPPY_BUILD_BENCHMARKS=ON \
              ${
              if stdenv.hostPlatform.isDarwin
              then ''
                "-DCMAKE_CXX_FLAGS=-Wno-c2y-extensions -ffile-prefix-map=$PWD=." \
                "-DCMAKE_CXX_STANDARD_LIBRARIES=-lc++ -lc++abi" \
                -DHAVE_LIBLZO2=OFF \
                -DHAVE_LIB_RT=OFF \
                -DSNAPPY_FUZZING_BUILD=OFF
              ''
              else ''
                -DSNAPPY_FUZZING_BUILD=OFF
              ''
            }
          '';
        }
        {
          name = "build";
          script = ''
            cmake --build build -j$NIX_BUILD_CORES
          '';
        }
        {
          name = "install";
          script = ''
            cmake --install build
          '';
        }
      ];

    checks = {
      testing,
      self,
      ...
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libsnappy.so"];
      };

      link = testing.mkLinkCheck {
        pname = "lib-snappy";
        library = self;
        libs = ["-lsnappy"];
        testSource = ''
          #include <snappy-c.h>
          int main(void) {
            return snappy_max_compressed_length(16) == 0;
          }
        '';
      };
    };

    meta = {
      description = "Fast compression and decompression library";
      homepage = "https://github.com/google/snappy";
      license = "BSD-3-Clause";
    };
  }
