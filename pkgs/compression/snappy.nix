##! Snappy — Fast compression and decompression library
{
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
}: let
  version = "1.2.2";
  benchmarkRevision = "d572f4777349d43653b21d6c2fc63020ab326db2";
  googletestRevision = "b796f7d44681514f58a683a3a71ff17c94edb0c1";

  benchmarkSrc = fetchurl {
    urls = [
      "https://github.com/google/benchmark/archive/${benchmarkRevision}.tar.gz"
    ];
    hash = "sha256-VGfKowJ1Lh9JEbCHWTZMfVcjJdS/OJO9a54JrneJdw0=";
  };
  googletestSrc = fetchurl {
    urls = [
      "https://github.com/google/googletest/archive/${googletestRevision}.tar.gz"
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
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd snappy-${version}

          # GitHub's tag archive omits git submodule contents.  Materialize
          # the exact commits recorded by the 1.2.2 tag so the upstream test
          # and benchmark targets remain enabled in the hermetic build.
          mkdir -p third_party/benchmark third_party/googletest
          tar xf ${benchmarkSrc} --strip-components=1 -C third_party/benchmark
          tar xf ${googletestSrc} --strip-components=1 -C third_party/googletest
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DBUILD_SHARED_LIBS=ON \
            -DSNAPPY_BUILD_TESTS=ON \
            -DSNAPPY_BUILD_BENCHMARKS=ON \
            -DSNAPPY_FUZZING_BUILD=OFF \
            -DBENCHMARK_ENABLE_INSTALL=OFF \
            -DINSTALL_GTEST=OFF
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
          ctest --output-on-failure
        '';
      }
      {
        name = "install";
        script = ''
          make install
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
