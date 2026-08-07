##! Snappy — Fast compression and decompression library
{
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
}: let
  version = "1.2.2";
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
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DBUILD_SHARED_LIBS=ON \
            -DSNAPPY_BUILD_TESTS=ON \
            -DSNAPPY_BUILD_BENCHMARKS=ON \
            -DSNAPPY_FUZZING_BUILD=OFF
        '';
      }
      {
        name = "build";
        script = ''
          cd build
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          cd build
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
