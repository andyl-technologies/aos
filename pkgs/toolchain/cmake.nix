##! cmake — cross-platform build system generator
{
  mkDerivation,
  fetchurl,
  gnumake,
  openssl,
  zlib,
}: let
  version = "3.31.6";
in
  mkDerivation {
    pname = "cmake";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/Kitware/CMake/releases/download/v${version}/cmake-${version}.tar.gz"
      ];
      hash = "sha256-ZTQn8PUBR1Cq//InJ/sqpgxscyypGAjPt4ziLd2eVfA=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [
      openssl
      zlib
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd cmake-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./bootstrap \
            --prefix=$out \
            --parallel=$NIX_BUILD_CORES \
            --system-zlib \
            -- \
            -DCMAKE_USE_OPENSSL=ON \
            -DZLIB_LIBRARY=${zlib}/lib/libz.so \
            -DZLIB_INCLUDE_DIR=${zlib}/include \
            -DOPENSSL_ROOT_DIR=${openssl} \
            -DOPENSSL_CRYPTO_LIBRARY=${openssl}/lib/libcrypto.so \
            -DOPENSSL_SSL_LIBRARY=${openssl}/lib/libssl.so \
            -DOPENSSL_INCLUDE_DIR=${openssl}/include
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
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
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "build-cmake";
        tool = self;
        command = "cmake --version";
      };

      build = testing.mkVMTest {
        name = "build-cmake-build";
        rootfsDeps = [
          self
          pkgs.gnumake
        ];
        testScript = ''
          mkdir -p /tmp/proj
          cat > /tmp/proj/CMakeLists.txt << 'EOF'
          cmake_minimum_required(VERSION 3.10)
          project(test C)
          add_executable(test_app main.c)
          EOF
          cat > /tmp/proj/main.c << 'EOF'
          #include <stdio.h>
          int main() { printf("cmake works\n"); return 0; }
          EOF
          mkdir -p /tmp/proj/build
          cd /tmp/proj/build
          cmake ..
          make
          result=$(./test_app)
          test "$result" = "cmake works"
          echo "==> cmake-build passed"
        '';
      };
    };

    meta = {
      description = "Cross-platform build system generator";
      homepage = "https://cmake.org";
      license = "BSD-3-Clause";
    };
  }
