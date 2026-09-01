##! cmake — cross-platform build system generator
{
  mkDerivation,
  fetchurl,
  gnumake,
  curl,
  openssl,
  zlib,
  stdenv,
  buildPackages,
}: let
  version = "3.31.6";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  zlibLibrary =
    if isDarwinCross
    then "${zlib}/lib/libz.dylib"
    else "${zlib}/lib/libz.so";
  opensslCryptoLibrary =
    if isDarwinCross
    then "${openssl}/lib/libcrypto.dylib"
    else "${openssl}/lib/libcrypto.so";
  opensslSslLibrary =
    if isDarwinCross
    then "${openssl}/lib/libssl.dylib"
    else "${openssl}/lib/libssl.so";
  curlLibrary =
    if isDarwinCross
    then "${curl}/lib/libcurl.dylib"
    else "${curl}/lib/libcurl.so";
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

    buildDeps =
      if isDarwinCross
      then [
        buildPackages.cmake
        buildPackages.ninja
      ]
      else [gnumake];
    runtimeDeps =
      [
        openssl
        zlib
      ]
      ++ (
        if isDarwinCross
        then [curl]
        else []
      );

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd cmake-${version}
          '';
        }
      ]
      ++ (
        if isDarwinCross
        then [
          {
            name = "configure";
            script = ''
              # Darwin has no FreeBSD libmd; OpenSSL supplies CMake's complete
              # digest implementation. Use target executable links for the
              # remaining feature checks so absent libc APIs do not become
              # false positives merely because a static archive was created.
              cmake -S . -B build -G Ninja \
                -DCMAKE_BUILD_TYPE=Release \
                -DCMAKE_INSTALL_PREFIX=$out \
                -DBUILD_TESTING=OFF \
                -DCMake_BUILD_TESTING=OFF \
                -DCMAKE_USE_OPENSSL=ON \
                -DCMAKE_USE_SYSTEM_CURL=ON \
                -DCMAKE_USE_SYSTEM_ZLIB=ON \
                -DLIBMD_FOUND=FALSE \
                -DCURL_LIBRARY=${curlLibrary} \
                -DCURL_INCLUDE_DIR=${curl}/include \
                -DZLIB_LIBRARY=${zlibLibrary} \
                -DZLIB_INCLUDE_DIR=${zlib}/include \
                -DOPENSSL_ROOT_DIR=${openssl} \
                -DOPENSSL_CRYPTO_LIBRARY=${opensslCryptoLibrary} \
                -DOPENSSL_SSL_LIBRARY=${opensslSslLibrary} \
                -DOPENSSL_INCLUDE_DIR=${openssl}/include \
                $cmakeFlags \
                -DCMAKE_TRY_COMPILE_TARGET_TYPE=EXECUTABLE
            '';
          }
          {
            name = "build";
            script = ''
              ninja -C build -j$NIX_BUILD_CORES
            '';
          }
          {
            name = "install";
            script = ''
              ninja -C build install
            '';
          }
        ]
        else [
          {
            name = "configure";
            script = ''
              ./bootstrap \
                --prefix=$out \
                --parallel=$NIX_BUILD_CORES \
                --system-zlib \
                -- \
                -DCMAKE_USE_OPENSSL=ON \
                -DZLIB_LIBRARY=${zlibLibrary} \
                -DZLIB_INCLUDE_DIR=${zlib}/include \
                -DOPENSSL_ROOT_DIR=${openssl} \
                -DOPENSSL_CRYPTO_LIBRARY=${opensslCryptoLibrary} \
                -DOPENSSL_SSL_LIBRARY=${opensslSslLibrary} \
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
        ]
      );

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
