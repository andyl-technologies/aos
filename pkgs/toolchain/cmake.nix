##! cmake — cross-platform build system generator
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  openssl,
  zlib,
  stdenv,
  buildPackages,
}: let
  version = "4.4.3";
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
  # CMake 4's libarchive probe uses find_path, which cannot infer headers
  # injected by the compiler wrapper. Point it at the target libc explicitly.
  iconvIncludeDir =
    if isDarwinCross
    then "${stdenv.sdk}/usr/include"
    else "${stdenv.glibc.dev}/include";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "cmake";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "CMake evaluates the language constructs and emits the fixed result.";
        "files" = {
          "valid.cmake" = "math(EXPR answer \"6 * 7\")\nif(NOT answer EQUAL 42)\n  message(FATAL_ERROR \"wrong answer\")\nendif()\nmessage(\"cmake result: \${answer}\")\n";
        };
        "input" = "A CMake script performing integer arithmetic and a conditional.";
        "operation" = "Execute the script in CMake script mode.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/cmake"
              "-P"
              "@work@/primary/valid.cmake"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "cmake result: 42\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "CMake rejects the unknown command with status 1.";
        "files" = {
          "invalid.cmake" = "not_a_cmake_command()\n";
        };
        "input" = "A CMake script calling an unknown command.";
        "operation" = "Execute the invalid script in CMake script mode.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/cmake"
              "-P"
              "@work@/bad-input/invalid.cmake"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/Kitware/CMake/releases/download/v${version}/cmake-${version}.tar.gz"
      ];
      hash = "sha256-xGQAYYtPHytDUH8k+yLzroMMNBbPI7d24W4dQTqokvA=";
    };

    buildDeps =
      if isDarwinCross
      then [
        buildPackages.cmake
        buildPackages.ninja
      ]
      else [gnumake];
    runtimeDeps = [
      openssl
      zlib
    ];

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
              # Bundled curl breaks the target-curl -> native-CMake bootstrap
              # cycle while retaining CMake's network support.
              cmake -S . -B build -G Ninja \
                -DCMAKE_BUILD_TYPE=Release \
                -DCMAKE_INSTALL_PREFIX=$out \
                -DBUILD_TESTING=OFF \
                -DCMake_BUILD_TESTING=OFF \
                -DCMAKE_USE_OPENSSL=ON \
                -DCMAKE_USE_SYSTEM_CURL=OFF \
                -DCMAKE_USE_SYSTEM_ZLIB=ON \
                -DLIBMD_FOUND=FALSE \
                -DZLIB_LIBRARY=${zlibLibrary} \
                -DZLIB_INCLUDE_DIR=${zlib}/include \
                -DOPENSSL_ROOT_DIR=${openssl} \
                -DOPENSSL_CRYPTO_LIBRARY=${opensslCryptoLibrary} \
                -DOPENSSL_SSL_LIBRARY=${opensslSslLibrary} \
                -DOPENSSL_INCLUDE_DIR=${openssl}/include \
                -DICONV_INCLUDE_DIR=${iconvIncludeDir} \
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
                -DOPENSSL_INCLUDE_DIR=${openssl}/include \
                -DICONV_INCLUDE_DIR=${iconvIncludeDir}
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
