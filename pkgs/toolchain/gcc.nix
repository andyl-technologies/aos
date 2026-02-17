##! GCC — GNU Compiler Collection
{
  mkDerivation,
  fetchurl,
  make,
  gawk,
  bootstrapTools,
  linux-headers,
  zlib,
  gmp,
  mpfr,
  libmpc,
}: let
  version = "13.4.0";
in
  mkDerivation {
    pname = "gcc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/gcc/gcc-${version}/gcc-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/gcc/gcc-${version}/gcc-${version}.tar.xz"
        "https://ftp.gnu.org/gnu/gcc/gcc-${version}/gcc-${version}.tar.xz"
      ];
      hash = "sha256-nEzm27BAVo/cVFWIrAPFy8lajb8MeqSQFwhDr7WcqPU=";
    };

    buildDeps = [
      make
      gawk
      gmp
      mpfr
      libmpc
    ];
    runtimeDeps = [linux-headers];
    propagatedDeps = [zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gcc-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # Skip fixincludes — AOS uses the ccWrapper for include paths,
          # and /include doesn't exist in the sandbox (headers come from
          # linux-headers via -isystem flags).
          sed -i 's|STMP_FIXINC = @STMP_FIXINC@|STMP_FIXINC =|' gcc/Makefile.in

          mkdir -p objdir && cd objdir

          # Target library configure scripts try to run compiled programs;
          # they need the dynamic linker and library paths from bootstrap tools.
          export LDFLAGS_FOR_TARGET="$LDFLAGS"

          # xgcc (the just-built compiler) doesn't use C_INCLUDE_PATH or the
          # ccWrapper, so it can't find system headers.  Explicitly pass
          # glibc and kernel header paths so target libraries (libgcc,
          # libstdc++) can find stdio.h, stdint.h, linux/futex.h, etc.
          export CFLAGS_FOR_TARGET="-O2 -isystem ${bootstrapTools}/include-glibc -isystem ${linux-headers}/include"
          export CXXFLAGS_FOR_TARGET="-O2 -isystem ${bootstrapTools}/include-glibc -isystem ${linux-headers}/include"

          ../configure \
            --prefix=$out \
            --enable-languages=c,c++ \
            --with-system-zlib \
            --with-gmp=${gmp} \
            --with-mpfr=${mpfr} \
            --with-mpc=${libmpc} \
            --disable-multilib \
            --disable-bootstrap \
            --disable-nls \
            --disable-libsanitizer \
            --with-sysroot=/ \
            --with-native-system-header-dir=${linux-headers}/include \
            --enable-default-pie \
            --enable-default-ssp
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
          # Create cc symlink
          ln -sf gcc $out/bin/cc
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      c-hello = testing.mkVMTest {
        name = "toolchain-c-hello";
        testScript = ''
          cat > /tmp/hello.c << 'EOF'
          #include <stdio.h>
          int main() { printf("Hello from C\n"); return 0; }
          EOF
          gcc -o /tmp/hello /tmp/hello.c
          /tmp/hello
        '';
      };

      cpp-hello = testing.mkVMTest {
        name = "toolchain-cpp-hello";
        testScript = ''
          cat > /tmp/hello.cpp << 'EOF'
          #include <iostream>
          #include <vector>
          #include <algorithm>
          int main() {
              std::vector<std::string> items = {"gamma", "alpha", "beta"};
              std::sort(items.begin(), items.end());
              std::cout << items[0] << "," << items[1] << "," << items[2] << std::endl;
              return 0;
          }
          EOF
          g++ -o /tmp/hello /tmp/hello.cpp
          /tmp/hello
        '';
      };

      dynamic-linking = testing.mkVMTest {
        name = "toolchain-dynamic-linking";
        testScript = ''
          cat > /tmp/dyntest.c << 'EOF'
          #include <stdio.h>
          #include <stdlib.h>
          int main() {
            printf("Dynamic linking works\n");
            void *p = malloc(64);
            if (!p) return 1;
            free(p);
            printf("malloc/free OK\n");
            return 0;
          }
          EOF
          gcc -o /tmp/dyntest /tmp/dyntest.c
          /tmp/dyntest
        '';
      };

      shared-library = testing.mkVMTest {
        name = "toolchain-shared-library";
        testScript = ''
          cat > /tmp/mylib.c << 'EOF'
          int mylib_add(int a, int b) { return a + b; }
          EOF

          cat > /tmp/main.c << 'EOF'
          #include <stdio.h>
          int mylib_add(int a, int b);
          int main(void) {
              int result = mylib_add(17, 25);
              printf("result=%d\n", result);
              return result == 42 ? 0 : 1;
          }
          EOF

          gcc -shared -fPIC -o /tmp/libmylib.so /tmp/mylib.c
          gcc -o /tmp/main /tmp/main.c -L/tmp -lmylib -Wl,-rpath,/tmp
          /tmp/main
        '';
      };

      optimization = testing.mkVMTest {
        name = "toolchain-gcc-optimization";
        testScript = ''
          cat > /tmp/opttest.c << 'EOF'
          #include <stdio.h>
          /* Non-trivial enough that optimization could miscompile */
          static int fib(int n) {
              if (n <= 1) return n;
              return fib(n - 1) + fib(n - 2);
          }
          /* Volatile to prevent constant folding */
          volatile int sink;
          int main(void) {
              sink = 20;
              int n = sink;
              int result = fib(n);
              /* fib(20) = 6765 */
              if (result != 6765) {
                  printf("WRONG: fib(%d)=%d expected=6765\n", n, result);
                  return 1;
              }
              printf("fib(%d)=%d\n", n, result);
              return 0;
          }
          EOF

          for opt in -O0 -O2 -O3; do
            echo "==> Testing $opt"
            gcc $opt -o "/tmp/opttest_$opt" /tmp/opttest.c
            "/tmp/opttest_$opt"
          done
          echo "==> All optimization levels produce correct results"
        '';
      };

      warnings = testing.mkVMTest {
        name = "toolchain-gcc-warnings";
        testScript = ''
          cat > /tmp/clean.c << 'EOF'
          #include <stdio.h>
          #include <stdlib.h>
          #include <string.h>
          static int safe_add(int a, int b) {
              return a + b;
          }
          int main(int argc, char *argv[]) {
              (void)argc;
              (void)argv;
              int result = safe_add(1, 2);
              char buf[32];
              snprintf(buf, sizeof(buf), "result=%d", result);
              printf("%s\n", buf);
              return 0;
          }
          EOF

          gcc -Wall -Wextra -Werror -pedantic -std=c11 -o /tmp/clean /tmp/clean.c
          /tmp/clean
          echo "==> -Wall -Wextra -Werror passed on clean code"
        '';
      };

      static = testing.mkVMTest {
        name = "toolchain-gcc-static";
        testScript = ''
          cat > /tmp/static.c << 'EOF'
          #include <stdio.h>
          int main(void) {
              printf("static-ok\n");
              return 0;
          }
          EOF

          gcc -static -o /tmp/static /tmp/static.c
          /tmp/static
          echo "==> Static binary runs successfully"
        '';
      };

      preprocessor = testing.mkVMTest {
        name = "toolchain-gcc-preprocessor";
        testScript = ''
          cat > /tmp/preproc.c << 'EOF'
          #include <stdio.h>

          #ifndef MY_FLAG
          #error "MY_FLAG not defined"
          #endif

          #define GREETING "preprocessor-ok"

          int main(void) {
              printf("%s MY_FLAG=%d\n", GREETING, MY_FLAG);
              return 0;
          }
          EOF

          gcc -DMY_FLAG=42 -o /tmp/preproc /tmp/preproc.c
          /tmp/preproc
        '';
      };

      link-openssl = testing.mkLinkCheck {
        pname = "toolchain-gcc-link-openssl";
        library = pkgs.openssl;
        libs = [
          "-lssl"
          "-lcrypto"
        ];
        testSource = ''
          #include <stdio.h>
          #include <openssl/ssl.h>
          #include <openssl/crypto.h>
          int main(void) {
              printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
              SSL_CTX *ctx = SSL_CTX_new(TLS_method());
              if (!ctx) {
                  fprintf(stderr, "SSL_CTX_new failed\n");
                  return 1;
              }
              SSL_CTX_free(ctx);
              printf("ssl-link-ok\n");
              return 0;
          }
        '';
      };

      link-zlib = testing.mkLinkCheck {
        pname = "toolchain-gcc-link-zlib";
        library = pkgs.zlib;
        libs = ["-lz"];
        testSource = ''
          #include <stdio.h>
          #include <string.h>
          #include <zlib.h>
          int main(void) {
              const char *input = "Hello, zlib compression test!";
              unsigned char compressed[256];
              unsigned char decompressed[256];
              uLongf comp_len = sizeof(compressed);
              uLongf decomp_len = sizeof(decompressed);

              if (compress(compressed, &comp_len,
                           (const unsigned char *)input, strlen(input) + 1) != Z_OK) {
                  fprintf(stderr, "compress failed\n");
                  return 1;
              }
              if (uncompress(decompressed, &decomp_len,
                             compressed, comp_len) != Z_OK) {
                  fprintf(stderr, "uncompress failed\n");
                  return 1;
              }
              if (strcmp((char *)decompressed, input) != 0) {
                  fprintf(stderr, "roundtrip mismatch\n");
                  return 1;
              }
              printf("zlib-ok version=%s\n", zlibVersion());
              return 0;
          }
        '';
      };

      rpath-injection = testing.mkVMTest {
        name = "toolchain-gcc-rpath-injection";
        rootfsDeps = [
          pkgs.openssl
          pkgs.zlib
        ];
        testScript = ''
          OPENSSL="${builtins.toString pkgs.openssl}"
          ZLIB="${builtins.toString pkgs.zlib}"

          # Set up include/library paths for cross-library linking
          export C_INCLUDE_PATH="$OPENSSL/include:$ZLIB/include:$C_INCLUDE_PATH"
          export LIBRARY_PATH="$OPENSSL/lib:$ZLIB/lib:$LIBRARY_PATH"
          export LD_LIBRARY_PATH="$OPENSSL/lib:$ZLIB/lib:$LD_LIBRARY_PATH"

          cat > /tmp/rpath_test.c << 'EOF'
          #include <stdio.h>
          #include <zlib.h>
          #include <openssl/crypto.h>
          int main(void) {
              printf("zlib=%s openssl=%s\n", zlibVersion(),
                     OpenSSL_version(OPENSSL_VERSION));
              return 0;
          }
          EOF

          gcc -o /tmp/rpath_test /tmp/rpath_test.c -lz -lssl -lcrypto \
            -Wl,-rpath,$OPENSSL/lib -Wl,-rpath,$ZLIB/lib

          # Run the binary to verify it works
          /tmp/rpath_test

          # Verify RPATH is present in the binary using readelf
          readelf -d /tmp/rpath_test > /tmp/rpath-out

          found_rpath=0
          while IFS= read -r line; do
            case "$line" in
              *RPATH*|*RUNPATH*) found_rpath=1 ;;
            esac
          done < /tmp/rpath-out

          if [ "$found_rpath" = "0" ]; then
            echo "FAIL: no RPATH/RUNPATH in binary"
            cat /tmp/rpath-out
            exit 1
          fi
          echo "==> RPATH injection verified"
        '';
      };

      include-paths = testing.mkVMTest {
        name = "toolchain-gcc-include-paths";
        rootfsDeps = [
          pkgs.openssl
          pkgs.zlib
        ];
        testScript = ''
          OPENSSL="${builtins.toString pkgs.openssl}"
          ZLIB="${builtins.toString pkgs.zlib}"

          # Add library include/lib paths via environment (no -I/-L flags)
          export C_INCLUDE_PATH="$OPENSSL/include:$ZLIB/include:$C_INCLUDE_PATH"
          export LIBRARY_PATH="$OPENSSL/lib:$ZLIB/lib:$LIBRARY_PATH"
          export LD_LIBRARY_PATH="$OPENSSL/lib:$ZLIB/lib:$LD_LIBRARY_PATH"

          echo "C_INCLUDE_PATH=$C_INCLUDE_PATH"

          cat > /tmp/find_headers.c << 'EOF'
          #include <zlib.h>
          #include <openssl/ssl.h>
          #include <stdio.h>
          int main(void) {
              printf("include-paths-ok\n");
              return 0;
          }
          EOF

          # Compile WITHOUT explicit -I flags — relies on C_INCLUDE_PATH
          gcc -o /tmp/find_headers /tmp/find_headers.c -lz -lssl -lcrypto
          /tmp/find_headers
          echo "==> Headers found via C_INCLUDE_PATH (no -I flags)"
        '';
      };
    };

    meta = {
      description = "GNU Compiler Collection — C and C++ compilers";
      homepage = "https://gcc.gnu.org";
      license = "GPL-3.0-or-later";
    };
  }
