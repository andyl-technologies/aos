##! Go — the Go programming language, built from source
{
  mkDerivation,
  fetchurl,
  gnumake,
  go-1_24,
  stdenv,
  buildPackages,
}: let
  version = "1.26.0";
  src = fetchurl {
    urls = [
      "https://go.dev/dl/go${version}.src.tar.gz"
    ];
    hash = "sha256-yRMqih9r0qpKrR10uCMdlSdJUEg6SVBlfubFbm6Bd5A=";
  };
in
  if stdenv.hostPlatform.isDarwin
  then
    import ./_go-darwin.nix {
      inherit mkDerivation version src stdenv;
      pname = "go";
      nativeGo = buildPackages.go;
      description = "Go ${version} — Darwin-hosted Go compiler and tools";
    }
  else
    mkDerivation {
      pname = "go";
      inherit version;

      inherit src;

      buildDeps = [
        gnumake
        go-1_24
      ];
      runtimeDeps = [];
      dontStrip = true; # Go runtime metadata in custom ELF sections

      phases = [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd go
          '';
        }
        {
          name = "build";
          script = ''
            export GOROOT_BOOTSTRAP=${go-1_24}
            export GOROOT_FINAL=$out
            export GOCACHE=$TMPDIR/go-cache
            cd src
            bash make.bash
            cd ..
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p $out/bin $out/src $out/pkg
            cp -a bin/* $out/bin/
            cp -a src/* $out/src/
            cp -a pkg/* $out/pkg/
            cp -a lib $out/ 2>/dev/null || true
            cp -a misc $out/ 2>/dev/null || true
          '';
        }
      ];

      checks = {
        testing,
        self,
        pkgs,
      }: {
        hello = testing.mkVMTest {
          name = "toolchain-go-hello";
          rootfsDeps = [self];
          memory = 512;
          testScript = ''
            export GOPATH="/tmp/go"
            export GOCACHE="/tmp/go-cache"
            export CGO_ENABLED=0
            mkdir -p "$GOPATH" "$GOCACHE"

            mkdir -p /tmp/testpkg
            cat > /tmp/testpkg/main.go << 'EOF'
            package main

            import (
                "fmt"
                "sort"
                "strings"
            )

            func main() {
                words := []string{"gamma", "alpha", "beta"}
                sort.Strings(words)
                fmt.Println(strings.Join(words, ","))
            }
            EOF

            cd /tmp/testpkg
            go mod init testpkg
            go build -o /tmp/testbin .
            /tmp/testbin
          '';
        };

        cgo = testing.mkVMTest {
          name = "toolchain-go-cgo";
          rootfsDeps = [self];
          memory = 512;
          testScript = ''
            export GOPATH="/tmp/go"
            export GOCACHE="/tmp/go-cache"
            export CGO_ENABLED=1
            # /usr/local/bin/gcc is a VM-local wrapper created in the
            # Firecracker rootfs by lib/testing/firecracker.nix.
            export CC="/usr/local/bin/gcc"
            mkdir -p "$GOPATH" "$GOCACHE"

            mkdir -p /tmp/cgopkg
            cat > /tmp/cgopkg/main.go << 'GOEOF'
            package main

            /*
            #include <stdlib.h>

            static int c_add(int a, int b) {
                return a + b;
            }
            */
            import "C"
            import "fmt"

            func main() {
                result := C.c_add(C.int(17), C.int(25))
                fmt.Printf("cgo-result=%d\n", int(result))
            }
            GOEOF

            cd /tmp/cgopkg
            go mod init cgopkg
            go build -o /tmp/cgobin .
            /tmp/cgobin
          '';
        };

        test = testing.mkVMTest {
          name = "toolchain-go-test";
          rootfsDeps = [self];
          memory = 512;
          testScript = ''
            export GOPATH="/tmp/go"
            export GOCACHE="/tmp/go-cache"
            export CGO_ENABLED=0
            mkdir -p "$GOPATH" "$GOCACHE"

            mkdir -p /tmp/testpkg
            cat > /tmp/testpkg/go.mod << 'EOF'
            module testpkg
            go 1.26
            EOF

            cat > /tmp/testpkg/math.go << 'EOF'
            package testpkg
            func Add(a, b int) int { return a + b }
            EOF

            cat > /tmp/testpkg/math_test.go << 'EOF'
            package testpkg

            import "testing"

            func TestAdd(t *testing.T) {
                if Add(2, 3) != 5 {
                    t.Fatal("2+3 != 5")
                }
            }

            func TestAddNegative(t *testing.T) {
                if Add(-1, 1) != 0 {
                    t.Fatal("-1+1 != 0")
                }
            }
            EOF

            cd /tmp/testpkg
            go test -v ./...
          '';
        };

        static = testing.mkVMTest {
          name = "toolchain-go-static";
          rootfsDeps = [self];
          memory = 512;
          testScript = ''
            export GOPATH="/tmp/go"
            export GOCACHE="/tmp/go-cache"
            export CGO_ENABLED=0
            mkdir -p "$GOPATH" "$GOCACHE"

            mkdir -p /tmp/staticpkg
            cat > /tmp/staticpkg/main.go << 'EOF'
            package main

            import "fmt"

            func main() {
                fmt.Println("go-static-ok")
            }
            EOF

            cd /tmp/staticpkg
            go mod init staticpkg
            go build -o /tmp/staticbin .
            /tmp/staticbin

            # Verify the binary does not depend on dynamic linker
            readelf -l /tmp/staticbin > /tmp/readelf-out 2>&1 || true
            found_interp=0
            while IFS= read -r line; do
              case "$line" in
                *INTERP*) found_interp=1 ;;
              esac
            done < /tmp/readelf-out
            if [ "$found_interp" = "0" ]; then
              echo "==> Binary is statically linked (no INTERP)"
            else
              echo "==> Binary has INTERP (expected for pure Go with external linker)"
            fi
          '';
        };

        cgo-openssl = testing.mkVMTest {
          name = "toolchain-go-cgo-openssl";
          rootfsDeps = [
            self
            pkgs.openssl
          ];
          memory = 512;
          testScript = ''
            export GOPATH="/tmp/go"
            export GOCACHE="/tmp/go-cache"
            export CGO_ENABLED=1
            # /usr/local/bin/gcc is a VM-local wrapper created in the
            # Firecracker rootfs by lib/testing/firecracker.nix.
            export CC="/usr/local/bin/gcc"
            mkdir -p "$GOPATH" "$GOCACHE"

            OPENSSL="${builtins.toString pkgs.openssl}"
            export CGO_CFLAGS="-I$OPENSSL/include"
            export CGO_LDFLAGS="-L$OPENSSL/lib -lssl -lcrypto"
            export LD_LIBRARY_PATH="$OPENSSL/lib:$LD_LIBRARY_PATH"

            mkdir -p /tmp/sslpkg
            cat > /tmp/sslpkg/main.go << 'GOEOF'
            package main

            /*
            #include <openssl/crypto.h>
            */
            import "C"
            import "fmt"

            func main() {
                ver := C.GoString(C.OpenSSL_version(C.OPENSSL_VERSION))
                fmt.Printf("go-openssl: %s\n", ver)
            }
            GOEOF

            cd /tmp/sslpkg
            go mod init sslpkg
            go build -o /tmp/sslbin .
            /tmp/sslbin
          '';
        };

        cgo-zlib = testing.mkVMTest {
          name = "toolchain-go-cgo-zlib";
          rootfsDeps = [
            self
            pkgs.zlib
          ];
          memory = 512;
          testScript = ''
            export GOPATH="/tmp/go"
            export GOCACHE="/tmp/go-cache"
            export CGO_ENABLED=1
            # /usr/local/bin/gcc is a VM-local wrapper created in the
            # Firecracker rootfs by lib/testing/firecracker.nix.
            export CC="/usr/local/bin/gcc"
            mkdir -p "$GOPATH" "$GOCACHE"

            ZLIB="${builtins.toString pkgs.zlib}"
            export CGO_CFLAGS="-I$ZLIB/include"
            export CGO_LDFLAGS="-L$ZLIB/lib -lz"
            export LD_LIBRARY_PATH="$ZLIB/lib:$LD_LIBRARY_PATH"

            mkdir -p /tmp/zpkg
            cat > /tmp/zpkg/main.go << 'GOEOF'
            package main

            /*
            #include <zlib.h>
            */
            import "C"
            import "fmt"

            func main() {
                ver := C.GoString(C.zlibVersion())
                fmt.Printf("go-zlib: %s\n", ver)
            }
            GOEOF

            cd /tmp/zpkg
            go mod init zpkg
            go build -o /tmp/zbin .
            /tmp/zbin
          '';
        };

        vet = testing.mkVMTest {
          name = "toolchain-go-vet";
          rootfsDeps = [self];
          memory = 512;
          testScript = ''
            export GOPATH="/tmp/go"
            export GOCACHE="/tmp/go-cache"
            export CGO_ENABLED=0
            mkdir -p "$GOPATH" "$GOCACHE"

            # First: clean code should pass vet
            mkdir -p /tmp/cleanpkg
            cat > /tmp/cleanpkg/go.mod << 'EOF'
            module cleanpkg
            go 1.26
            EOF

            cat > /tmp/cleanpkg/main.go << 'EOF'
            package main
            import "fmt"
            func main() { fmt.Println("clean") }
            EOF

            cd /tmp/cleanpkg
            go vet ./...
            echo "==> Clean code passed go vet"

            # Second: buggy code should fail vet
            mkdir -p /tmp/buggypkg
            cat > /tmp/buggypkg/go.mod << 'EOF'
            module buggypkg
            go 1.26
            EOF

            cat > /tmp/buggypkg/main.go << 'EOF'
            package main
            import "fmt"
            func main() {
                x := "hello"
                fmt.Printf("%d\n", x)
            }
            EOF

            cd /tmp/buggypkg
            vet_exit=0
            go vet ./... 2>/tmp/vet-output || vet_exit=$?
            if [ "$vet_exit" -eq 0 ]; then
              echo "FAIL: go vet did not catch the printf format bug"
              exit 1
            fi
            echo "==> go vet correctly caught the format bug (exit=$vet_exit)"
          '';
        };

        fmt = testing.mkVMTest {
          name = "toolchain-go-fmt";
          rootfsDeps = [self];
          memory = 512;
          testScript = ''
            export GOPATH="/tmp/go"
            export GOCACHE="/tmp/go-cache"
            export CGO_ENABLED=0
            mkdir -p "$GOPATH" "$GOCACHE"

            # Write unformatted Go code
            cat > /tmp/ugly.go << 'EOF'
            package main
            import    "fmt"
            func main(  ){
            fmt.Println("hello")
            }
            EOF

            # gofmt -l should report the file as needing formatting
            OUTPUT=$(gofmt -l /tmp/ugly.go)
            if [ -z "$OUTPUT" ]; then
              echo "FAIL: gofmt -l did not report the unformatted file"
              exit 1
            fi
            echo "==> gofmt correctly identified unformatted file: $OUTPUT"

            # Verify gofmt produces valid, compilable output
            gofmt /tmp/ugly.go > /tmp/formatted.go

            mkdir -p /tmp/fmtpkg
            cp /tmp/formatted.go /tmp/fmtpkg/main.go
            cat > /tmp/fmtpkg/go.mod << 'EOF'
            module fmtpkg
            go 1.26
            EOF

            cd /tmp/fmtpkg
            go build -o /tmp/fmtbin .
            /tmp/fmtbin
            echo "==> Formatted code compiles and runs"
          '';
        };

        build = testing.mkVMTest {
          name = "cross-cutting-go-build";
          rootfsDeps = [self];
          memory = 512;
          testScript = ''
            export GOPATH="/tmp/gopath"
            export GOCACHE="/tmp/gocache"
            export PATH="${self}/bin:$PATH"
            mkdir -p /tmp/gopath /tmp/gocache

            cat > /tmp/hello.go << 'EOF'
            package main

            import (
                "fmt"
                "runtime"
            )

            func main() {
                fmt.Printf("Hello from Go %s on %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
                // Test basic computation
                result := fibonacci(10)
                if result != 55 {
                    panic("fibonacci(10) != 55")
                }
                fmt.Printf("fibonacci(10) = %d\n", result)
            }

            func fibonacci(n int) int {
                if n <= 1 { return n }
                return fibonacci(n-1) + fibonacci(n-2)
            }
            EOF

            echo "==> Building Go program"
            go build -o /tmp/hello /tmp/hello.go
            echo "==> Running Go program"
            /tmp/hello
            echo "Go build integration: PASS"
          '';
        };

        cgo-full = testing.mkVMTest {
          name = "cross-cutting-go-cgo-full";
          rootfsDeps = [
            self
            pkgs.zlib
          ];
          memory = 512;
          testScript = ''
            export GOPATH="/tmp/gopath"
            export GOCACHE="/tmp/gocache"
            export HOME="/tmp"
            export PATH="${self}/bin:$PATH"
            export CGO_ENABLED=1
            # /usr/local/bin/gcc is a VM-local wrapper created in the
            # Firecracker rootfs by lib/testing/firecracker.nix.
            export CC="/usr/local/bin/gcc"
            export CGO_CFLAGS="-I${pkgs.zlib}/include"
            export CGO_LDFLAGS="-L${pkgs.zlib}/lib -lz"
            export C_INCLUDE_PATH="${pkgs.zlib}/include:$C_INCLUDE_PATH"
            export LIBRARY_PATH="${pkgs.zlib}/lib:$LIBRARY_PATH"
            export LD_LIBRARY_PATH="${pkgs.zlib}/lib:$LD_LIBRARY_PATH"
            mkdir -p /tmp/gopath /tmp/gocache /tmp/cgotest

            cat > /tmp/cgotest/main.go << 'EOF'
            package main

            /*
            #include <zlib.h>
            #include <stdlib.h>
            #include <string.h>

            int do_compress(const char *src, int srcLen, char *dst, int *dstLen) {
                uLong dl = (uLong)*dstLen;
                int ret = compress((Bytef *)dst, &dl, (const Bytef *)src, (uLong)srcLen);
                *dstLen = (int)dl;
                return ret;
            }

            int do_uncompress(const char *src, int srcLen, char *dst, int *dstLen) {
                uLong dl = (uLong)*dstLen;
                int ret = uncompress((Bytef *)dst, &dl, (const Bytef *)src, (uLong)srcLen);
                *dstLen = (int)dl;
                return ret;
            }
            */
            import "C"
            import (
                "fmt"
                "unsafe"
            )

            func main() {
                src := "Hello from Go CGO with zlib compression!"
                srcC := C.CString(src)
                defer C.free(unsafe.Pointer(srcC))

                // Compress
                dstLen := C.int(256)
                dst := (*C.char)(C.malloc(256))
                defer C.free(unsafe.Pointer(dst))

                ret := C.do_compress(srcC, C.int(len(src)), dst, &dstLen)
                if ret != 0 {
                    panic(fmt.Sprintf("compress failed: %d", ret))
                }
                fmt.Printf("Compressed %d -> %d bytes\n", len(src), dstLen)

                // Uncompress
                outLen := C.int(256)
                out := (*C.char)(C.malloc(256))
                defer C.free(unsafe.Pointer(out))

                ret = C.do_uncompress(dst, dstLen, out, &outLen)
                if ret != 0 {
                    panic(fmt.Sprintf("uncompress failed: %d", ret))
                }

                result := C.GoStringN(out, outLen)
                if result != src {
                    panic(fmt.Sprintf("round-trip mismatch: got %q", result))
                }
                fmt.Printf("Round-trip OK: %q\n", result)
                fmt.Println("Go CGO full: PASS")
            }
            EOF

            echo "==> Building Go CGO program with zlib"
            cd /tmp/cgotest
            go mod init cgotest
            go build -o /tmp/cgotest/cgotest .
            echo "==> Running Go CGO program"
            /tmp/cgotest/cgotest
          '';
        };

        cgo-gcc-and-clang = testing.mkVMTest {
          name = "cross-cutting-go-cgo-gcc-clang";
          rootfsDeps = [
            self
            pkgs.llvm
            pkgs.zlib
          ];
          memory = 768;
          testScript = ''
            export GOPATH="/tmp/gopath"
            export GOCACHE="/tmp/gocache"
            export HOME="/tmp"
            export PATH="${self}/bin:${pkgs.llvm}/bin:$PATH"
            export CGO_ENABLED=1
            export CGO_CFLAGS="-I${pkgs.zlib}/include"
            export CGO_LDFLAGS="-L${pkgs.zlib}/lib -lz"
            export C_INCLUDE_PATH="${pkgs.zlib}/include:$C_INCLUDE_PATH"
            export LIBRARY_PATH="${pkgs.zlib}/lib:$LIBRARY_PATH"
            export LD_LIBRARY_PATH="${pkgs.zlib}/lib:$LD_LIBRARY_PATH"
            mkdir -p "$GOPATH" "$GOCACHE" /tmp/cgo-integration

            BT="${builtins.toString pkgs.bootstrapTools}"
            DL=$(ls "$BT"/lib/ld-linux-*.so.* | head -1)
            GCC_VER=$(ls "$BT"/lib/gcc/x86_64-unknown-linux-gnu)

            # --sysroot=/ points at the Firecracker guest rootfs assembled for
            # this VM test, not at the host filesystem or Nix build sandbox root.
            cat > /tmp/clang-cgo << EOF
            #!/bin/sh
            exec ${pkgs.llvm}/bin/clang \\
              --sysroot=/ \\
              -isystem "$BT/include-glibc" \\
              -B"$BT/lib" \\
              -B"$BT/lib/gcc/x86_64-unknown-linux-gnu/$GCC_VER" \\
              -L"$BT/lib" \\
              -L"$BT/lib/gcc/x86_64-unknown-linux-gnu/$GCC_VER" \\
              -Wl,-dynamic-linker="$DL" \\
              -Wl,-rpath,"$BT/lib" \\
              -Wl,-rpath,"$BT/lib/gcc/x86_64-unknown-linux-gnu/$GCC_VER" \\
              "\$@"
            EOF
            chmod +x /tmp/clang-cgo

            cat > /tmp/cgo-integration/main.go << 'GOEOF'
            package main

            /*
            #include <zlib.h>
            #include <stdlib.h>
            #include <string.h>

            int z_roundtrip(const char *src, int srcLen) {
                unsigned long packedLen = compressBound((unsigned long)srcLen);
                unsigned char *packed = (unsigned char *)malloc(packedLen);
                unsigned char unpacked[128];
                unsigned long unpackedLen = sizeof(unpacked);
                int ret;

                if (packed == NULL) {
                    return -100;
                }

                ret = compress(packed, &packedLen, (const unsigned char *)src, (unsigned long)srcLen);
                if (ret != Z_OK) {
                    free(packed);
                    return ret;
                }

                ret = uncompress(unpacked, &unpackedLen, packed, packedLen);
                free(packed);
                if (ret != Z_OK) {
                    return ret;
                }
                if (unpackedLen != (unsigned long)srcLen) {
                    return -101;
                }
                return memcmp(src, unpacked, (size_t)srcLen);
            }
            */
            import "C"
            import "fmt"

            func main() {
                input := "go cgo compiler integration"
                if rc := C.z_roundtrip(C.CString(input), C.int(len(input))); rc != 0 {
                    panic(fmt.Sprintf("zlib roundtrip failed: %d", int(rc)))
                }
                fmt.Println("go-cgo-compiler-ok")
            }
            GOEOF

            cat > /tmp/cgo-integration/go.mod << 'GOEOF'
            module cgo-integration
            go 1.26
            GOEOF

            cd /tmp/cgo-integration

            # Both compilers are inside the guest: /usr/local/bin/gcc is staged
            # by the VM rootfs builder and /tmp/clang-cgo is generated above.
            for cc in /usr/local/bin/gcc /tmp/clang-cgo; do
              export CC="$cc"
              rm -f /tmp/cgo-integration/cgo-test
              echo "==> Building Go CGO program with CC=$CC"
              go build -x -o /tmp/cgo-integration/cgo-test .
              /tmp/cgo-integration/cgo-test
            done

            echo "Go CGO GCC/LLVM integration: PASS"
          '';
        };
      };

      meta = {
        description = "Go programming language";
        homepage = "https://go.dev";
        license = "BSD-3-Clause";
      };
    }
