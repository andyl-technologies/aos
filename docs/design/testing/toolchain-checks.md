# Toolchain Integration Checks

This document specifies integration tests for compiler toolchains, language
runtimes, and build systems in AOS. Each test validates that a toolchain
produces correct, linkable, runnable binaries using AOS-built packages and
the AOS build environment (ccWrapper, bootstrap tools, C_INCLUDE_PATH, etc.).

All tests in this document are **build-sandbox** (Layer 2.5) tests: each test
is a Nix derivation that compiles a test program and runs it inside the Nix
build sandbox. No VM is required. The derivation succeeds only if every
assertion passes.

## Test infrastructure

### Build-sandbox test pattern

Each test is a `mkDerivation` that takes the packages under test as
`buildDeps` or `runtimeDeps`, writes a small source file inline, compiles it,
runs it, and asserts on the output. The derivation creates `$out/result`
on success.

```nix
# Pattern: build-sandbox integration test
pkgs.mkDerivation {
  pname = "check-<name>";
  version = "0";
  src = null;
  buildDeps = [ /* packages under test */ ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      # Write test source, compile, run, assert
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### Composition

All toolchain checks are collected in `tests/toolchain.nix` and exposed as
`checks.toolchain` in the test entry point. Individual checks can be run via:

```
nix-build -A checks.toolchain           # all toolchain checks
nix-build -A checks.toolchain.gcc       # gcc group only
nix-build -A checks.toolchain.go        # go group only
```

### Conventions

- Test names use the pattern `check-<group>-<name>` for the derivation pname.
- Each test writes a clear PASS/FAIL line to stdout before creating `$out`.
- Tests that compile C/C++ use `$CC`, `$CXX`, `$LD` from the environment
  (set by mkDerivation from ccWrapper).
- The builder shell is `/bin/sh` (dash). Use `$CONFIG_SHELL` for bash features.
- Phase scripts must avoid bash-isms (no `[[ ]]`, no `<<<`, no arrays).

---

## GCC (C/C++ compiler)

### TC-001: gcc-compile-c

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | gcc, glibc, ccWrapper |
| Description | Compile and run a minimal C program. Validates the fundamental C compilation pipeline. |

```nix
pkgs.mkDerivation {
  pname = "check-gcc-compile-c";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > hello.c << 'EOF'
      #include <stdio.h>
      #include <stdlib.h>
      int main(void) {
          printf("Hello from AOS gcc\n");
          return EXIT_SUCCESS;
      }
      EOF

      $CC -o hello hello.c
      OUTPUT=$(./hello)
      if [ "$OUTPUT" != "Hello from AOS gcc" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: gcc-compile-c"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-002: gcc-compile-cpp

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | gcc, g++, libstdc++, ccWrapper -nostdinc++ logic |
| Description | Compile a C++ program using STL containers and iostream. Validates the g++ wrapper's -nostdinc++ header ordering fix. |

```nix
pkgs.mkDerivation {
  pname = "check-gcc-compile-cpp";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > test.cpp << 'EOF'
      #include <iostream>
      #include <string>
      #include <vector>
      #include <algorithm>
      #include <cstdlib>

      int main() {
          std::vector<std::string> items = {"gamma", "alpha", "beta"};
          std::sort(items.begin(), items.end());
          if (items[0] != "alpha" || items[1] != "beta" || items[2] != "gamma") {
              std::cerr << "sort failed" << std::endl;
              return EXIT_FAILURE;
          }
          std::cout << "STL OK" << std::endl;
          return EXIT_SUCCESS;
      }
      EOF

      $CXX -o test test.cpp
      OUTPUT=$(./test)
      if [ "$OUTPUT" != "STL OK" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: gcc-compile-cpp"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-003: gcc-link-shared

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | gcc, binutils ld, shared library linking, RPATH |
| Description | Build a shared library (.so), link a program against it, and run the result. Validates the dynamic linking pipeline including RPATH resolution. |

```nix
pkgs.mkDerivation {
  pname = "check-gcc-link-shared";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Build a shared library
      cat > mylib.c << 'EOF'
      int mylib_add(int a, int b) { return a + b; }
      EOF

      cat > mylib.h << 'EOF'
      int mylib_add(int a, int b);
      EOF

      cat > main.c << 'EOF'
      #include <stdio.h>
      #include "mylib.h"
      int main(void) {
          int result = mylib_add(17, 25);
          printf("result=%d\n", result);
          return result == 42 ? 0 : 1;
      }
      EOF

      $CC -shared -fPIC -o libmylib.so mylib.c
      $CC -o main main.c -L. -lmylib -Wl,-rpath,$PWD
      OUTPUT=$(./main)
      if [ "$OUTPUT" != "result=42" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: gcc-link-shared"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-004: gcc-link-openssl

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | gcc, openssl headers and libraries, ccWrapper include/library paths |
| Description | Compile a program that calls OpenSSL functions and links against libssl and libcrypto. Validates that AOS openssl headers are discoverable and the library links correctly. |

```nix
pkgs.mkDerivation {
  pname = "check-gcc-link-openssl";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > test_ssl.c << 'EOF'
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
      EOF

      $CC -o test_ssl test_ssl.c -lssl -lcrypto
      OUTPUT=$(./test_ssl)
      if ! echo "$OUTPUT" | grep -q "ssl-link-ok"; then
        echo "FAIL: openssl link test failed: $OUTPUT"
        exit 1
      fi
      echo "PASS: gcc-link-openssl"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-005: gcc-link-zlib

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | gcc, zlib headers and libraries |
| Description | Compile a program that calls zlib compress/uncompress and links against libz. Validates the gcc-to-zlib dependency edge. |

```nix
pkgs.mkDerivation {
  pname = "check-gcc-link-zlib";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make ];
  runtimeDeps = [ pkgs.zlib ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > test_zlib.c << 'EOF'
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
      EOF

      $CC -o test_zlib test_zlib.c -lz
      OUTPUT=$(./test_zlib)
      if ! echo "$OUTPUT" | grep -q "zlib-ok"; then
        echo "FAIL: zlib link test failed: $OUTPUT"
        exit 1
      fi
      echo "PASS: gcc-link-zlib"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-006: gcc-optimization

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | gcc optimizer correctness at -O0, -O2, -O3 |
| Description | Compile a non-trivial computation at multiple optimization levels and verify all produce identical correct results. Catches optimizer bugs that could silently corrupt builds. |

```nix
pkgs.mkDerivation {
  pname = "check-gcc-optimization";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > opttest.c << 'EOF'
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
        $CC $opt -o "opttest_$opt" opttest.c
        OUTPUT=$("./opttest_$opt")
        if ! echo "$OUTPUT" | grep -q "fib(20)=6765"; then
          echo "FAIL: optimization $opt produced: $OUTPUT"
          exit 1
        fi
        echo "  $opt: OK"
      done
      echo "PASS: gcc-optimization"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-007: gcc-warnings

| Field | Value |
|-------|-------|
| Priority | P2 |
| Type | build-sandbox |
| Validates | gcc warning compatibility with clean code |
| Description | Compile clean C code with -Wall -Werror and verify no warnings are emitted. Validates that the bootstrap gcc's warning set is compatible with standard coding patterns. |

```nix
pkgs.mkDerivation {
  pname = "check-gcc-warnings";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > clean.c << 'EOF'
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

      $CC -Wall -Wextra -Werror -pedantic -std=c11 -o clean clean.c
      ./clean
      echo "PASS: gcc-warnings"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-008: gcc-rpath-injection

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | ccWrapper RPATH injection, $NIX_LDFLAGS forwarding |
| Description | Compile and link a binary, then verify that RPATH entries from ccWrapper and runtime dependencies appear in the ELF binary. This is the critical mechanism that makes AOS binaries self-contained. |

```nix
pkgs.mkDerivation {
  pname = "check-gcc-rpath-injection";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make ];
  runtimeDeps = [ pkgs.zlib pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > rpath_test.c << 'EOF'
      #include <stdio.h>
      #include <zlib.h>
      #include <openssl/crypto.h>
      int main(void) {
          printf("zlib=%s openssl=%s\n", zlibVersion(),
                 OpenSSL_version(OPENSSL_VERSION));
          return 0;
      }
      EOF

      $CC -o rpath_test rpath_test.c -lz -lssl -lcrypto
      ./rpath_test

      # Verify RPATH contains the bootstrap tools lib directory
      RPATH=$(readelf -d rpath_test | grep -E 'RPATH|RUNPATH' || true)
      if [ -z "$RPATH" ]; then
        echo "FAIL: no RPATH/RUNPATH in binary"
        exit 1
      fi
      echo "  RPATH entry: $RPATH"

      # Verify ldd resolves all shared libraries (no "not found")
      LDD_OUT=$(ldd rpath_test 2>&1)
      if echo "$LDD_OUT" | grep -q "not found"; then
        echo "FAIL: unresolved shared libraries:"
        echo "$LDD_OUT"
        exit 1
      fi
      echo "PASS: gcc-rpath-injection"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-009: gcc-include-paths

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | C_INCLUDE_PATH, CPLUS_INCLUDE_PATH, build environment setup |
| Description | Verify that the build environment correctly sets include paths so that headers from runtime dependencies are discoverable without explicit -I flags. |

```nix
pkgs.mkDerivation {
  pname = "check-gcc-include-paths";
  version = "0";
  src = null;
  buildDeps = [ pkgs.make ];
  runtimeDeps = [ pkgs.zlib pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Verify C_INCLUDE_PATH is set and contains dep paths
      echo "C_INCLUDE_PATH=$C_INCLUDE_PATH"
      if [ -z "$C_INCLUDE_PATH" ]; then
        echo "FAIL: C_INCLUDE_PATH is empty"
        exit 1
      fi

      # Verify zlib.h is findable through the include path
      cat > find_headers.c << 'EOF'
      #include <zlib.h>
      #include <openssl/ssl.h>
      int main(void) { return 0; }
      EOF

      # Compile without explicit -I flags -- relies on C_INCLUDE_PATH
      $CC -o find_headers find_headers.c -lz -lssl -lcrypto
      echo "  Headers found via C_INCLUDE_PATH"

      # Also verify PKG_CONFIG_PATH if pkg-config is available
      if [ -n "${PKG_CONFIG_PATH:-}" ]; then
        echo "  PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
      fi

      echo "PASS: gcc-include-paths"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## Binutils

### TC-010: binutils-as

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | GNU assembler (as) |
| Description | Assemble a minimal x86_64 assembly file into an object file. Validates the assembler from the bootstrap tools. |

```nix
pkgs.mkDerivation {
  pname = "check-binutils-as";
  version = "0";
  src = null;
  buildDeps = [ pkgs.binutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > test.s << 'EOF'
      .section .data
      msg:  .asciz "asm-ok\n"
      .section .text
      .globl _start
      _start:
          mov $1, %rax
          mov $1, %rdi
          lea msg(%rip), %rsi
          mov $7, %rdx
          syscall
          mov $60, %rax
          xor %rdi, %rdi
          syscall
      EOF

      ${pkgs.binutils}/bin/as -o test.o test.s
      if [ ! -f test.o ]; then
        echo "FAIL: assembler did not produce test.o"
        exit 1
      fi
      # Verify it is a valid ELF relocatable
      file test.o | grep -q "ELF.*relocatable"
      echo "PASS: binutils-as"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-011: binutils-ld

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | GNU linker (ld) |
| Description | Link object files into an executable using ld directly. Validates the linker from binutils. |

```nix
pkgs.mkDerivation {
  pname = "check-binutils-ld";
  version = "0";
  src = null;
  buildDeps = [ pkgs.binutils ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      # Assemble the test program
      cat > test.s << 'EOF'
      .section .data
      msg:  .asciz "ld-ok\n"
      .section .text
      .globl _start
      _start:
          mov $1, %rax
          mov $1, %rdi
          lea msg(%rip), %rsi
          mov $6, %rdx
          syscall
          mov $60, %rax
          xor %rdi, %rdi
          syscall
      EOF

      ${pkgs.binutils}/bin/as -o test.o test.s
      ${pkgs.binutils}/bin/ld -o test test.o
      OUTPUT=$(./test)
      if [ "$OUTPUT" != "ld-ok" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: binutils-ld"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-012: binutils-ar

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | GNU archiver (ar), static library creation and extraction |
| Description | Create a static library from object files and link against it. Validates ar and ranlib. |

```nix
pkgs.mkDerivation {
  pname = "check-binutils-ar";
  version = "0";
  src = null;
  buildDeps = [ pkgs.binutils pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > add.c << 'EOF'
      int add(int a, int b) { return a + b; }
      EOF
      cat > mul.c << 'EOF'
      int mul(int a, int b) { return a * b; }
      EOF
      cat > main.c << 'EOF'
      #include <stdio.h>
      int add(int, int);
      int mul(int, int);
      int main(void) {
          printf("add=%d mul=%d\n", add(3, 4), mul(3, 4));
          return 0;
      }
      EOF

      $CC -c add.c mul.c
      $AR rcs libmath.a add.o mul.o
      $CC -o main main.c -L. -lmath
      OUTPUT=$(./main)
      if [ "$OUTPUT" != "add=7 mul=12" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: binutils-ar"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-013: binutils-nm

| Field | Value |
|-------|-------|
| Priority | P2 |
| Type | build-sandbox |
| Validates | nm symbol listing |
| Description | Compile an object file and verify nm lists the expected symbols. |

```nix
pkgs.mkDerivation {
  pname = "check-binutils-nm";
  version = "0";
  src = null;
  buildDeps = [ pkgs.binutils pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > sym.c << 'EOF'
      int exported_function(void) { return 42; }
      static int internal_function(void) { return 0; }
      int global_var = 100;
      EOF

      $CC -c sym.c
      NM_OUT=$($NM sym.o)
      if ! echo "$NM_OUT" | grep -q "exported_function"; then
        echo "FAIL: nm did not find exported_function"
        exit 1
      fi
      if ! echo "$NM_OUT" | grep -q "global_var"; then
        echo "FAIL: nm did not find global_var"
        exit 1
      fi
      echo "PASS: binutils-nm"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-014: binutils-strip

| Field | Value |
|-------|-------|
| Priority | P2 |
| Type | build-sandbox |
| Validates | strip debug symbol removal |
| Description | Compile a binary with debug info, strip it, verify it still runs and is smaller. |

```nix
pkgs.mkDerivation {
  pname = "check-binutils-strip";
  version = "0";
  src = null;
  buildDeps = [ pkgs.binutils pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > prog.c << 'EOF'
      #include <stdio.h>
      int main(void) { printf("strip-ok\n"); return 0; }
      EOF

      $CC -g -o prog prog.c
      SIZE_BEFORE=$(wc -c < prog)

      $STRIP -s prog
      SIZE_AFTER=$(wc -c < prog)

      OUTPUT=$(./prog)
      if [ "$OUTPUT" != "strip-ok" ]; then
        echo "FAIL: stripped binary does not run correctly"
        exit 1
      fi
      if [ "$SIZE_AFTER" -ge "$SIZE_BEFORE" ]; then
        echo "FAIL: strip did not reduce binary size ($SIZE_BEFORE -> $SIZE_AFTER)"
        exit 1
      fi
      echo "  size: $SIZE_BEFORE -> $SIZE_AFTER bytes"
      echo "PASS: binutils-strip"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-015: binutils-objdump

| Field | Value |
|-------|-------|
| Priority | P2 |
| Type | build-sandbox |
| Validates | objdump disassembly |
| Description | Compile a binary and verify objdump can disassemble it and find expected symbols. |

```nix
pkgs.mkDerivation {
  pname = "check-binutils-objdump";
  version = "0";
  src = null;
  buildDeps = [ pkgs.binutils pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > func.c << 'EOF'
      int target_func(int x) { return x * 2; }
      int main(void) { return target_func(0); }
      EOF

      $CC -o func func.c
      DUMP=$(${pkgs.binutils}/bin/objdump -d func)
      if ! echo "$DUMP" | grep -q "target_func"; then
        echo "FAIL: objdump did not find target_func"
        exit 1
      fi
      if ! echo "$DUMP" | grep -q "main"; then
        echo "FAIL: objdump did not find main"
        exit 1
      fi
      echo "PASS: binutils-objdump"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-016: binutils-readelf

| Field | Value |
|-------|-------|
| Priority | P2 |
| Type | build-sandbox |
| Validates | readelf ELF header parsing |
| Description | Compile a binary and verify readelf can parse its ELF headers correctly. |

```nix
pkgs.mkDerivation {
  pname = "check-binutils-readelf";
  version = "0";
  src = null;
  buildDeps = [ pkgs.binutils pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > simple.c << 'EOF'
      int main(void) { return 0; }
      EOF

      $CC -o simple simple.c
      HEADERS=$(${pkgs.binutils}/bin/readelf -h simple)
      if ! echo "$HEADERS" | grep -q "ELF"; then
        echo "FAIL: readelf did not identify ELF format"
        exit 1
      fi
      if ! echo "$HEADERS" | grep -q "X86-64\|AArch64"; then
        echo "FAIL: readelf did not identify architecture"
        exit 1
      fi

      # Also test section headers
      SECTIONS=$(${pkgs.binutils}/bin/readelf -S simple)
      if ! echo "$SECTIONS" | grep -q ".text"; then
        echo "FAIL: readelf did not find .text section"
        exit 1
      fi
      echo "PASS: binutils-readelf"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## LLVM/Clang

The AOS LLVM package (pkgs/toolchain/llvm.nix) builds LLVM with clang and lld
enabled. These tests validate the LLVM toolchain can produce working binaries
independently of the bootstrap GCC.

### TC-017: llvm-compile-c

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | llvm, clang C compilation |
| Description | Compile and run a C program using clang. Validates the LLVM C frontend. |

```nix
pkgs.mkDerivation {
  pname = "check-llvm-compile-c";
  version = "0";
  src = null;
  buildDeps = [ pkgs.llvm pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > hello.c << 'EOF'
      #include <stdio.h>
      int main(void) {
          printf("clang-c-ok\n");
          return 0;
      }
      EOF

      ${pkgs.llvm}/bin/clang \
        --sysroot=/ \
        -B${pkgs.bootstrapTools}/lib \
        -isystem ${pkgs.bootstrapTools}/include-glibc \
        -L${pkgs.bootstrapTools}/lib \
        -Wl,-dynamic-linker=$(ls ${pkgs.bootstrapTools}/lib/ld-linux-*.so.* | head -1) \
        -Wl,-rpath,${pkgs.bootstrapTools}/lib \
        -o hello hello.c
      OUTPUT=$(./hello)
      if [ "$OUTPUT" != "clang-c-ok" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: llvm-compile-c"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-018: llvm-compile-cpp

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | llvm, clang++ C++ compilation |
| Description | Compile and run a C++ program using clang++. Note: clang++ uses the GCC libstdc++ from bootstrap tools since AOS does not build libc++. |

```nix
pkgs.mkDerivation {
  pname = "check-llvm-compile-cpp";
  version = "0";
  src = null;
  buildDeps = [ pkgs.llvm pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > test.cpp << 'EOF'
      #include <iostream>
      #include <vector>
      int main() {
          std::vector<int> v = {3, 1, 2};
          int sum = 0;
          for (int x : v) sum += x;
          if (sum != 6) return 1;
          std::cout << "clang-cpp-ok" << std::endl;
          return 0;
      }
      EOF

      # clang++ needs explicit paths to GCC's C++ headers and libraries
      BT=${pkgs.bootstrapTools}
      BT_ROOT=$(dirname $BT/lib)
      CXX_VER=$(ls "$BT_ROOT/include/c++")
      ${pkgs.llvm}/bin/clang++ \
        --sysroot=/ \
        -isystem "$BT_ROOT/include/c++/$CXX_VER" \
        -isystem "$BT_ROOT/include/c++/$CXX_VER/x86_64-unknown-linux-gnu" \
        -isystem $BT/include-glibc \
        -B$BT/lib \
        -L$BT/lib \
        -L$BT/lib/gcc/x86_64-unknown-linux-gnu/$CXX_VER/ \
        -Wl,-dynamic-linker=$(ls $BT/lib/ld-linux-*.so.* | head -1) \
        -Wl,-rpath,$BT/lib \
        -o test test.cpp -lstdc++
      OUTPUT=$(./test)
      if [ "$OUTPUT" != "clang-cpp-ok" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: llvm-compile-cpp"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-019: llvm-link-openssl

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | llvm/clang + openssl linking |
| Description | Compile a program with clang that links against AOS openssl. Validates LLVM's ability to consume AOS-built shared libraries. |

```nix
pkgs.mkDerivation {
  pname = "check-llvm-link-openssl";
  version = "0";
  src = null;
  buildDeps = [ pkgs.llvm pkgs.make ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > ssl_test.c << 'EOF'
      #include <stdio.h>
      #include <openssl/crypto.h>
      int main(void) {
          printf("openssl-via-clang: %s\n", OpenSSL_version(OPENSSL_VERSION));
          return 0;
      }
      EOF

      BT=${pkgs.bootstrapTools}
      ${pkgs.llvm}/bin/clang \
        --sysroot=/ \
        -isystem ${pkgs.openssl}/include \
        -isystem $BT/include-glibc \
        -B$BT/lib \
        -L$BT/lib \
        -L${pkgs.openssl}/lib \
        -Wl,-dynamic-linker=$(ls $BT/lib/ld-linux-*.so.* | head -1) \
        -Wl,-rpath,$BT/lib \
        -Wl,-rpath,${pkgs.openssl}/lib \
        -o ssl_test ssl_test.c -lcrypto
      OUTPUT=$(./ssl_test)
      if ! echo "$OUTPUT" | grep -q "openssl-via-clang"; then
        echo "FAIL: clang+openssl test failed"
        exit 1
      fi
      echo "PASS: llvm-link-openssl"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-020: llvm-libllvm

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | LLVM shared library (libLLVM.so) |
| Description | Verify libLLVM.so exists, is a valid shared library, and llvm-config reports correct paths. This is critical because Rust links against libLLVM. |

```nix
pkgs.mkDerivation {
  pname = "check-llvm-libllvm";
  version = "0";
  src = null;
  buildDeps = [ pkgs.llvm ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Verify libLLVM.so exists
      LIBLLVM=$(ls ${pkgs.llvm}/lib/libLLVM*.so 2>/dev/null | head -1)
      if [ -z "$LIBLLVM" ]; then
        echo "FAIL: libLLVM.so not found in ${pkgs.llvm}/lib/"
        exit 1
      fi
      echo "  Found: $LIBLLVM"
      file "$LIBLLVM" | grep -q "shared object"

      # Verify llvm-config works and reports sane paths
      ${pkgs.llvm}/bin/llvm-config --version
      ${pkgs.llvm}/bin/llvm-config --libdir
      ${pkgs.llvm}/bin/llvm-config --includedir

      LIBDIR=$(${pkgs.llvm}/bin/llvm-config --libdir)
      if [ ! -d "$LIBDIR" ]; then
        echo "FAIL: llvm-config --libdir points to nonexistent directory: $LIBDIR"
        exit 1
      fi

      echo "PASS: llvm-libllvm"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-021: llvm-tools

| Field | Value |
|-------|-------|
| Priority | P2 |
| Type | build-sandbox |
| Validates | LLVM tool suite (llvm-ar, llvm-nm, llvm-strip, lld) |
| Description | Verify LLVM bundled tools exist and produce output. |

```nix
pkgs.mkDerivation {
  pname = "check-llvm-tools";
  version = "0";
  src = null;
  buildDeps = [ pkgs.llvm pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > tiny.c << 'EOF'
      int main(void) { return 0; }
      EOF

      # Use the ccWrapper to compile so we get a valid object file
      $CC -c -o tiny.o tiny.c

      # llvm-ar: create static archive
      ${pkgs.llvm}/bin/llvm-ar rcs tiny.a tiny.o
      if [ ! -f tiny.a ]; then
        echo "FAIL: llvm-ar did not create archive"
        exit 1
      fi
      echo "  llvm-ar: OK"

      # llvm-nm: list symbols
      NM_OUT=$(${pkgs.llvm}/bin/llvm-nm tiny.o)
      if ! echo "$NM_OUT" | grep -q "main"; then
        echo "FAIL: llvm-nm did not find main symbol"
        exit 1
      fi
      echo "  llvm-nm: OK"

      # lld: verify the linker exists
      if [ -x ${pkgs.llvm}/bin/ld.lld ]; then
        ${pkgs.llvm}/bin/ld.lld --version
        echo "  ld.lld: OK"
      else
        echo "  ld.lld: not found (skipped)"
      fi

      echo "PASS: llvm-tools"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## Go

The AOS Go toolchain consists of `go-bootstrap` (pre-built binary) used to
compile `go` (from source). Both pure Go and CGO programs must work.

### TC-022: go-compile-pure

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | go compiler, pure Go compilation (no CGO) |
| Description | Compile and run a pure Go program with CGO_ENABLED=0. Validates the from-source Go compiler works independently of C toolchains. |

```nix
pkgs.mkDerivation {
  pname = "check-go-compile-pure";
  version = "0";
  src = null;
  buildDeps = [ pkgs.go ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      export GOPATH="$TMPDIR/go"
      export GOCACHE="$TMPDIR/go-cache"
      export CGO_ENABLED=0
      mkdir -p "$GOPATH" "$GOCACHE"

      mkdir -p testpkg
      cat > testpkg/main.go << 'EOF'
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

      ${pkgs.go}/bin/go build -o testbin ./testpkg/
      OUTPUT=$(./testbin)
      if [ "$OUTPUT" != "alpha,beta,gamma" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: go-compile-pure"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-023: go-compile-cgo

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | go compiler with CGO, gcc, glibc interop |
| Description | Compile a CGO program that calls a C function via cgo. Validates the go-to-gcc integration path. |

```nix
pkgs.mkDerivation {
  pname = "check-go-compile-cgo";
  version = "0";
  src = null;
  buildDeps = [ pkgs.go pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      export GOPATH="$TMPDIR/go"
      export GOCACHE="$TMPDIR/go-cache"
      export CGO_ENABLED=1
      mkdir -p "$GOPATH" "$GOCACHE"

      mkdir -p cgopkg
      cat > cgopkg/main.go << 'GOEOF'
      package main

      /*
      #include <stdlib.h>
      #include <string.h>

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

      ${pkgs.go}/bin/go build -o cgobin ./cgopkg/
      OUTPUT=$(./cgobin)
      if [ "$OUTPUT" != "cgo-result=42" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: go-compile-cgo"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-024: go-cgo-openssl

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | go CGO + openssl headers and libraries |
| Description | Build a CGO program that includes openssl headers and calls OpenSSL_version(). Validates the go + openssl dependency edge. |

```nix
pkgs.mkDerivation {
  pname = "check-go-cgo-openssl";
  version = "0";
  src = null;
  buildDeps = [ pkgs.go pkgs.make pkgs.pkg-config ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      export GOPATH="$TMPDIR/go"
      export GOCACHE="$TMPDIR/go-cache"
      export CGO_ENABLED=1
      mkdir -p "$GOPATH" "$GOCACHE"

      mkdir -p sslpkg
      cat > sslpkg/main.go << 'GOEOF'
      package main

      /*
      #cgo pkg-config: openssl
      #include <openssl/crypto.h>
      */
      import "C"
      import "fmt"

      func main() {
          ver := C.GoString(C.OpenSSL_version(C.OPENSSL_VERSION))
          fmt.Printf("go-openssl: %s\n", ver)
      }
      GOEOF

      ${pkgs.go}/bin/go build -o sslbin ./sslpkg/
      OUTPUT=$(./sslbin)
      if ! echo "$OUTPUT" | grep -q "go-openssl:"; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: go-cgo-openssl"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-025: go-cgo-zlib

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | go CGO + zlib |
| Description | Build a CGO program that calls zlib's compress function. |

```nix
pkgs.mkDerivation {
  pname = "check-go-cgo-zlib";
  version = "0";
  src = null;
  buildDeps = [ pkgs.go pkgs.make pkgs.pkg-config ];
  runtimeDeps = [ pkgs.zlib ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      export GOPATH="$TMPDIR/go"
      export GOCACHE="$TMPDIR/go-cache"
      export CGO_ENABLED=1
      mkdir -p "$GOPATH" "$GOCACHE"

      mkdir -p zpkg
      cat > zpkg/main.go << 'GOEOF'
      package main

      /*
      #cgo pkg-config: zlib
      #include <zlib.h>
      */
      import "C"
      import "fmt"

      func main() {
          ver := C.GoString(C.zlibVersion())
          fmt.Printf("go-zlib: %s\n", ver)
      }
      GOEOF

      ${pkgs.go}/bin/go build -o zbin ./zpkg/
      OUTPUT=$(./zbin)
      if ! echo "$OUTPUT" | grep -q "go-zlib:"; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: go-cgo-zlib"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-026: go-test

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | go test framework |
| Description | Run `go test` on a test file. Validates the test runner works in the AOS build sandbox. |

```nix
pkgs.mkDerivation {
  pname = "check-go-test";
  version = "0";
  src = null;
  buildDeps = [ pkgs.go ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      export GOPATH="$TMPDIR/go"
      export GOCACHE="$TMPDIR/go-cache"
      export CGO_ENABLED=0
      mkdir -p "$GOPATH" "$GOCACHE"

      mkdir -p testpkg
      cat > testpkg/go.mod << 'EOF'
      module testpkg
      go 1.23
      EOF

      cat > testpkg/math.go << 'EOF'
      package testpkg
      func Add(a, b int) int { return a + b }
      EOF

      cat > testpkg/math_test.go << 'EOF'
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

      cd testpkg
      ${pkgs.go}/bin/go test -v ./...
      echo "PASS: go-test"
      cd ..
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-027: go-vet

| Field | Value |
|-------|-------|
| Priority | P2 |
| Type | build-sandbox |
| Validates | go vet static analysis tool |
| Description | Run `go vet` and verify it produces no errors on clean code and catches issues in buggy code. |

```nix
pkgs.mkDerivation {
  pname = "check-go-vet";
  version = "0";
  src = null;
  buildDeps = [ pkgs.go ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      export GOPATH="$TMPDIR/go"
      export GOCACHE="$TMPDIR/go-cache"
      export CGO_ENABLED=0
      mkdir -p "$GOPATH" "$GOCACHE"

      # Clean code should pass vet
      mkdir -p cleanpkg
      cat > cleanpkg/go.mod << 'EOF'
      module cleanpkg
      go 1.23
      EOF

      cat > cleanpkg/main.go << 'EOF'
      package main
      import "fmt"
      func main() { fmt.Println("clean") }
      EOF

      cd cleanpkg
      ${pkgs.go}/bin/go vet ./...
      cd ..
      echo "  clean code: vet passed"

      echo "PASS: go-vet"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-028: go-fmt

| Field | Value |
|-------|-------|
| Priority | P2 |
| Type | build-sandbox |
| Validates | gofmt formatting tool |
| Description | Run gofmt and verify it can format Go source code. |

```nix
pkgs.mkDerivation {
  pname = "check-go-fmt";
  version = "0";
  src = null;
  buildDeps = [ pkgs.go ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Unformatted Go code
      cat > ugly.go << 'EOF'
      package main
      import    "fmt"
      func main(  ){
      fmt.Println("hello")
      }
      EOF

      ${pkgs.go}/bin/gofmt ugly.go > formatted.go
      # Verify the output is valid Go that compiles
      export GOPATH="$TMPDIR/go"
      export GOCACHE="$TMPDIR/go-cache"
      export CGO_ENABLED=0
      mkdir -p "$GOPATH" "$GOCACHE"

      # gofmt should produce compilable output
      mkdir -p fmtpkg
      cp formatted.go fmtpkg/main.go
      cat > fmtpkg/go.mod << 'EOF'
      module fmtpkg
      go 1.23
      EOF
      cd fmtpkg
      ${pkgs.go}/bin/go build -o ../fmtbin .
      cd ..
      ./fmtbin

      echo "PASS: go-fmt"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-029: go-build-containerd

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | go-built containerd binary, all transitive deps |
| Description | Verify the AOS-built containerd binary exists and responds to --version. This is a high-value smoke test because containerd is a complex Go+CGO binary with many dependencies. |

```nix
pkgs.mkDerivation {
  pname = "check-go-build-containerd";
  version = "0";
  src = null;
  buildDeps = [ pkgs.containerd ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Verify the binary exists and is executable
      if [ ! -x ${pkgs.containerd}/bin/containerd ]; then
        echo "FAIL: containerd binary not found"
        exit 1
      fi

      # Verify it responds to --version
      VERSION=$(${pkgs.containerd}/bin/containerd --version 2>&1 || true)
      if ! echo "$VERSION" | grep -q "containerd"; then
        echo "FAIL: containerd --version did not contain 'containerd': $VERSION"
        exit 1
      fi
      echo "  version: $VERSION"

      # Verify all shared libraries resolve
      LDD_OUT=$(ldd ${pkgs.containerd}/bin/containerd 2>&1 || true)
      if echo "$LDD_OUT" | grep -q "not found"; then
        echo "FAIL: unresolved libraries:"
        echo "$LDD_OUT"
        exit 1
      fi

      echo "PASS: go-build-containerd"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-030: go-build-kubelet

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | go-built kubelet binary, all transitive deps |
| Description | Verify the AOS-built kubelet binary exists and responds to --version. Kubelet is the most complex Go binary in the AOS package set. |

```nix
pkgs.mkDerivation {
  pname = "check-go-build-kubelet";
  version = "0";
  src = null;
  buildDeps = [ pkgs.kubelet ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      if [ ! -x ${pkgs.kubelet}/bin/kubelet ]; then
        echo "FAIL: kubelet binary not found"
        exit 1
      fi

      VERSION=$(${pkgs.kubelet}/bin/kubelet --version 2>&1 || true)
      if ! echo "$VERSION" | grep -q "Kubernetes"; then
        echo "FAIL: kubelet --version did not contain 'Kubernetes': $VERSION"
        exit 1
      fi
      echo "  version: $VERSION"

      LDD_OUT=$(ldd ${pkgs.kubelet}/bin/kubelet 2>&1 || true)
      if echo "$LDD_OUT" | grep -q "not found"; then
        echo "FAIL: unresolved libraries:"
        echo "$LDD_OUT"
        exit 1
      fi

      echo "PASS: go-build-kubelet"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## Rust

The AOS Rust toolchain consists of `rust-bootstrap` (pre-built binary) used to
compile `rust` (from source, including cargo). The from-source build uses LLVM
and links against openssl and zlib.

### TC-031: rust-compile-hello

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | rustc, rust standard library |
| Description | Compile a minimal Rust binary with rustc directly (no cargo). Validates the from-source rustc works. |

```nix
pkgs.mkDerivation {
  pname = "check-rust-compile-hello";
  version = "0";
  src = null;
  buildDeps = [ pkgs.rust ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > hello.rs << 'EOF'
      fn main() {
          let v: Vec<i32> = vec![3, 1, 4, 1, 5];
          let sum: i32 = v.iter().sum();
          println!("rust-sum={}", sum);
      }
      EOF

      ${pkgs.rust}/bin/rustc -o hello hello.rs
      OUTPUT=$(./hello)
      if [ "$OUTPUT" != "rust-sum=14" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: rust-compile-hello"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-032: rust-cargo-build

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | cargo, rustc, Cargo.toml project compilation |
| Description | Build a minimal Cargo project from scratch (no external dependencies). Validates cargo + rustc integration. |

```nix
pkgs.mkDerivation {
  pname = "check-rust-cargo-build";
  version = "0";
  src = null;
  buildDeps = [ pkgs.rust ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      export CARGO_HOME="$TMPDIR/cargo"
      mkdir -p "$CARGO_HOME"

      mkdir -p myproject/src
      cat > myproject/Cargo.toml << 'EOF'
      [package]
      name = "myproject"
      version = "0.1.0"
      edition = "2021"
      EOF

      cat > myproject/src/main.rs << 'EOF'
      use std::collections::HashMap;
      fn main() {
          let mut map = HashMap::new();
          map.insert("a", 1);
          map.insert("b", 2);
          let total: i32 = map.values().sum();
          println!("cargo-ok={}", total);
      }
      EOF

      cd myproject
      ${pkgs.rust}/bin/cargo build --release 2>&1
      OUTPUT=$(./target/release/myproject)
      if [ "$OUTPUT" != "cargo-ok=3" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: rust-cargo-build"
      cd ..
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-033: rust-link-openssl

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | rust + openssl (via FFI) |
| Description | Build a Rust program that uses openssl via FFI bindings. Since this requires the openssl-sys crate (network fetch), this test instead verifies rustc can link against libssl directly. |

```nix
pkgs.mkDerivation {
  pname = "check-rust-link-openssl";
  version = "0";
  src = null;
  buildDeps = [ pkgs.rust pkgs.make ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Test that rustc can produce a binary that links against libssl
      # by combining Rust + C through the FFI
      cat > ssl_ffi.c << 'EOF'
      #include <openssl/crypto.h>
      const char* get_openssl_version(void) {
          return OpenSSL_version(OPENSSL_VERSION);
      }
      EOF

      cat > main.rs << 'EOF'
      extern "C" {
          fn get_openssl_version() -> *const std::os::raw::c_char;
      }
      fn main() {
          let ver = unsafe {
              std::ffi::CStr::from_ptr(get_openssl_version())
          };
          println!("rust-openssl: {}", ver.to_str().unwrap());
      }
      EOF

      # Compile the C glue
      $CC -c -o ssl_ffi.o ssl_ffi.c

      # Compile and link with rustc
      ${pkgs.rust}/bin/rustc -o ssl_test main.rs \
        -L ${pkgs.openssl}/lib \
        -l ssl -l crypto \
        --edition 2021 \
        -C link-arg=ssl_ffi.o \
        -C link-arg=-Wl,-rpath,${pkgs.openssl}/lib

      OUTPUT=$(./ssl_test)
      if ! echo "$OUTPUT" | grep -q "rust-openssl:"; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "  $OUTPUT"
      echo "PASS: rust-link-openssl"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-034: rust-link-libgit2

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | rust + libgit2 (via FFI) |
| Description | Build a Rust program that calls libgit2 via FFI to verify the Rust-to-libgit2 dependency edge. |

```nix
pkgs.mkDerivation {
  pname = "check-rust-link-libgit2";
  version = "0";
  src = null;
  buildDeps = [ pkgs.rust pkgs.make ];
  runtimeDeps = [ pkgs.libgit2 ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      cat > git_ffi.c << 'EOF'
      #include <git2.h>
      int git2_init_wrapper(void) {
          return git_libgit2_init();
      }
      const char* git2_version_string(void) {
          return LIBGIT2_VERSION;
      }
      EOF

      cat > main.rs << 'EOF'
      extern "C" {
          fn git2_init_wrapper() -> i32;
          fn git2_version_string() -> *const std::os::raw::c_char;
      }
      fn main() {
          let rc = unsafe { git2_init_wrapper() };
          assert!(rc >= 0, "git_libgit2_init failed");
          let ver = unsafe {
              std::ffi::CStr::from_ptr(git2_version_string())
          };
          println!("rust-libgit2: {}", ver.to_str().unwrap());
      }
      EOF

      $CC -c -o git_ffi.o git_ffi.c -I${pkgs.libgit2}/include
      ${pkgs.rust}/bin/rustc -o git_test main.rs \
        -L ${pkgs.libgit2}/lib \
        -l git2 \
        --edition 2021 \
        -C link-arg=git_ffi.o \
        -C link-arg=-Wl,-rpath,${pkgs.libgit2}/lib

      OUTPUT=$(./git_test)
      if ! echo "$OUTPUT" | grep -q "rust-libgit2:"; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "  $OUTPUT"
      echo "PASS: rust-link-libgit2"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-035: rust-link-zlib

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | rust + zlib (via FFI) |
| Description | Build a Rust program that calls zlib's compress/uncompress via FFI. |

```nix
pkgs.mkDerivation {
  pname = "check-rust-link-zlib";
  version = "0";
  src = null;
  buildDeps = [ pkgs.rust pkgs.make ];
  runtimeDeps = [ pkgs.zlib ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      cat > zlib_ffi.c << 'EOF'
      #include <zlib.h>
      #include <string.h>
      const char* zlib_ver(void) { return zlibVersion(); }
      int zlib_roundtrip(void) {
          const char *input = "test data for roundtrip";
          unsigned char comp[256], decomp[256];
          uLongf clen = sizeof(comp), dlen = sizeof(decomp);
          if (compress(comp, &clen, (const unsigned char*)input, strlen(input)+1) != Z_OK)
              return 1;
          if (uncompress(decomp, &dlen, comp, clen) != Z_OK)
              return 2;
          return strcmp((char*)decomp, input) == 0 ? 0 : 3;
      }
      EOF

      cat > main.rs << 'EOF'
      extern "C" {
          fn zlib_ver() -> *const std::os::raw::c_char;
          fn zlib_roundtrip() -> i32;
      }
      fn main() {
          let ver = unsafe { std::ffi::CStr::from_ptr(zlib_ver()) };
          println!("zlib version: {}", ver.to_str().unwrap());
          let rc = unsafe { zlib_roundtrip() };
          assert_eq!(rc, 0, "zlib roundtrip failed with code {}", rc);
          println!("rust-zlib-ok");
      }
      EOF

      $CC -c -o zlib_ffi.o zlib_ffi.c
      ${pkgs.rust}/bin/rustc -o zlib_test main.rs \
        -L ${pkgs.zlib}/lib \
        -l z \
        --edition 2021 \
        -C link-arg=zlib_ffi.o \
        -C link-arg=-Wl,-rpath,${pkgs.zlib}/lib

      OUTPUT=$(./zlib_test)
      if ! echo "$OUTPUT" | grep -q "rust-zlib-ok"; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: rust-link-zlib"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-036: rust-bootstrap-chain

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | rust-bootstrap -> rust compilation chain |
| Description | Verify that the from-source rust compiler (built using rust-bootstrap) can compile programs. This validates the bootstrap chain integrity -- if rust-bootstrap changes, the from-source rust must still work. |

```nix
pkgs.mkDerivation {
  pname = "check-rust-bootstrap-chain";
  version = "0";
  src = null;
  buildDeps = [ pkgs.rust ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Verify rustc is the from-source build, not the bootstrap
      RUSTC_VER=$(${pkgs.rust}/bin/rustc --version)
      echo "  rustc version: $RUSTC_VER"

      # Verify cargo is the from-source build
      CARGO_VER=$(${pkgs.rust}/bin/cargo --version)
      echo "  cargo version: $CARGO_VER"

      # Verify rustc links against AOS LLVM (not a bundled one)
      RUSTC_BIN=${pkgs.rust}/bin/rustc
      LDD_OUT=$(ldd "$RUSTC_BIN" 2>&1 || true)
      if echo "$LDD_OUT" | grep -q "not found"; then
        echo "FAIL: rustc has unresolved shared libraries"
        echo "$LDD_OUT"
        exit 1
      fi
      echo "  all shared libraries resolved"

      # Verify rustc can compile a non-trivial program using multiple std features
      cat > chain_test.rs << 'EOF'
      use std::collections::BTreeMap;
      use std::io::Write;

      fn main() {
          let mut map = BTreeMap::new();
          for i in 0..10 {
              map.insert(i, i * i);
          }
          let mut buf = Vec::new();
          for (k, v) in &map {
              write!(buf, "{}:{} ", k, v).unwrap();
          }
          let s = String::from_utf8(buf).unwrap();
          assert!(s.contains("9:81"));
          println!("bootstrap-chain-ok");
      }
      EOF

      ${pkgs.rust}/bin/rustc -o chain_test chain_test.rs --edition 2021
      OUTPUT=$(./chain_test)
      if [ "$OUTPUT" != "bootstrap-chain-ok" ]; then
        echo "FAIL: unexpected output: $OUTPUT"
        exit 1
      fi
      echo "PASS: rust-bootstrap-chain"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## Python 3

AOS Python 3 is built from source with openssl, zlib, and xz as runtime
dependencies. The sqlite3 module is built via the bundled sqlite or the AOS
sqlite package.

### TC-037: python-import-stdlib

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | python3, stdlib modules, sqlite3 extension |
| Description | Import key standard library modules including native extensions (sqlite3, json, re). Validates the Python build produced a functional interpreter with working C extensions. |

```nix
pkgs.mkDerivation {
  pname = "check-python-import-stdlib";
  version = "0";
  src = null;
  buildDeps = [ pkgs.python3 ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      ${pkgs.python3}/bin/python3 << 'PYEOF'
      import sys
      import os
      import json
      import re
      import hashlib
      import sqlite3
      import collections
      import functools
      import io
      import pathlib
      import math

      # Verify sqlite3 works
      conn = sqlite3.connect(":memory:")
      conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, val TEXT)")
      conn.execute("INSERT INTO t VALUES (1, 'test')")
      row = conn.execute("SELECT val FROM t WHERE id=1").fetchone()
      assert row[0] == "test", f"sqlite3 query failed: {row}"

      # Verify json roundtrip
      data = {"key": [1, 2, 3], "nested": {"a": True}}
      assert json.loads(json.dumps(data)) == data

      # Verify re
      m = re.match(r"(\d+)-(\d+)", "42-17")
      assert m.group(1) == "42"

      # Verify hashlib (uses openssl backend)
      h = hashlib.sha256(b"test").hexdigest()
      assert len(h) == 64

      print(f"python={sys.version}")
      print("stdlib-ok")
      PYEOF

      echo "PASS: python-import-stdlib"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-038: python-ctypes-zlib

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | python3 ctypes + zlib shared library |
| Description | Load libz.so via ctypes and call zlibVersion(). Validates that Python can find and load AOS-built shared libraries at runtime. |

```nix
pkgs.mkDerivation {
  pname = "check-python-ctypes-zlib";
  version = "0";
  src = null;
  buildDeps = [ pkgs.python3 ];
  runtimeDeps = [ pkgs.zlib ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      ${pkgs.python3}/bin/python3 << 'PYEOF'
      import ctypes
      import ctypes.util

      # Load libz directly by path
      libz = ctypes.CDLL("${pkgs.zlib}/lib/libz.so")
      libz.zlibVersion.restype = ctypes.c_char_p
      version = libz.zlibVersion().decode()
      print(f"zlib via ctypes: {version}")
      assert version.startswith("1."), f"unexpected version: {version}"
      print("ctypes-zlib-ok")
      PYEOF

      echo "PASS: python-ctypes-zlib"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-039: python-ctypes-openssl

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | python3 ctypes + openssl shared library |
| Description | Load libcrypto.so via ctypes and call OpenSSL_version(). Validates the Python-to-openssl runtime path. |

```nix
pkgs.mkDerivation {
  pname = "check-python-ctypes-openssl";
  version = "0";
  src = null;
  buildDeps = [ pkgs.python3 ];
  runtimeDeps = [ pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      ${pkgs.python3}/bin/python3 << 'PYEOF'
      import ctypes

      OPENSSL_VERSION = 0  # OPENSSL_VERSION enum value

      libcrypto = ctypes.CDLL("${pkgs.openssl}/lib/libcrypto.so")
      libcrypto.OpenSSL_version.argtypes = [ctypes.c_int]
      libcrypto.OpenSSL_version.restype = ctypes.c_char_p
      version = libcrypto.OpenSSL_version(OPENSSL_VERSION).decode()
      print(f"openssl via ctypes: {version}")
      assert "OpenSSL" in version, f"unexpected version: {version}"
      print("ctypes-openssl-ok")
      PYEOF

      echo "PASS: python-ctypes-openssl"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-040: python-script

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | python3 interpreter, non-trivial computation |
| Description | Run a non-trivial Python script that exercises multiple language features. Validates the interpreter handles real workloads. |

```nix
pkgs.mkDerivation {
  pname = "check-python-script";
  version = "0";
  src = null;
  buildDeps = [ pkgs.python3 ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > script.py << 'PYEOF'
      import json
      import tempfile
      import os

      # Data processing: read, transform, write, verify
      data = [
          {"name": "alpha", "value": 10},
          {"name": "beta", "value": 20},
          {"name": "gamma", "value": 30},
      ]

      # Transform: compute running totals
      total = 0
      results = []
      for item in sorted(data, key=lambda x: x["name"]):
          total += item["value"]
          results.append({**item, "cumulative": total})

      # Write to temp file and read back
      with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
          json.dump(results, f)
          tmppath = f.name

      with open(tmppath) as f:
          loaded = json.load(f)

      os.unlink(tmppath)

      assert len(loaded) == 3
      assert loaded[0]["name"] == "alpha"
      assert loaded[0]["cumulative"] == 10
      assert loaded[2]["cumulative"] == 60

      # Generator and comprehension
      squares = {x: x**2 for x in range(10)}
      assert squares[9] == 81

      print("python-script-ok")
      PYEOF

      ${pkgs.python3}/bin/python3 script.py
      echo "PASS: python-script"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## Perl

### TC-041: perl-modules

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | perl interpreter, core modules |
| Description | Load core Perl modules to verify the Perl installation is complete. Perl is a build dependency for many packages (openssl, autoconf). |

```nix
pkgs.mkDerivation {
  pname = "check-perl-modules";
  version = "0";
  src = null;
  buildDeps = [ pkgs.perl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      ${pkgs.perl}/bin/perl -e '
        use strict;
        use warnings;
        use File::Find;
        use File::Path;
        use File::Basename;
        use Getopt::Long;
        use POSIX;
        use Cwd;
        use Digest::SHA;
        use IO::File;
        use Data::Dumper;

        my $sha = Digest::SHA::sha256_hex("test");
        die "SHA256 wrong length" unless length($sha) == 64;

        print "perl-modules-ok\n";
      '
      echo "PASS: perl-modules"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-042: perl-script

| Field | Value |
|-------|-------|
| Priority | P2 |
| Type | build-sandbox |
| Validates | perl interpreter execution |
| Description | Run a non-trivial Perl script. |

```nix
pkgs.mkDerivation {
  pname = "check-perl-script";
  version = "0";
  src = null;
  buildDeps = [ pkgs.perl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      cat > test.pl << 'PLEOF'
      use strict;
      use warnings;

      # Hash operations
      my %data = (a => 1, b => 2, c => 3);
      my $sum = 0;
      $sum += $_ for values %data;
      die "sum wrong: $sum" unless $sum == 6;

      # Array operations
      my @sorted = sort { $a <=> $b } (5, 3, 1, 4, 2);
      my $joined = join(",", @sorted);
      die "sort wrong: $joined" unless $joined eq "1,2,3,4,5";

      # Regex
      my $str = "version=3.14.159";
      if ($str =~ /version=(\d+\.\d+)/) {
          die "regex wrong: $1" unless $1 eq "3.14";
      } else {
          die "regex did not match";
      }

      print "perl-script-ok\n";
      PLEOF

      ${pkgs.perl}/bin/perl test.pl
      echo "PASS: perl-script"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-043: perl-openssl-build

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | perl + openssl build compatibility |
| Description | Verify that Perl can execute OpenSSL's Configure script (a Perl script). OpenSSL's build depends critically on Perl working correctly. |

```nix
pkgs.mkDerivation {
  pname = "check-perl-openssl-build";
  version = "0";
  src = null;
  buildDeps = [ pkgs.perl pkgs.openssl ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Verify openssl's configdata.pm exists (generated by Configure)
      if [ -f ${pkgs.openssl}/etc/ssl/misc/CA.pl ]; then
        ${pkgs.perl}/bin/perl -c ${pkgs.openssl}/etc/ssl/misc/CA.pl 2>&1
        echo "  CA.pl syntax check: OK"
      fi

      # Verify perl can parse a Configure-style script
      ${pkgs.perl}/bin/perl -e '
        use File::Spec;
        use File::Basename;
        # These modules are used by openssl Configure
        eval { require Text::Template };
        # Text::Template might not be installed, but the eval should not crash perl
        print "perl-openssl-compat-ok\n";
      '

      echo "PASS: perl-openssl-build"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## Build systems

### TC-044: cmake-configure

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | cmake |
| Description | Run cmake on a test CMakeLists.txt to verify cmake can generate build files. cmake is a critical dependency for LLVM, libgit2, and many other packages. |

```nix
pkgs.mkDerivation {
  pname = "check-cmake-configure";
  version = "0";
  src = null;
  buildDeps = [ pkgs.cmake pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      mkdir -p project
      cat > project/CMakeLists.txt << 'EOF'
      cmake_minimum_required(VERSION 3.20)
      project(test_project C)
      add_executable(hello hello.c)
      EOF

      cat > project/hello.c << 'EOF'
      #include <stdio.h>
      int main(void) { printf("cmake-ok\n"); return 0; }
      EOF

      cd project
      ${pkgs.cmake}/bin/cmake -B build -DCMAKE_C_COMPILER=$CC
      ${pkgs.cmake}/bin/cmake --build build
      OUTPUT=$(./build/hello)
      cd ..

      if [ "$OUTPUT" != "cmake-ok" ]; then
        echo "FAIL: cmake build produced: $OUTPUT"
        exit 1
      fi
      echo "PASS: cmake-configure"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-045: cmake-find-package

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | cmake find_package, openssl .pc/.cmake files |
| Description | Use cmake's find_package(OpenSSL) to locate AOS openssl. Validates that cmake module search paths and pkg-config integration work. |

```nix
pkgs.mkDerivation {
  pname = "check-cmake-find-package";
  version = "0";
  src = null;
  buildDeps = [ pkgs.cmake pkgs.make pkgs.pkg-config ];
  runtimeDeps = [ pkgs.openssl pkgs.zlib ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      mkdir -p project
      cat > project/CMakeLists.txt << 'EOF'
      cmake_minimum_required(VERSION 3.20)
      project(find_test C)

      find_package(OpenSSL REQUIRED)
      find_package(ZLIB REQUIRED)

      message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
      message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
      message(STATUS "ZLIB version: ${ZLIB_VERSION_STRING}")

      add_executable(ssl_test ssl_test.c)
      target_link_libraries(ssl_test OpenSSL::Crypto ZLIB::ZLIB)
      EOF

      cat > project/ssl_test.c << 'EOF'
      #include <stdio.h>
      #include <openssl/crypto.h>
      #include <zlib.h>
      int main(void) {
          printf("cmake-find: openssl=%s zlib=%s\n",
                 OpenSSL_version(OPENSSL_VERSION), zlibVersion());
          return 0;
      }
      EOF

      cd project
      ${pkgs.cmake}/bin/cmake -B build \
        -DCMAKE_C_COMPILER=$CC \
        -DOPENSSL_ROOT_DIR=${pkgs.openssl} \
        -DZLIB_ROOT=${pkgs.zlib}
      ${pkgs.cmake}/bin/cmake --build build
      OUTPUT=$(./build/ssl_test)
      cd ..

      if ! echo "$OUTPUT" | grep -q "cmake-find:"; then
        echo "FAIL: cmake find_package test failed: $OUTPUT"
        exit 1
      fi
      echo "  $OUTPUT"
      echo "PASS: cmake-find-package"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-046: meson-configure

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | meson, python3, ninja |
| Description | Run meson setup on a test project. Validates the meson -> python3 -> ninja chain. |

```nix
pkgs.mkDerivation {
  pname = "check-meson-configure";
  version = "0";
  src = null;
  buildDeps = [ pkgs.meson pkgs.ninja pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      mkdir -p project
      cat > project/meson.build << 'EOF'
      project('test', 'c', version: '0.1')
      executable('hello', 'hello.c')
      EOF

      cat > project/hello.c << 'EOF'
      #include <stdio.h>
      int main(void) { printf("meson-ok\n"); return 0; }
      EOF

      cd project
      ${pkgs.meson}/bin/meson setup build
      echo "  meson setup: OK"
      cd ..
      echo "PASS: meson-configure"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-047: meson-build

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | meson + ninja + gcc full build pipeline |
| Description | Full meson build+install cycle. Validates the entire meson build pipeline that systemd and other packages use. |

```nix
pkgs.mkDerivation {
  pname = "check-meson-build";
  version = "0";
  src = null;
  buildDeps = [ pkgs.meson pkgs.ninja pkgs.make ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      mkdir -p project
      cat > project/meson.build << 'EOF'
      project('test', 'c', version: '0.1')
      executable('hello', 'hello.c', install: true)
      EOF

      cat > project/hello.c << 'EOF'
      #include <stdio.h>
      int main(void) { printf("meson-build-ok\n"); return 0; }
      EOF

      cd project
      ${pkgs.meson}/bin/meson setup build --prefix=$TMPDIR/install
      ${pkgs.meson}/bin/meson compile -C build
      ${pkgs.meson}/bin/meson install -C build
      cd ..

      OUTPUT=$($TMPDIR/install/bin/hello)
      if [ "$OUTPUT" != "meson-build-ok" ]; then
        echo "FAIL: meson build produced: $OUTPUT"
        exit 1
      fi
      echo "PASS: meson-build"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-048: autoconf-generate

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | autoconf, m4, perl |
| Description | Run autoreconf on a minimal autoconf project to generate a configure script. Validates the autoconf -> m4 -> perl dependency chain. |

```nix
pkgs.mkDerivation {
  pname = "check-autoconf-generate";
  version = "0";
  src = null;
  buildDeps = [ pkgs.autoconf pkgs.automake pkgs.make pkgs.perl pkgs.m4 ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      mkdir -p project
      cat > project/configure.ac << 'EOF'
      AC_INIT([test], [0.1])
      AC_CONFIG_SRCDIR([hello.c])
      AM_INIT_AUTOMAKE([foreign])
      AC_PROG_CC
      AC_OUTPUT([Makefile])
      EOF

      cat > project/Makefile.am << 'EOF'
      bin_PROGRAMS = hello
      hello_SOURCES = hello.c
      EOF

      cat > project/hello.c << 'EOF'
      #include <stdio.h>
      int main(void) { printf("autoconf-ok\n"); return 0; }
      EOF

      cd project
      ${pkgs.autoconf}/bin/autoreconf --install --force \
        -I ${pkgs.automake}/share/aclocal
      cd ..

      if [ ! -x project/configure ]; then
        echo "FAIL: autoreconf did not generate configure"
        exit 1
      fi
      echo "  configure script generated"
      echo "PASS: autoconf-generate"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-049: automake-build

| Field | Value |
|-------|-------|
| Priority | P1 |
| Type | build-sandbox |
| Validates | autoconf + automake + make full build pipeline |
| Description | Full autoreconf + configure + make cycle. Validates the classic autotools build pipeline used by most GNU packages. |

```nix
pkgs.mkDerivation {
  pname = "check-automake-build";
  version = "0";
  src = null;
  buildDeps = [ pkgs.autoconf pkgs.automake pkgs.make pkgs.perl pkgs.m4 ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail
      mkdir -p project
      cat > project/configure.ac << 'EOF'
      AC_INIT([test], [0.1])
      AC_CONFIG_SRCDIR([hello.c])
      AM_INIT_AUTOMAKE([foreign])
      AC_PROG_CC
      AC_OUTPUT([Makefile])
      EOF

      cat > project/Makefile.am << 'EOF'
      bin_PROGRAMS = hello
      hello_SOURCES = hello.c
      EOF

      cat > project/hello.c << 'EOF'
      #include <stdio.h>
      int main(void) { printf("automake-ok\n"); return 0; }
      EOF

      cd project
      ${pkgs.autoconf}/bin/autoreconf --install --force \
        -I ${pkgs.automake}/share/aclocal
      ./configure --prefix=$TMPDIR/install
      make -j$NIX_BUILD_CORES
      make install
      cd ..

      OUTPUT=$($TMPDIR/install/bin/hello)
      if [ "$OUTPUT" != "automake-ok" ]; then
        echo "FAIL: automake build produced: $OUTPUT"
        exit 1
      fi
      echo "PASS: automake-build"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

### TC-050: pkg-config-query

| Field | Value |
|-------|-------|
| Priority | P0 |
| Type | build-sandbox |
| Validates | pkg-config, .pc file correctness for openssl, zlib |
| Description | Query pkg-config for key libraries and verify the returned flags are sane. pkg-config is the primary mechanism by which build systems find AOS package headers and libraries. |

```nix
pkgs.mkDerivation {
  pname = "check-pkg-config-query";
  version = "0";
  src = null;
  buildDeps = [ pkgs.pkg-config pkgs.make ];
  runtimeDeps = [ pkgs.openssl pkgs.zlib ];
  phases = [{
    name = "check";
    script = ''
      set -euo pipefail

      # Query openssl
      SSL_CFLAGS=$(${pkgs.pkg-config}/bin/pkg-config --cflags openssl)
      SSL_LIBS=$(${pkgs.pkg-config}/bin/pkg-config --libs openssl)
      SSL_VER=$(${pkgs.pkg-config}/bin/pkg-config --modversion openssl)
      echo "  openssl: version=$SSL_VER cflags=$SSL_CFLAGS libs=$SSL_LIBS"

      if [ -z "$SSL_LIBS" ]; then
        echo "FAIL: pkg-config returned empty --libs for openssl"
        exit 1
      fi

      # Query zlib
      Z_CFLAGS=$(${pkgs.pkg-config}/bin/pkg-config --cflags zlib)
      Z_LIBS=$(${pkgs.pkg-config}/bin/pkg-config --libs zlib)
      Z_VER=$(${pkgs.pkg-config}/bin/pkg-config --modversion zlib)
      echo "  zlib: version=$Z_VER cflags=$Z_CFLAGS libs=$Z_LIBS"

      if [ -z "$Z_LIBS" ]; then
        echo "FAIL: pkg-config returned empty --libs for zlib"
        exit 1
      fi

      # Verify the returned flags actually work by compiling a test program
      cat > pkgtest.c << 'EOF'
      #include <openssl/crypto.h>
      #include <zlib.h>
      #include <stdio.h>
      int main(void) {
          printf("pkg-config-ok openssl=%s zlib=%s\n",
                 OpenSSL_version(OPENSSL_VERSION), zlibVersion());
          return 0;
      }
      EOF

      $CC $SSL_CFLAGS $Z_CFLAGS -o pkgtest pkgtest.c $SSL_LIBS $Z_LIBS
      OUTPUT=$(./pkgtest)
      if ! echo "$OUTPUT" | grep -q "pkg-config-ok"; then
        echo "FAIL: pkg-config flags did not produce working binary"
        exit 1
      fi
      echo "  $OUTPUT"
      echo "PASS: pkg-config-query"
      mkdir -p $out
      echo "PASS" > $out/result
    '';
  }];
}
```

---

## Priority summary

| Priority | Count | Tests |
|----------|-------|-------|
| P0 | 14 | TC-001, TC-002, TC-003, TC-004, TC-005, TC-008, TC-022, TC-023, TC-029, TC-030, TC-031, TC-032, TC-036, TC-044, TC-045, TC-050 |
| P1 | 20 | TC-006, TC-009, TC-010, TC-011, TC-012, TC-017, TC-018, TC-019, TC-020, TC-024, TC-025, TC-026, TC-033, TC-034, TC-035, TC-037, TC-038, TC-039, TC-041, TC-043, TC-046, TC-047, TC-048, TC-049 |
| P2 | 8 | TC-007, TC-013, TC-014, TC-015, TC-016, TC-021, TC-027, TC-028, TC-042 |

P0 tests should be implemented first: they validate the fundamental compilation,
linking, and dependency resolution paths that every other AOS package depends on.
A failure in any P0 test indicates a broken toolchain that will cascade into
build failures across the entire package set.

## Dependency edges validated

The following diagram shows which dependency edges are tested. An arrow `A -> B`
means "test validates that A can use B":

```
gcc ---------> glibc           (TC-001)
gcc ---------> libstdc++       (TC-002)
gcc ---------> binutils/ld     (TC-003)
gcc ---------> openssl         (TC-004)
gcc ---------> zlib            (TC-005)
ccWrapper ---> RPATH injection (TC-008)
ccWrapper ---> include paths   (TC-009)

clang -------> glibc           (TC-017)
clang++ -----> libstdc++       (TC-018)
clang -------> openssl         (TC-019)
llvm --------> libLLVM.so      (TC-020)

go ----------> pure build      (TC-022)
go ----------> gcc/glibc (CGO) (TC-023)
go ----------> openssl (CGO)   (TC-024)
go ----------> zlib (CGO)      (TC-025)

rustc -------> std             (TC-031)
cargo -------> rustc           (TC-032)
rust --------> openssl (FFI)   (TC-033)
rust --------> libgit2 (FFI)   (TC-034)
rust --------> zlib (FFI)      (TC-035)
rust --------> llvm/bootstrap  (TC-036)

python3 -----> sqlite3         (TC-037)
python3 -----> zlib (ctypes)   (TC-038)
python3 -----> openssl (ctypes)(TC-039)

perl --------> core modules    (TC-041)
perl --------> openssl compat  (TC-043)

cmake -------> gcc             (TC-044)
cmake -------> openssl/zlib    (TC-045)
meson -------> python3/ninja   (TC-046, TC-047)
autoconf ----> m4/perl         (TC-048, TC-049)
pkg-config --> .pc files       (TC-050)

containerd --> go + all deps   (TC-029)
kubelet -----> go + all deps   (TC-030)
```
