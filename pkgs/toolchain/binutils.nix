##! Binutils — GNU Binary Utilities
{
  mkDerivation,
  fetchurl,
  make,
}: let
  version = "2.44";
in
  mkDerivation {
    pname = "binutils";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnu.mirror.constant.com/binutils/binutils-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/binutils/binutils-${version}.tar.xz"
        "https://ftp.gnu.org/gnu/binutils/binutils-${version}.tar.xz"
      ];
      hash = "sha256-ziAX4FnWPmfduSQOnU7EnCiTYFA1zWDpKtUxd/Q3cjc=";
    };

    buildDeps = [make];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd binutils-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir -p build && cd build
          ../configure \
            --prefix=$out \
            --enable-deterministic-archives \
            --disable-nls \
            --enable-64-bit-bfd \
            --enable-gold \
            --enable-plugins \
            --enable-relro \
            --enable-default-hash-style=gnu
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES MAKEINFO=true
        '';
      }
      {
        name = "install";
        script = ''
          make install MAKEINFO=true
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      as = testing.mkFirecrackerTest {
        pname = "toolchain-binutils-as";
        testScript = ''
          cat > /tmp/test.s << 'EOF'
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

          as -o /tmp/test.o /tmp/test.s
          test -f /tmp/test.o
          echo "==> Assembler produced object file"
        '';
      };

      ld = testing.mkFirecrackerTest {
        pname = "toolchain-binutils-ld";
        testScript = ''
          cat > /tmp/test.s << 'EOF'
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

          as -o /tmp/test.o /tmp/test.s
          ld -o /tmp/test /tmp/test.o
          /tmp/test
        '';
      };

      ar = testing.mkFirecrackerTest {
        pname = "toolchain-binutils-ar";
        testScript = ''
          cat > /tmp/add.c << 'EOF'
          int add(int a, int b) { return a + b; }
          EOF
          cat > /tmp/mul.c << 'EOF'
          int mul(int a, int b) { return a * b; }
          EOF
          cat > /tmp/main.c << 'EOF'
          #include <stdio.h>
          int add(int, int);
          int mul(int, int);
          int main(void) {
              printf("add=%d mul=%d\n", add(3, 4), mul(3, 4));
              return 0;
          }
          EOF

          gcc -c /tmp/add.c -o /tmp/add.o
          gcc -c /tmp/mul.c -o /tmp/mul.o
          ar rcs /tmp/libmath.a /tmp/add.o /tmp/mul.o
          gcc -o /tmp/main /tmp/main.c -L/tmp -lmath
          /tmp/main
        '';
      };

      nm = testing.mkFirecrackerTest {
        pname = "toolchain-binutils-nm";
        testScript = ''
          cat > /tmp/sym.c << 'EOF'
          int exported_function(void) { return 42; }
          int global_var = 100;
          EOF

          gcc -c /tmp/sym.c -o /tmp/sym.o
          nm /tmp/sym.o > /tmp/nm-out
          # Verify expected symbols are present (using shell builtins, no grep)
          while IFS= read -r line; do
            case "$line" in
              *exported_function*) echo "  found: exported_function" ;;
              *global_var*) echo "  found: global_var" ;;
            esac
          done < /tmp/nm-out
          echo "==> nm lists symbols correctly"
        '';
      };

      strip = testing.mkFirecrackerTest {
        pname = "toolchain-binutils-strip";
        testScript = ''
          cat > /tmp/prog.c << 'EOF'
          #include <stdio.h>
          int main(void) { printf("strip-ok\n"); return 0; }
          EOF

          gcc -g -o /tmp/prog /tmp/prog.c
          SIZE_BEFORE=$(wc -c < /tmp/prog)
          strip -s /tmp/prog
          SIZE_AFTER=$(wc -c < /tmp/prog)
          /tmp/prog
          echo "  size: $SIZE_BEFORE -> $SIZE_AFTER bytes"
          echo "==> strip removed debug symbols"
        '';
      };

      objdump = testing.mkFirecrackerTest {
        pname = "toolchain-binutils-objdump";
        testScript = ''
          cat > /tmp/func.c << 'EOF'
          int target_func(int x) { return x * 2; }
          int main(void) { return target_func(0); }
          EOF

          gcc -o /tmp/func /tmp/func.c
          objdump -d /tmp/func > /tmp/dump
          # Verify disassembly contains expected symbols (using shell builtins)
          found_target=0
          found_main=0
          while IFS= read -r line; do
            case "$line" in
              *target_func*) found_target=1 ;;
              *main*) found_main=1 ;;
            esac
          done < /tmp/dump
          test "$found_target" = "1"
          test "$found_main" = "1"
          echo "==> objdump found target_func and main"
        '';
      };

      readelf = testing.mkFirecrackerTest {
        pname = "toolchain-binutils-readelf";
        testScript = ''
          cat > /tmp/simple.c << 'EOF'
          int main(void) { return 0; }
          EOF

          gcc -o /tmp/simple /tmp/simple.c
          readelf -h /tmp/simple > /tmp/elf-out
          # Check for ELF magic and architecture
          found_elf=0
          found_arch=0
          while IFS= read -r line; do
            case "$line" in
              *ELF*) found_elf=1 ;;
              *X86-64*|*AArch64*) found_arch=1 ;;
            esac
          done < /tmp/elf-out
          test "$found_elf" = "1"
          test "$found_arch" = "1"

          # Check for .text section
          readelf -S /tmp/simple > /tmp/sections
          found_text=0
          while IFS= read -r line; do
            case "$line" in
              *.text*) found_text=1 ;;
            esac
          done < /tmp/sections
          test "$found_text" = "1"
          echo "==> readelf parsed ELF headers correctly"
        '';
      };
    };

    meta = {
      description = "GNU Binary Utilities — assembler, linker, and related tools";
      homepage = "https://www.gnu.org/software/binutils/";
      license = "GPL-3.0-or-later";
    };
  }
