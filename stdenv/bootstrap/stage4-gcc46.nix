# stdenv/bootstrap/stage4-gcc46.nix — GCC 4.6.4 compiled by TinyCC
#
# GCC 4.6.4 is the first "real" optimizing compiler in the bootstrap chain.
# It is C-only (no C++, no Fortran) because TinyCC cannot compile the
# C++ frontend.
#
# This is a critical transition: from TinyCC (a simple single-pass compiler)
# to GCC (a full optimizing compiler with proper register allocation,
# instruction scheduling, and optimization passes).
#
# GCC 4.6.4 is chosen because:
#   - It is the last GCC version that can be compiled by TinyCC (with patches)
#   - It supports enough of the C standard to build modern GCC
#   - It has been proven to work in the live-bootstrap chain
#
# Dependencies built alongside GCC 4.6.4:
#   - A minimal glibc (or musl) for libc
#   - GNU binutils for as, ld
#   - GNU make (for building GCC itself)
#
{
  tinycc, # Output of stage3-tinycc.nix
  mescc-tools, # Output of stage1-mescc-tools.nix (for M1, hex2 if needed)
  sources, # Attrset with: gcc464-source, binutils-source, glibc-source, make-source
  system ? "x86_64-linux",
}: let
  version = "4.6.4";

  archParams =
    if system == "x86_64-linux"
    then {
      target = "x86_64-unknown-linux-gnu";
      arch = "x86_64";
    }
    else throw "stage4-gcc46: only x86_64-linux is supported at this stage";

  # ---------------------------------------------------------------------------
  # Step 1: Build a minimal binutils with TinyCC
  # ---------------------------------------------------------------------------
  # We need `as` and `ld` before we can build GCC.
  binutils-bootstrap = builtins.derivation {
    name = "binutils-bootstrap-2.14";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
              set -eu

              export PATH="${tinycc}/bin:${mescc-tools}/bin:$PATH"

              WORK="$TMPDIR/binutils-build"
              mkdir -p "$WORK"
              cd "$WORK"

              # Extract binutils source
              # Using an old version (2.14) because TinyCC can compile it
              if [ -d "${sources.binutils}" ]; then
                cp -r ${sources.binutils}/* .
              else
                tar xf ${sources.binutils}
                cd binutils-* 2>/dev/null || true
              fi
              chmod -R u+w .

              PREFIX="$out"
              mkdir -p "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/${archParams.target}/bin"

              # TODO: Build binutils with TinyCC
              # The approach is:
              #   1. Compile libiberty (portability library)
              #   2. Compile libbfd (binary file descriptor library)
              #   3. Compile gas (GNU assembler)
              #   4. Compile ld (GNU linker)
              #
              # TinyCC needs patches to handle some binutils C idioms.
              # The live-bootstrap project provides these patches.
              #
              # Rough build:
              #   cd libiberty && tcc -c *.c && ar rcs libiberty.a *.o
              #   cd bfd && tcc -c -I../include *.c && ar rcs libbfd.a *.o
              #   cd gas && tcc -I../include -I../bfd -o as *.c -L../libiberty -L../bfd -lbfd -liberty
              #   cd ld && tcc -I../include -I../bfd -o ld *.c -L../libiberty -L../bfd -lbfd -liberty

              echo "TODO: Build binutils with TinyCC" >&2

              # Placeholder binaries
              for tool in as ld ar nm objdump ranlib readelf strip objcopy; do
                cat > "$PREFIX/bin/$tool" << TOOL_STUB
        #!/bin/sh
        echo "$tool (bootstrap, compiled by TinyCC)"
        echo "Placeholder — replace with real build"
        exit 1
        TOOL_STUB
                chmod +x "$PREFIX/bin/$tool"
                ln -s "$PREFIX/bin/$tool" "$PREFIX/${archParams.target}/bin/$tool" 2>/dev/null || true
              done

              echo "Bootstrap binutils complete"
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # Step 2: Build a minimal make with TinyCC
  # ---------------------------------------------------------------------------
  make-bootstrap = builtins.derivation {
    name = "make-bootstrap-3.82";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
              set -eu

              export PATH="${tinycc}/bin:${mescc-tools}/bin:$PATH"

              WORK="$TMPDIR/make-build"
              mkdir -p "$WORK"
              cd "$WORK"

              if [ -d "${sources.make}" ]; then
                cp -r ${sources.make}/* .
              else
                tar xf ${sources.make}
                cd make-* 2>/dev/null || true
              fi
              chmod -R u+w .

              PREFIX="$out"
              mkdir -p "$PREFIX/bin"

              # TODO: Build GNU Make with TinyCC
              # GNU Make can be built with a simple shell script (build.sh)
              # that compiles each .c file individually and links them.
              #
              # The source includes a build.sh for exactly this purpose:
              #   sh build.sh
              #
              # Or manually:
              #   tcc -I . -I glob -o make \
              #     main.c read.c ... (all source files)

              echo "TODO: Build GNU Make with TinyCC" >&2

              cat > "$PREFIX/bin/make" << 'MAKE_STUB'
        #!/bin/sh
        echo "GNU Make (bootstrap, compiled by TinyCC)"
        echo "Placeholder — replace with real build"
        exit 1
        MAKE_STUB
              chmod +x "$PREFIX/bin/make"
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # Step 3: Build a minimal glibc with TinyCC
  # ---------------------------------------------------------------------------
  glibc-bootstrap = builtins.derivation {
    name = "glibc-bootstrap";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
        set -eu

        export PATH="${tinycc}/bin:${binutils-bootstrap}/bin:$PATH"

        PREFIX="$out"
        mkdir -p "$PREFIX/lib" "$PREFIX/include"

        # TODO: Build a minimal C library
        # At this stage we need just enough libc to compile GCC.
        # Options:
        #   a) Build a minimal glibc (very complex, thousands of files)
        #   b) Use the mes libc (simpler, sufficient for GCC bootstrap)
        #   c) Build musl (much simpler than glibc)
        #
        # The live-bootstrap chain uses mes-libc initially, then
        # builds a proper glibc after GCC is available.

        echo "TODO: Build bootstrap libc" >&2

        # Install minimal headers so GCC can find standard includes
        mkdir -p "$PREFIX/include/linux" "$PREFIX/include/asm" "$PREFIX/include/sys"

        # Placeholder headers (GCC needs these to compile)
        echo "/* placeholder */" > "$PREFIX/include/stdio.h"
        echo "/* placeholder */" > "$PREFIX/include/stdlib.h"
        echo "/* placeholder */" > "$PREFIX/include/string.h"
        echo "/* placeholder */" > "$PREFIX/include/stddef.h"
        echo "/* placeholder */" > "$PREFIX/include/unistd.h"
        echo "/* placeholder */" > "$PREFIX/include/errno.h"
        echo "/* placeholder */" > "$PREFIX/include/fcntl.h"
        echo "/* placeholder */" > "$PREFIX/include/signal.h"
        echo "/* placeholder */" > "$PREFIX/include/time.h"
        echo "/* placeholder */" > "$PREFIX/include/sys/types.h"
        echo "/* placeholder */" > "$PREFIX/include/sys/stat.h"
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # Step 4: Build GCC 4.6.4
  # ---------------------------------------------------------------------------
  gcc = builtins.derivation {
    name = "gcc-${version}";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
              set -eu

              export PATH="${tinycc}/bin:${binutils-bootstrap}/bin:${make-bootstrap}/bin:$PATH"
              export C_INCLUDE_PATH="${glibc-bootstrap}/include"
              export LIBRARY_PATH="${glibc-bootstrap}/lib"

              WORK="$TMPDIR/gcc-build"
              mkdir -p "$WORK"
              cd "$WORK"

              # Extract GCC source
              if [ -d "${sources.gcc464}" ]; then
                cp -r ${sources.gcc464}/* .
              else
                tar xf ${sources.gcc464}
                cd gcc-${version} 2>/dev/null || true
              fi
              chmod -R u+w .

              # Create a build directory (GCC prefers out-of-tree builds)
              BUILD="$TMPDIR/gcc-objdir"
              mkdir -p "$BUILD"
              cd "$BUILD"

              PREFIX="$out"
              mkdir -p "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/libexec"

              # TODO: Configure and build GCC 4.6.4 with TinyCC
              #
              # GCC 4.6.4 needs patches to compile under TinyCC:
              #   - Remove use of GCC extensions not supported by TinyCC
              #   - Simplify some preprocessor usage
              #   - Work around TinyCC limitations in code generation
              #
              # Configure (C only, no C++):
              #   CC=tcc \
              #   ../configure \
              #     --prefix=$PREFIX \
              #     --build=${archParams.target} \
              #     --host=${archParams.target} \
              #     --target=${archParams.target} \
              #     --enable-languages=c \
              #     --disable-multilib \
              #     --disable-bootstrap \
              #     --disable-shared \
              #     --disable-libssp \
              #     --disable-libgomp \
              #     --disable-libmudflap \
              #     --disable-libquadmath \
              #     --disable-decimal-float \
              #     --disable-threads \
              #     --disable-nls \
              #     --with-gnu-as \
              #     --with-gnu-ld \
              #     --with-as=${binutils-bootstrap}/bin/as \
              #     --with-ld=${binutils-bootstrap}/bin/ld \
              #     --with-native-system-header-dir=${glibc-bootstrap}/include
              #
              # Build:
              #   make -j$NIX_BUILD_CORES
              #   make install

              echo "TODO: Configure and build GCC ${version}" >&2
              echo "  CC=tcc, target=${archParams.target}" >&2
              echo "  Languages: C only" >&2
              echo "  Using binutils from: ${binutils-bootstrap}" >&2

              # Placeholder
              for tool in gcc cc1 collect2 lto-wrapper; do
                cat > "$PREFIX/bin/$tool" << TOOL_STUB
        #!/bin/sh
        echo "GCC ${version} $tool (compiled by TinyCC)"
        echo "Placeholder — replace with real build"
        exit 1
        TOOL_STUB
                chmod +x "$PREFIX/bin/$tool"
              done

              echo "GCC ${version} bootstrap complete"
      ''
    ];
  };
in
  gcc
  // {
    inherit version;

    # Export sub-components for debugging
    components = {
      inherit binutils-bootstrap make-bootstrap glibc-bootstrap;
    };

    meta = {
      description = "GCC 4.6.4 (C only) — first optimizing compiler, built by TinyCC";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux"];
    };
  }
