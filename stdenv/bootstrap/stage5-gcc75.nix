# stdenv/bootstrap/stage5-gcc75.nix — GCC 7.5.0 compiled by GCC 4.6.4
#
# GCC 7.5.0 adds C++ support, which is required to build modern GCC (10+).
# This is the second "hop" in the GCC bootstrap chain:
#   TinyCC -> GCC 4.6.4 (C only) -> GCC 7.5.0 (C + C++)
#
# With GCC 7.5.0 we can build:
#   - Modern GCC (13.x) which requires a C++11-capable compiler
#   - A proper glibc with all features enabled
#   - binutils, make, and other GNU tools at modern versions
#
# GCC 7.5.0 is chosen because:
#   - It can be compiled by GCC 4.6.4 (needs only C90/C99)
#   - It supports C++11, which modern GCC requires to build
#   - It is the version used by Guix's bootstrap chain
#

{
  gcc46, # Output of stage4-gcc46.nix (GCC 4.6.4, C only)
  sources,
  # Attrset with: gcc75-source, gmp-source, mpfr-source, mpc-source,
  #               linux-headers-source, glibc-source, binutils-source
  system ? "x86_64-linux",
}:

let
  version = "7.5.0";

  archParams =
    if system == "x86_64-linux" then
      {
        target = "x86_64-unknown-linux-gnu";
        arch = "x86_64";
        kernelArch = "x86";
      }
    else
      throw "stage5-gcc75: only x86_64-linux is supported at this stage";

  # ---------------------------------------------------------------------------
  # Prerequisite: GMP (GNU Multiple Precision Arithmetic Library)
  # GCC requires GMP for its internal arithmetic.
  # ---------------------------------------------------------------------------
  gmp = builtins.derivation {
    name = "gmp-6.2.1";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${gcc46}/bin:${gcc46.components.binutils-bootstrap}/bin:${gcc46.components.make-bootstrap}/bin:$PATH"

        WORK="$TMPDIR/gmp-build"
        mkdir -p "$WORK"
        cd "$WORK"

        if [ -d "${sources.gmp}" ]; then
          cp -r ${sources.gmp}/* .
        else
          tar xf ${sources.gmp}
          cd gmp-* 2>/dev/null || true
        fi
        chmod -R u+w .

        PREFIX="$out"

        # TODO: Configure and build GMP with GCC 4.6.4
        # ./configure --prefix=$PREFIX --enable-cxx=no --disable-shared
        # make -j4
        # make install

        echo "TODO: Build GMP with GCC 4.6.4" >&2

        mkdir -p "$PREFIX/lib" "$PREFIX/include"
        echo "/* GMP placeholder */" > "$PREFIX/include/gmp.h"
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # Prerequisite: MPFR (Multiple Precision Floating-Point)
  # ---------------------------------------------------------------------------
  mpfr = builtins.derivation {
    name = "mpfr-4.1.0";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${gcc46}/bin:${gcc46.components.binutils-bootstrap}/bin:${gcc46.components.make-bootstrap}/bin:$PATH"

        WORK="$TMPDIR/mpfr-build"
        mkdir -p "$WORK"

        if [ -d "${sources.mpfr}" ]; then
          cp -r ${sources.mpfr}/* "$WORK/"
        else
          cd "$WORK" && tar xf ${sources.mpfr}
          cd mpfr-* 2>/dev/null || true
        fi
        chmod -R u+w "$WORK"
        cd "$WORK"

        PREFIX="$out"

        # TODO: Configure and build MPFR with GCC 4.6.4
        # ./configure --prefix=$PREFIX --with-gmp=${gmp} --disable-shared
        # make -j4
        # make install

        echo "TODO: Build MPFR with GCC 4.6.4" >&2

        mkdir -p "$PREFIX/lib" "$PREFIX/include"
        echo "/* MPFR placeholder */" > "$PREFIX/include/mpfr.h"
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # Prerequisite: MPC (Multiple Precision Complex)
  # ---------------------------------------------------------------------------
  mpc = builtins.derivation {
    name = "mpc-1.2.1";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${gcc46}/bin:${gcc46.components.binutils-bootstrap}/bin:${gcc46.components.make-bootstrap}/bin:$PATH"

        WORK="$TMPDIR/mpc-build"
        mkdir -p "$WORK"

        if [ -d "${sources.mpc}" ]; then
          cp -r ${sources.mpc}/* "$WORK/"
        else
          cd "$WORK" && tar xf ${sources.mpc}
          cd mpc-* 2>/dev/null || true
        fi
        chmod -R u+w "$WORK"
        cd "$WORK"

        PREFIX="$out"

        # TODO: Configure and build MPC with GCC 4.6.4
        # ./configure --prefix=$PREFIX --with-gmp=${gmp} --with-mpfr=${mpfr} --disable-shared
        # make -j4
        # make install

        echo "TODO: Build MPC with GCC 4.6.4" >&2

        mkdir -p "$PREFIX/lib" "$PREFIX/include"
        echo "/* MPC placeholder */" > "$PREFIX/include/mpc.h"
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # Prerequisite: Linux kernel headers
  # GCC and glibc need kernel headers for system call numbers, ioctl
  # definitions, and other kernel-userspace interface definitions.
  # ---------------------------------------------------------------------------
  linux-headers = builtins.derivation {
    name = "linux-headers-6.1";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${gcc46}/bin:${gcc46.components.binutils-bootstrap}/bin:${gcc46.components.make-bootstrap}/bin:$PATH"

        WORK="$TMPDIR/headers-build"
        mkdir -p "$WORK"
        cd "$WORK"

        if [ -d "${sources.linux-headers}" ]; then
          cp -r ${sources.linux-headers}/* .
        else
          tar xf ${sources.linux-headers}
          cd linux-* 2>/dev/null || true
        fi
        chmod -R u+w .

        PREFIX="$out"

        # TODO: Build and install kernel headers
        # make headers_install \
        #   ARCH=${archParams.kernelArch} \
        #   INSTALL_HDR_PATH=$PREFIX

        echo "TODO: Install Linux kernel headers" >&2

        mkdir -p "$PREFIX/include/linux" "$PREFIX/include/asm" "$PREFIX/include/asm-generic"
        echo "/* kernel headers placeholder */" > "$PREFIX/include/linux/types.h"
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # Prerequisite: Rebuild binutils with GCC 4.6.4
  # ---------------------------------------------------------------------------
  binutils = builtins.derivation {
    name = "binutils-2.38";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${gcc46}/bin:${gcc46.components.binutils-bootstrap}/bin:${gcc46.components.make-bootstrap}/bin:$PATH"

        WORK="$TMPDIR/binutils-build"
        mkdir -p "$WORK"
        cd "$WORK"

        if [ -d "${sources.binutils}" ]; then
          cp -r ${sources.binutils}/* .
        else
          tar xf ${sources.binutils}
          cd binutils-* 2>/dev/null || true
        fi
        chmod -R u+w .

        BUILD="$TMPDIR/binutils-objdir"
        mkdir -p "$BUILD"
        cd "$BUILD"

        PREFIX="$out"

        # TODO: Configure and build binutils with GCC 4.6.4
        # CC=gcc \
        # ../binutils-*/configure \
        #   --prefix=$PREFIX \
        #   --target=${archParams.target} \
        #   --disable-nls \
        #   --disable-shared \
        #   --disable-werror
        # make -j4
        # make install

        echo "TODO: Build binutils with GCC 4.6.4" >&2

        mkdir -p "$PREFIX/bin" "$PREFIX/${archParams.target}/bin"
        for tool in as ld ar nm objdump ranlib readelf strip objcopy; do
          echo "#!/bin/sh" > "$PREFIX/bin/$tool"
          echo "echo '$tool (built by GCC 4.6.4) — placeholder'" >> "$PREFIX/bin/$tool"
          chmod +x "$PREFIX/bin/$tool"
        done
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # Prerequisite: Build a proper glibc with GCC 4.6.4
  # ---------------------------------------------------------------------------
  glibc-intermediate = builtins.derivation {
    name = "glibc-intermediate-2.31";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${gcc46}/bin:${binutils}/bin:${gcc46.components.make-bootstrap}/bin:$PATH"

        WORK="$TMPDIR/glibc-build"
        mkdir -p "$WORK"
        cd "$WORK"

        if [ -d "${sources.glibc}" ]; then
          cp -r ${sources.glibc}/* .
        else
          tar xf ${sources.glibc}
          cd glibc-* 2>/dev/null || true
        fi
        chmod -R u+w .

        BUILD="$TMPDIR/glibc-objdir"
        mkdir -p "$BUILD"
        cd "$BUILD"

        PREFIX="$out"

        # TODO: Configure and build glibc with GCC 4.6.4
        # CC=gcc \
        # ../glibc-*/configure \
        #   --prefix=$PREFIX \
        #   --host=${archParams.target} \
        #   --build=${archParams.target} \
        #   --with-headers=${linux-headers}/include \
        #   --enable-kernel=3.2 \
        #   --disable-werror \
        #   libc_cv_forced_unwind=yes
        # make -j4
        # make install

        echo "TODO: Build intermediate glibc with GCC 4.6.4" >&2

        mkdir -p "$PREFIX/lib" "$PREFIX/include"
      ''
    ];
  };

  # ---------------------------------------------------------------------------
  # Build GCC 7.5.0
  # ---------------------------------------------------------------------------
  gcc75 = builtins.derivation {
    name = "gcc-${version}";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
              set -eu
              export PATH="${gcc46}/bin:${binutils}/bin:${gcc46.components.make-bootstrap}/bin:$PATH"
              export C_INCLUDE_PATH="${glibc-intermediate}/include:${linux-headers}/include"
              export LIBRARY_PATH="${glibc-intermediate}/lib"

              WORK="$TMPDIR/gcc75-build"
              mkdir -p "$WORK"
              cd "$WORK"

              # Extract GCC source
              if [ -d "${sources.gcc75}" ]; then
                cp -r ${sources.gcc75}/* .
              else
                tar xf ${sources.gcc75}
                cd gcc-${version} 2>/dev/null || true
              fi
              chmod -R u+w .

              # GCC in-tree prerequisites: symlink GMP, MPFR, MPC into the source tree
              # so GCC builds them as part of its own build process.
              # Alternatively, point to pre-built versions:

              BUILD="$TMPDIR/gcc75-objdir"
              mkdir -p "$BUILD"
              cd "$BUILD"

              PREFIX="$out"

              # TODO: Configure and build GCC 7.5.0
              #
              # This is the key step: building a C++-capable GCC using
              # the C-only GCC 4.6.4.
              #
              # CC=gcc CXX="gcc -lstdc++" \
              # $WORK/gcc-${version}/configure \
              #   --prefix=$PREFIX \
              #   --build=${archParams.target} \
              #   --host=${archParams.target} \
              #   --target=${archParams.target} \
              #   --enable-languages=c,c++ \
              #   --disable-multilib \
              #   --disable-bootstrap \
              #   --disable-libsanitizer \
              #   --disable-lto \
              #   --disable-plugin \
              #   --disable-nls \
              #   --with-gmp=${gmp} \
              #   --with-mpfr=${mpfr} \
              #   --with-mpc=${mpc} \
              #   --with-gnu-as \
              #   --with-gnu-ld \
              #   --with-as=${binutils}/bin/as \
              #   --with-ld=${binutils}/bin/ld \
              #   --with-native-system-header-dir=${glibc-intermediate}/include \
              #   --with-sysroot=/
              #
              # make -j4
              # make install

              echo "TODO: Configure and build GCC ${version}" >&2
              echo "  Using GCC 4.6.4 as the bootstrap compiler" >&2
              echo "  Languages: C, C++" >&2
              echo "  GMP: ${gmp}" >&2
              echo "  MPFR: ${mpfr}" >&2
              echo "  MPC: ${mpc}" >&2

              mkdir -p "$PREFIX/bin" "$PREFIX/lib" "$PREFIX/lib64" "$PREFIX/libexec"
              mkdir -p "$PREFIX/include"

              # Placeholder binaries
              for tool in gcc g++ cpp gcov gcc-ar gcc-nm gcc-ranlib; do
                cat > "$PREFIX/bin/$tool" << TOOL_STUB
        #!/bin/sh
        echo "GCC ${version} $tool (compiled by GCC 4.6.4)"
        echo "Placeholder — replace with real build"
        exit 1
        TOOL_STUB
                chmod +x "$PREFIX/bin/$tool"
              done

              # Symlink cc -> gcc
              ln -s gcc "$PREFIX/bin/cc"
              ln -s g++ "$PREFIX/bin/c++"

              echo "GCC ${version} build complete"
      ''
    ];
  };

in
gcc75
// {
  inherit version;

  # Export sub-components for downstream stages
  components = {
    inherit
      gmp
      mpfr
      mpc
      linux-headers
      binutils
      glibc-intermediate
      ;
  };

  meta = {
    description = "GCC 7.5.0 (C + C++) — built by GCC 4.6.4, enables modern GCC";
    homepage = "https://gcc.gnu.org/";
    license = "GPL-3.0-or-later";
    platforms = [ "x86_64-linux" ];
  };
}
