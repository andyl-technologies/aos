# stdenv/toolchains/gcc3_4/glibc.nix — glibc 2.3.4 (RHEL 4)
#
# First tier glibc, built with GCC 3.4.6 + binutils 2.15 + linux 2.6.9 headers.
# All i686-linux.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  this,
  ...
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.3.4.tar.bz2";
    sha256 = "13cg3l7szdf0ardqi13gxgg2z9v5yvzv7xpizrg9mcrk125vjx5y";
  };

  linuxpthreads = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-linuxthreads-2.3.4.tar.bz2";
    sha256 = "1zlv8zql09fyicf9lh27z73f9afyr3mismhkngnybgqvcfgp7zgj";
  };
in
  builtins.derivation {
    name = "glibc-2.3.4";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${this.gcc}/bin:${this.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        # Copy source to writable location and add linuxthreads
        cp -r ${src} "$TMPDIR/glibc-2.3.4"
        chmod -R u+w "$TMPDIR/glibc-2.3.4"

        # glibc 2.3.4 needs linuxthreads extracted into the source tree
        cp -r ${linuxpthreads}/linuxthreads "$TMPDIR/glibc-2.3.4/" 2>/dev/null || true
        cp -r ${linuxpthreads}/linuxthreads_db "$TMPDIR/glibc-2.3.4/" 2>/dev/null || true

        SRC="$TMPDIR/glibc-2.3.4"

        # glibc 2.3.4 configure hardcodes /bin/pwd which doesn't exist in sandbox
        sed -i 's|/bin/pwd|pwd|g' "$SRC/configure"

        # Out-of-tree build required by glibc
        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${this.gcc}/bin/gcc" \
        AR="${this.binutils}/bin/ar" \
        RANLIB="${this.binutils}/bin/ranlib" \
        CFLAGS="-O2 -I${prev.glibc}/include" \
        "$SRC/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} \
          --host=${hostPlatform.config} \
          --with-headers="${this.linuxHeaders}/include" \
          --disable-profile \
          --disable-nscd \
          --enable-add-ons=nptl \
          --enable-kernel=2.6.0 \
          --without-gd \
          --without-selinux \
          libc_cv_forced_unwind=yes \
          libc_cv_c_cleanup=yes

        # glibc 2.3.4's generated subdirectory and rtld stamp rules are not
        # parallel-safe: concurrent recipes race on mkdir/stamp.os and can
        # emit an incomplete elf/librtld.mk (observed as rtld-Rules "missing
        # separator"). Keep this historical bootstrap stage serial; later
        # glibc tiers use the requested build-wide parallelism.
        make -j1
        make install

        # Copy linux headers into glibc output for downstream use
        cp -r "${this.linuxHeaders}/include/linux" "$out/include/" 2>/dev/null || true
        cp -r "${this.linuxHeaders}/include/asm" "$out/include/" 2>/dev/null || true
        cp -r "${this.linuxHeaders}/include/asm-generic" "$out/include/" 2>/dev/null || true

        echo "glibc 2.3.4 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU C Library, version 2.3.4";
      homepage = "https://www.gnu.org/software/libc/";
      license = "LGPL-2.1-or-later";
      build = {
        os = "linux";
        cpu = [
          "x86_64"
          "i686"
        ];
      };
      execute = {
        os = "linux";
        cpu = [
          "x86_64"
          "i686"
        ];
      };
    };
  }
