# stdenv/toolchains/gcc4_1/glibc.nix — glibc 2.5 (RHEL 5)
#
# Built with THIS tier's GCC 4.1.2 + binutils 2.17 + linux-headers 2.6.18.
# glibc 2.5 requires out-of-tree build.
#
{
  prev,
  gcc,
  binutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.5.tar.bz2";
    sha256 = "0khysawcx2glspp1nq2j02sszqjc06hjrpiirbw1qr2a73q5jg1w";
  };

  stubsSuffix =
    if hostPlatform.is64bit
    then "64"
    else "32";
in
  builtins.derivation {
    name = "glibc-2.5";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
              set -eu
              export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
              export CONFIG_SHELL="${prev.bash}/bin/bash"

              cd "$TMPDIR"
              cp -r ${src} glibc-2.5
              cd glibc-2.5
              chmod -R u+w .

              # Avoid the x86_64 fixed vsyscall page so this tier's Bash and
              # other static tools run on kernels without legacy emulation.
              ${prev.patch}/bin/patch -p1 < ${./patches/glibc-2.5-no-fixed-vsyscall.patch}

              # The preceding cross tier's static sed 4.1.2 crashes in
              # in-place mode on newer 6.12 kernels. Stream each transform
              # back into the existing inode so configure keeps its mode.
              rewrite_with_prev_sed() {
                file="$1"
                shift
                ${prev.sed}/bin/sed "$@" "$file" > "$file.tmp-sed"
                ${prev.coreutils}/bin/cat "$file.tmp-sed" > "$file"
                ${prev.coreutils}/bin/rm "$file.tmp-sed"
              }

              # glibc configure hardcodes /bin/pwd which doesn't exist in sandbox
              rewrite_with_prev_sed configure 's|/bin/pwd|pwd|g'

              # vm86 is a versioned symbol (vm86@@GLIBC_2.3.4) — make-syscalls.sh only
              # generates rules for versioned symbols when building shared libraries.
              # With --disable-shared, the rule is skipped but the i386 Makefile still
              # lists vm86 in sysdep_routines, causing "No rule to make target vm86.o".
              rewrite_with_prev_sed sysdeps/unix/sysv/linux/i386/Makefile '/^sysdep_routines/s/ vm86//'

              # Out-of-tree build (required by glibc)
              mkdir -p "$TMPDIR/build"
              cd "$TMPDIR/build"

              # GCC 4.1.2 produces dynamically-linked test programs by default,
              # but there's no dynamic linker in the sandbox. Create a wrapper
              # that adds -static only when linking (not for -c/-S/-E compilation).
              mkdir -p "$TMPDIR/fakebin"
              cat > "$TMPDIR/fakebin/gcc-wrap" << 'WRAPPER'
        #!/bin/sh
        linking=yes
        for arg; do
          case "$arg" in
            -c|-S|-E) linking=no; break ;;
          esac
        done
        if [ "$linking" = "yes" ]; then
          exec REAL_GCC "$@" -static
        else
          exec REAL_GCC "$@"
        fi
        WRAPPER
              rewrite_with_prev_sed "$TMPDIR/fakebin/gcc-wrap" "s|REAL_GCC|${gcc}/bin/gcc|g"
              chmod +x "$TMPDIR/fakebin/gcc-wrap"

              CC="$TMPDIR/fakebin/gcc-wrap" \
              AR="${binutils}/bin/ar" \
              RANLIB="${binutils}/bin/ranlib" \
              CFLAGS="-O2" \
              "$TMPDIR/glibc-2.5/configure" \
                --prefix="$out" \
                --build=${hostPlatform.config} \
                --host=${hostPlatform.config} \
                --with-headers="${linuxHeaders}/include" \
                --disable-shared \
                --disable-profile \
                --disable-nscd \
                --enable-add-ons=nptl \
                --enable-kernel=2.6.0 \
                --enable-static-nss \
                --without-gd \
                --without-selinux \
                libc_cv_forced_unwind=yes \
                libc_cv_c_cleanup=yes

              # PERL=true: configure sets PERL=no without perl in PATH, causing
              # locale/Makefile to run "no gen-translit.pl ..." which fails.
              make -j"$NIX_BUILD_CORES" PERL=true || true
              test -f libc.a || { echo "FATAL: libc.a not built"; exit 1; }
              # -k: keep going past locale subdirectory failure.  libc.a, headers,
              # and crt files are all installed before locale runs.
              # -k installs headers and subdirectory artifacts but the locale
              # failure prevents the top-level libc.a/crt install and stubs
              # generation.  Install those manually from the build directory.
              make -k install PERL=true || true
              mkdir -p "$out/lib"
              cp libc.a "$out/lib/"
              cp csu/crt1.o csu/crti.o csu/crtn.o "$out/lib/"
              # Fix stubs file: static-only build generates stubs-.h (empty ABI suffix)
              if [ -f "$out/include/gnu/stubs-.h" ] && [ ! -f "$out/include/gnu/stubs-${stubsSuffix}.h" ]; then
                mv "$out/include/gnu/stubs-.h" "$out/include/gnu/stubs-${stubsSuffix}.h"
              fi
              mkdir -p "$out/include/gnu"
              touch "$out/include/gnu/stubs-${stubsSuffix}.h"

              # Copy linux headers into glibc output for downstream use
              cp -r "${linuxHeaders}/include/linux" "$out/include/" 2>/dev/null || true
              cp -r "${linuxHeaders}/include/asm" "$out/include/" 2>/dev/null || true
              cp -r "${linuxHeaders}/include/asm-generic" "$out/include/" 2>/dev/null || true

              echo "glibc 2.5 installed to $out"
      ''
    ];
  }
  // {
    meta = {
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
