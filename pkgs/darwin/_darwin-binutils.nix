##! GNU binutils hosted on Darwin.
##!
##! Darwin's system assembler and linker come from LLVM/cctools, but the GNU
##! binary utilities remain useful developer tools for their broad BFD target
##! support.  This package builds those utilities as Darwin executables and
##! enables every BFD target; it is intentionally distinct from the linker
##! programs used by the cross stdenv.
{
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  bash,
  zlib,
}: let
  version = "2.41";
in
  mkDerivation {
    pname = "binutils";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/binutils/binutils-${version}.tar.xz"
      ];
      hash = "sha256-rppXieI0WeWWBuZxRyPy0//DHAMXQZHvDQFb3wYAdFA=";
    };

    buildDeps = [
      buildPackages.gnumake
      buildPackages.flex
      buildPackages.bison
      buildPackages.m4
      buildPackages.texinfo
    ];
    runtimeDeps = [
      bash
      zlib
    ];
    hardeningDisable = ["all"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd binutils-${version}

          # Preserve the release-generated parsers and Autotools output.
          find . -type f \( -name '*.y' -o -name '*.l' -o -name Makefile.am -o -name configure.ac \) \
            -exec touch -t 200001010000.00 {} + 2>/dev/null || true
          find . -type f \( -name '*.c' -o -name '*.h' \) \
            -exec touch -t 200001010030.00 {} + 2>/dev/null || true
          find . \( -name configure -o -name Makefile.in -o -name aclocal.m4 -o -name config.h.in \) \
            -exec touch -t 200001010100.00 {} + 2>/dev/null || true
        '';
      }
      {
        name = "patch";
        script = ''
          # Sourceware PR libctf/33194: libctf-nobfd used an ELF weak-symbol
          # trick for optional BFD-backed lazy opening. Mach-O does not model
          # that pragma as an allowed undefined reference, so use the upstream
          # fix and reject lazy opening based on the NOBFD build identity.
          patch -p1 < ${./binutils-libctf-nobfd-darwin.patch}
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir "$TMPDIR/binutils-build"
          cd "$TMPDIR/binutils-build"
          # Libtool cannot execute its command-length probe while crossing to
          # Darwin and otherwise assumes 512 bytes. That forces a relocatable
          # `ld -r` prelink, which is not implemented by ld64.lld. Darwin's
          # documented ARG_MAX is 262144 bytes, large enough to link BFD's
          # complete object list directly without dropping shared libraries.
          export lt_cv_sys_max_cmd_len=262144

          # Bundled gettext's relocatable support calls the public GNU iconv
          # relocation hook. Darwin exports it from libiconv rather than the
          # libSystem compatibility surface used for the POSIX iconv calls.
          export LDFLAGS="$LDFLAGS -liconv"

          CC_FOR_BUILD=${buildPackages.cc}/bin/cc \
          CXX_FOR_BUILD=${buildPackages.cc}/bin/c++ \
          "$TMPDIR/binutils-${version}/configure" \
            --prefix=$out \
            --build=${stdenv.buildPlatform.config} \
            --host=${stdenv.hostPlatform.config} \
            --target=${stdenv.hostPlatform.config} \
            --enable-targets=all \
            --enable-shared \
            --enable-static \
            --enable-plugins \
            --enable-threads \
            --disable-werror \
            --disable-gdb \
            --disable-gdbserver \
            --disable-libdecnumber \
            --disable-readline \
            --disable-sim \
            --disable-gprofng \
            --with-system-zlib \
            --program-transform-name=
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES \
            CC_FOR_BUILD=${buildPackages.cc}/bin/cc \
            CXX_FOR_BUILD=${buildPackages.cc}/bin/c++
        '';
      }
      {
        name = "install";
        script = ''
          make install \
            CC_FOR_BUILD=${buildPackages.cc}/bin/cc \
            CXX_FOR_BUILD=${buildPackages.cc}/bin/c++

          # Installed libtool metadata otherwise retains transient build-tree
          # search directories for bundled libiberty and gettext. They cannot
          # exist for downstream consumers and must not escape in the target
          # development output; keep the library flags themselves intact.
          find "$out/lib" -name '*.la' -type f \
            -exec sed -i 's|-L/build/[^ ]* ||g' {} +

          # Any installed helper scripts must execute with the target AOS bash,
          # never with a path supplied by the eventual macOS host.
          find "$out" -type f -perm -0100 | while read -r file; do
            firstLine=$(sed -n '1p' "$file" 2>/dev/null || true)
            case "$firstLine" in
              '#!'*'/sh'|'#!'*'/bash')
                sed -i "1c #!${bash}/bin/bash" "$file"
                ;;
            esac
          done
        '';
      }
    ];

    meta = {
      description = "GNU binary utilities hosted on Darwin with all BFD targets";
      homepage = "https://www.gnu.org/software/binutils/";
      license = "GPL-3.0-or-later";
    };
  }
