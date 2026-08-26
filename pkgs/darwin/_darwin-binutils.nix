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
        name = "configure";
        script = ''
          mkdir "$TMPDIR/binutils-build"
          cd "$TMPDIR/binutils-build"
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
