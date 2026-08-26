##! GNU GDB — source-level debugger and remote debugging client
{
  mkDerivation,
  fetchurl,
  gnumake,
  bison,
  flex,
  texinfo,
  pkg-config,
  file,
  perl,
  gettext,
  python3,
  gmp,
  mpfr,
  expat,
  readline,
  ncurses,
  zlib,
  xz,
  zstd,
  bash,
  stdenv,
  buildPackages,
}: let
  version = "17.2";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  pythonConfigureProgram =
    if isDarwinCross
    then "$PWD/aos-python-config"
    else "${python3}/bin/python3";
  debuggerTargetFlag =
    if isDarwinCross
    then "--target=x86_64-apple-darwin22 --program-prefix="
    else "";
  buildMakeFlags =
    if isDarwinCross
    then " CC_FOR_BUILD=$PWD/.aos-build-tools/cc-for-build CXX_FOR_BUILD=$PWD/.aos-build-tools/cxx-for-build CFLAGS_FOR_BUILD= CXXFLAGS_FOR_BUILD= LDFLAGS_FOR_BUILD="
    else "";
in
  mkDerivation {
    pname = "gdb";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/gdb/gdb-${version}.tar.xz"
        "https://mirrors.kernel.org/gnu/gdb/gdb-${version}.tar.xz"
      ];
      hash = "sha256-HANsDXLks9H7XJTIhjKt1vnXb018TS6nk8EqnxmjIow=";
    };

    buildDeps = [
      gnumake
      bison
      flex
      texinfo
      pkg-config
      file
      perl
      gettext
      python3
    ];
    runtimeDeps = [
      bash
      python3
      gmp
      mpfr
      expat
      readline
      ncurses
      zlib
      xz
      zstd
    ];
    propagatedDeps = [];
    disallowedReferences =
      if isDarwinCross
      then [buildPackages.bash buildPackages.cc buildPackages.llvm]
      else [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gdb-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if isDarwinCross
            then ''
              # Top-level binutils-gdb rejects unversioned Darwin targets and
              # has no native AArch64 Darwin backend. A versioned x86_64
              # debugger target enables the Darwin client on both Darwin host
              # architectures; --enable-targets=all retains the multiarch and
              # remote-debugging backends.
              # The native compiler wrapper inherits the target hardening and
              # SDK environment. Isolate GDB's build-machine generators from
              # Darwin-only flags such as arm64 PAC before invoking it.
              write_build_compiler() {
                native_compiler=$1
                wrapper=$2
                cat > "$wrapper" <<EOF
              #!$CONFIG_SHELL
              native_hardening=
              for token in \$AOS_HARDENING_ENABLE; do
                case "\$token" in
                  pacret) ;;
                  *) native_hardening="\$native_hardening \$token" ;;
                esac
              done
              export AOS_HARDENING_ENABLE="\$native_hardening"
              unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
              unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
              exec "$native_compiler" "\$@"
              EOF
                chmod +x "$wrapper"
              }
              mkdir -p .aos-build-tools
              write_build_compiler "$BUILD_CC" .aos-build-tools/cc-for-build
              write_build_compiler "$BUILD_CXX" .aos-build-tools/cxx-for-build

              export CC_FOR_BUILD="$PWD/.aos-build-tools/cc-for-build"
              export CXX_FOR_BUILD="$PWD/.aos-build-tools/cxx-for-build"
              export CFLAGS_FOR_BUILD=
              export CXXFLAGS_FOR_BUILD=
              export LDFLAGS_FOR_BUILD=

              cat > aos-python-config <<'PYTHON_CONFIG'
              #!${buildPackages.bash}/bin/bash
              # GDB invokes this as "program python-config.py --option".  A
              # target Python cannot run on the Linux builder, so answer the
              # configuration query directly from the target package.
              case "$2" in
                --includes|--cflags)
                  echo "-I${python3}/include/python3.14"
                  ;;
                --libs|--ldflags)
                  echo "-L${python3}/lib -lpython3.14"
                  ;;
                --prefix|--exec-prefix)
                  echo "${python3}"
                  ;;
                *)
                  exit 1
                  ;;
              esac
              PYTHON_CONFIG
              chmod +x aos-python-config
            ''
            else ""
          }
          ./configure \
            $configureFlags \
            ${debuggerTargetFlag} \
            --prefix=$out \
            --enable-targets=all \
            --enable-64-bit-bfd \
            --enable-tui \
            --with-python=${pythonConfigureProgram} \
            --with-python-libdir=${python3}/lib \
            --with-system-readline \
            --with-system-zlib \
            --with-expat \
            --with-lzma
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES${buildMakeFlags} all-gdb all-gdbserver
        '';
      }
      {
        name = "install";
        script = ''
          make${buildMakeFlags} install-gdb install-gdbserver
          for script in "$out/bin/gdb-add-index" "$out/bin/gcore" "$out/bin/gstack"; do
            [ -f "$script" ] || continue
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$script"
          done
          test -x "$out/bin/gdb"
          ${
            if isDarwinCross
            then ''
              ${buildPackages.llvm}/bin/llvm-objdump --macho --private-header \
                "$out/bin/gdb" >/dev/null
            ''
            else ''
              test -x "$out/bin/gdbserver"
              "$out/bin/gdb" --batch \
                -ex 'python import sys; assert sys.version_info >= (3, 14)' \
                -ex 'set architecture i386:x86-64' \
                -ex 'set architecture aarch64' \
                -ex 'show architecture'
            ''
          }
          mkdir -p "$out/share/licenses/gdb"
          cp COPYING3 "$out/share/licenses/gdb/GPL-3.0.txt"
        '';
      }
    ];

    meta = {
      description = "GNU debugger with multi-architecture remote debugging support";
      homepage = "https://www.gnu.org/software/gdb/";
      license = "GPL-3.0-or-later";
      mainProgram = "gdb";
    };
  }
