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
}: let
  version = "17.2";
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
          ./configure \
            --prefix=$out \
            --enable-targets=all \
            --enable-64-bit-bfd \
            --enable-tui \
            --with-python=${python3}/bin/python3 \
            --with-system-readline \
            --with-system-zlib \
            --with-expat \
            --with-lzma
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES all-gdb all-gdbserver
        '';
      }
      {
        name = "install";
        script = ''
          make install-gdb install-gdbserver
          test -x "$out/bin/gdb"
          test -x "$out/bin/gdbserver"
          "$out/bin/gdb" --batch \
            -ex 'python import sys; assert sys.version_info >= (3, 14)' \
            -ex 'set architecture i386:x86-64' \
            -ex 'set architecture aarch64' \
            -ex 'show architecture'
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
