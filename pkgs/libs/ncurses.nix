##! ncurses — Terminal handling library
{
  mkDerivation,
  fetchurl,
  gnumake,
}:
let
  version = "6.6";
in
mkDerivation {
  pname = "ncurses";
  inherit version;

  src = fetchurl {
    urls = [
      "https://invisible-mirror.net/archives/ncurses/ncurses-${version}.tar.gz"
      "https://mirrors.kernel.org/gnu/ncurses/ncurses-${version}.tar.gz"
    ];
    hash = "sha256-NVtMu+2ICwOBoExGYXt2VuNiWF1S6c+Epn4gCbdJ/xE=";
  };

  buildDeps = [ gnumake ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd ncurses-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        # GCC 13+ requires explicit stdbool.h include for bool type
        export CPPFLAGS="$CPPFLAGS -include stdbool.h"

        ./configure \
          --prefix=$out \
          --with-shared \
          --without-debug \
          --without-ada \
          --enable-widec \
          --enable-pc-files \
          --with-pkg-config-libdir=$out/lib/pkgconfig \
          cf_cv_type_of_bool=bool
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        make install

        # ncurses-config is an autotools-generated helper that prints
        # `--libs`/`--cflags` for downstream consumers. It hardcodes the
        # build-time binutils `/lib` paths (as "standard libdirs to
        # skip"), which drags ~43 MB of binutils into the runtime closure
        # of every package that consumes ncurses (and therefore the
        # initrd). The script is dev tooling — any runtime consumer
        # links against libncurses directly, not via the helper script.
        rm -f "$out/bin/ncursesw6-config" "$out/bin/ncurses6-config" \
              "$out/bin/ncurses5-config" "$out/bin/ncursesw5-config"

        # Create non-wide-char compatibility symlinks
        for lib in ncurses form panel menu; do
          ln -sf lib''${lib}w.so $out/lib/lib''${lib}.so
          ln -sf ''${lib}w.pc $out/lib/pkgconfig/''${lib}.pc
        done

        # tinfo compatibility
        ln -sf libncursesw.so $out/lib/libtinfo.so
        ln -sf ncursesw.pc $out/lib/pkgconfig/tinfo.pc

        # curses compatibility
        ln -sf libncursesw.so $out/lib/libcurses.so

        # Patch curses.h to include stdbool.h for GCC 13+ compatibility.
        # Must happen BEFORE creating symlinks so both ncursesw/curses.h
        # and the include/curses.h symlink get the fix.
        sed -i '1i #include <stdbool.h>' $out/include/ncursesw/curses.h

        # Symlink wide-char headers into $out/include for discoverability
        for f in $out/include/ncursesw/*; do
          ln -sf "ncursesw/$(basename "$f")" "$out/include/$(basename "$f")"
        done
      '';
    }
  ];

  meta = {
    description = "ncurses — terminal handling library";
    homepage = "https://invisible-island.net/ncurses/";
    license = "MIT";
  };
}
