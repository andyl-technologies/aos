##! readline — GNU Readline library
{
  mkDerivation,
  fetchurl,
  make,
  ncurses,
}:

let
  version = "8.2";
in
mkDerivation {
  pname = "readline";
  inherit version;

  src = fetchurl {
    urls = [
      "https://ftp.gnu.org/gnu/readline/readline-${version}.tar.gz"
      "https://mirrors.kernel.org/gnu/readline/readline-${version}.tar.gz"
    ];
    hash = "sha256-P+txcfFqhO6CyhijbXub4QmlLAT0kqBTMx19EJUAfDU=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ncurses ];
  propagatedDeps = [ ncurses ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd readline-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --enable-shared \
          --disable-static \
          --with-curses
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES SHLIB_LIBS="-lncursesw"
      '';
    }
    {
      name = "install";
      script = ''
        make install SHLIB_LIBS="-lncursesw"
      '';
    }
  ];

  meta = {
    description = "GNU Readline — command line editing library";
    homepage = "https://tiswww.cwru.edu/php/chet/readline/rltop.html";
    license = "GPL-3.0-or-later";
  };
}
