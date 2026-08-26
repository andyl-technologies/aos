##! readline — GNU Readline library
{
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
}: let
  version = "8.3";
in
  mkDerivation {
    pname = "readline";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/readline/readline-${version}.tar.gz"
        "https://mirrors.kernel.org/gnu/readline/readline-${version}.tar.gz"
      ];
      hash = "sha256-/lODIERngozUle6NHTwDen66E4nCK8agQfYnl2+QYcw=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [ncurses];
    propagatedDeps = [ncurses];

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
            $configureFlags \
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
