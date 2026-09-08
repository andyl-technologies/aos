##! readline — GNU Readline library
{
  mkDerivation,
  fetchurl,
  gnumake,
  patch,
  ncurses,
  stdenv,
}: let
  version = "8.3p3";
  sourceVersion = "8.3";
  readlinePatches = [
    (fetchurl {
      urls = ["https://ftp.gnu.org/gnu/readline/readline-8.3-patches/readline83-001"];
      hash = "sha256-IfCgMQbb5pczfNJccOsO26or221ZW0X4MoXN01ushN4=";
    })
    (fetchurl {
      urls = ["https://ftp.gnu.org/gnu/readline/readline-8.3-patches/readline83-002"];
      hash = "sha256-4nNkOWup9t6/fLqvGmaeKyhUJBrgf37KdMqKi6DJdHI=";
    })
    (fetchurl {
      urls = ["https://ftp.gnu.org/gnu/readline/readline-8.3-patches/readline83-003"];
      hash = "sha256-ct7hNgHOOPZ0brFSOZmafFb44f9eseyBU6HyE+Ss2yk=";
    })
  ];
in
  mkDerivation {
    pname = "readline";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/readline/readline-${sourceVersion}.tar.gz"
      ];
      hash = "sha256-/lODIERngozUle6NHTwDen66E4nCK8agQfYnl2+QYcw=";
    };

    buildDeps = [gnumake patch];
    runtimeDeps = [ncurses];
    propagatedDeps = [ncurses];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd readline-${sourceVersion}
        '';
      }
      {
        name = "patch";
        script = ''
          for patchFile in ${builtins.concatStringsSep " " readlinePatches}; do
            patch -p0 < "$patchFile"
          done
        '';
      }
      {
        name = "configure";
        script = ''
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # Mach-O debug symbols retain compilation and object paths even
              # after stripping. Remap the sandbox prefix at compile time so
              # cached libraries contain no ephemeral /build references.
              export CFLAGS="''${CFLAGS:-} -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -fdebug-compilation-dir=."
            ''
            else ""
          }

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
