##! libedit — NetBSD command-line editing library
{
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
}: let
  version = "20260512-3.1";
in
  mkDerivation {
    pname = "libedit";
    inherit version;

    src = fetchurl {
      urls = ["https://thrysoee.dk/editline/libedit-${version}.tar.gz"];
      hash = "sha256-Qy1efqiwEW3Tny7Ke8EdDu13+qa3fqUmrOiZB8I+pKA=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [ncurses];
    propagatedDeps = [ncurses];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libedit-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure $configureFlags \
            --prefix="$out" \
            --enable-widec
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        script = ''make check'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "libedit";
        library = self;
        libs = ["-ledit" "-lncursesw"];
        testSource = ''
          #include <histedit.h>

          int main(void) {
              History *history = history_init();
              if (history == NULL) return 1;
              history_end(history);
              return 0;
          }
        '';
      };
    };

    meta = {
      description = "Port of the NetBSD command-line editor library";
      homepage = "https://thrysoee.dk/editline/";
      license = "BSD-3-Clause";
    };
  }
