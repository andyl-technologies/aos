##! GNU Autoconf — generates configure scripts from templates
{
  mkDerivation,
  fetchurl,
  make,
  m4,
  perl,
}:

let
  version = "2.72";
in
mkDerivation {
  pname = "autoconf";
  inherit version;

  src = fetchurl {
    urls = [
      "https://ftp.gnu.org/gnu/autoconf/autoconf-${version}.tar.xz"
    ];
    hash = "sha256-uohcExlXjWyU1G6bDc60AUyq/iSQ5Deg28o/JwoiP1o=";
  };

  buildDeps = [ make ];
  runtimeDeps = [
    m4
    perl
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd autoconf-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out
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
      '';
    }
  ];

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      build = testing.mkFirecrackerTest {
        pname = "build-autotools-build";
        rootfsDeps = [
          self
          pkgs.automake
          pkgs.make
          pkgs.m4
        ];
        testScript = ''
          mkdir -p /tmp/proj
          cat > /tmp/proj/configure.ac << 'EOF'
          AC_INIT([test], [1.0])
          AM_INIT_AUTOMAKE([foreign])
          AC_PROG_CC
          AC_OUTPUT([Makefile])
          EOF
          cat > /tmp/proj/Makefile.am << 'EOF'
          bin_PROGRAMS = test_app
          test_app_SOURCES = main.c
          EOF
          cat > /tmp/proj/main.c << 'EOF'
          #include <stdio.h>
          int main() { printf("autotools works\n"); return 0; }
          EOF
          cd /tmp/proj
          autoreconf -i
          ./configure
          make
          result=$(./test_app)
          test "$result" = "autotools works"
          echo "==> autotools-build passed"
        '';
      };
    };

  meta = {
    description = "GNU Autoconf — generates configure scripts from templates";
    homepage = "https://www.gnu.org/software/autoconf/";
    license = "GPL-3.0-or-later";
  };
}
