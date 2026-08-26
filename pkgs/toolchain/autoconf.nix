##! GNU Autoconf — generates configure scripts from templates
{
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  perl,
  bash,
}: let
  version = "2.72";
in
  mkDerivation {
    pname = "autoconf";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/autoconf/autoconf-${version}.tar.xz"
      ];
      hash = "sha256-uohcExlXjWyU1G6bDc60AUyq/iSQ5Deg28o/JwoiP1o=";
    };

    # The generated Perl programs are executed while assembling the package.
    # Keep a native Perl on PATH; runtimeDeps still retains the target Perl
    # needed by the installed Darwin Autoconf scripts.
    buildDeps = [
      gnumake
      m4
      perl
      bash
    ];
    runtimeDeps = [
      m4
      perl
      bash
    ];
    propagatedDeps = [];

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
            $configureFlags \
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

          retarget_tool_root() {
            nativeTool=$(command -v "$1")
            nativeRoot=$(dirname "$(dirname "$nativeTool")")
            targetRoot=$2
            [ "$nativeRoot" = "$targetRoot" ] && return
            grep -IrlZ -F "$nativeRoot" "$out" 2>/dev/null \
              | xargs -0 -r sed -i "s|$nativeRoot|$targetRoot|g"
          }
          retarget_tool_root m4 ${m4}
          retarget_tool_root perl ${perl}

          nativeBashRoot=$(dirname "$(dirname "$CONFIG_SHELL")")
          grep -IrlZ -F "$nativeBashRoot" "$out" 2>/dev/null \
            | xargs -0 -r sed -i "s|$nativeBashRoot|${bash}|g"
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      build = testing.mkVMTest {
        name = "build-autotools-build";
        rootfsDeps = [
          self
          pkgs.automake
          pkgs.gnumake
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
