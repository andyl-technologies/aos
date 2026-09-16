##! GNU Autoconf — generates configure scripts from templates
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  perl,
  bash,
}: let
  version = "2.73";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "autoconf";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Autoconf generates a runnable script that accepts the declared option.";
        "files" = {
          "configure.ac" = "AC_INIT([aos-probe], [1.0])\nAC_CONFIG_SRCDIR([configure.ac])\nAC_ARG_ENABLE([feature], [AS_HELP_STRING([--enable-feature], [enable probe feature])])\nAS_IF([test \"x$enable_feature\" != xyes], [AC_MSG_ERROR([feature was not enabled])])\nAC_MSG_NOTICE([autoconf feature passed])\nAC_OUTPUT\n";
        };
        "input" = "A configure.ac declaring a boolean feature option.";
        "operation" = "Generate configure, then execute it with the feature enabled.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/autoconf"
              "--output=configure"
              "configure.ac"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@bash@"
              "configure"
              "--enable-feature"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Autoconf rejects the source with a failure status.";
        "files" = {
          "invalid.ac" = "AC_INIT([aos-probe], [1.0])\nAC_MSG_NOTICE([unterminated)\nAC_OUTPUT\n";
        };
        "input" = "An Autoconf source with an unterminated M4 quotation.";
        "operation" = "Generate configure from the malformed macro source.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/autoconf"
              "--output=configure"
              "invalid.ac"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/autoconf/autoconf-${version}.tar.xz"
      ];
      hash = "sha256-n9ZyschCX6wvpn+gR3uZCYcmi5D/NtXwFtrle+DWtS4=";
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
          pkgs.findutils
          pkgs.gawk
          pkgs.gnumake
          pkgs.grep
          pkgs.m4
          pkgs.sed
          pkgs.tar
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
