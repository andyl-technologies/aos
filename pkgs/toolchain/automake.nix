##! GNU Automake — generates Makefile.in from Makefile.am templates
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  autoconf,
  perl,
  bash,
  stdenv,
}: let
  version = "1.18.1";
in
  mkDerivation {
    pname = "automake";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Automake accepts the declarations and emits Makefile.in.";
        "files" = {
          "Makefile.am" = "bin_PROGRAMS = probe\nprobe_SOURCES = probe.c\n";
          "configure.ac" = "AC_INIT([aos-probe], [1.0])\nAM_INIT_AUTOMAKE([foreign])\nAC_PROG_CC\nAC_CONFIG_FILES([Makefile])\nAC_OUTPUT\n";
          "probe.c" = "int main(void) { return 0; }\n";
        };
        "input" = "A minimal foreign Automake project containing one C program.";
        "operation" = "Generate Makefile.in and required helper scripts with automake.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/aclocal"
              "--system-acdir=@out@/share/aclocal"
            ];
            "exit_code" = 0;
          }
          {
            "argv" = [
              "@out@/bin/automake"
              "--add-missing"
              "--foreign"
            ];
            "exit_code" = 0;
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Automake rejects the invalid syntax with status 1.";
        "files" = {
          "Makefile.am" = "this is not automake syntax\n";
          "configure.ac" = "AC_INIT([aos-probe], [1.0])\nAM_INIT_AUTOMAKE([foreign])\nAC_CONFIG_FILES([Makefile])\nAC_OUTPUT\n";
        };
        "input" = "A Makefile.am containing text that is not an assignment or rule.";
        "operation" = "Generate Makefile.in from the malformed declaration.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/automake"
              "--add-missing"
              "--foreign"
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
        "https://mirrors.kernel.org/gnu/automake/automake-${version}.tar.xz"
      ];
      hash = "sha256-FoqjYyeDUbia9WaERI9SWlvOUHnQtoQr2RD90/FkaIc=";
    };

    # Automake invokes both Autoconf and Perl during its build.  Build-dep
    # splicing selects their native outputs while the installed Darwin scripts
    # retain the corresponding target runtimes below.
    buildDeps = [
      gnumake
      autoconf
      perl
      bash
    ];
    runtimeDeps = [
      autoconf
      perl
      bash
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd automake-${version}
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
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            make install

            retarget_tool_root() {
              nativeTool=$(command -v "$1")
              nativeRoot=$(dirname "$(dirname "$nativeTool")")
              targetRoot=$2
              [ "$nativeRoot" = "$targetRoot" ] && return
              # grep's no-match status is expected when the installed files
              # do not embed a particular native tool. Keep pipefail active
              # so a real sed/xargs failure still aborts the phase.
              (grep -IrlZ -F "$nativeRoot" "$out" 2>/dev/null || true) \
                | xargs -0 -r sed -i "s|$nativeRoot|$targetRoot|g"
            }
            retarget_tool_root autoconf ${autoconf}
            retarget_tool_root perl ${perl}

            nativeBashRoot=$(dirname "$(dirname "$CONFIG_SHELL")")
            (grep -IrlZ -F "$nativeBashRoot" "$out" 2>/dev/null || true) \
              | xargs -0 -r sed -i "s|$nativeBashRoot|${bash}|g"
          ''
          else ''
            make install

            retarget_tool_root() {
              nativeTool=$(command -v "$1")
              nativeRoot=$(dirname "$(dirname "$nativeTool")")
              targetRoot=$2
              [ "$nativeRoot" = "$targetRoot" ] && return
              grep -IrlZ -F "$nativeRoot" "$out" 2>/dev/null \
                | xargs -0 -r sed -i "s|$nativeRoot|$targetRoot|g"
            }
            retarget_tool_root autoconf ${autoconf}
            retarget_tool_root perl ${perl}

            nativeBashRoot=$(dirname "$(dirname "$CONFIG_SHELL")")
            grep -IrlZ -F "$nativeBashRoot" "$out" 2>/dev/null \
              | xargs -0 -r sed -i "s|$nativeBashRoot|${bash}|g"
          '';
      }
    ];

    meta = {
      description = "GNU Automake — generates Makefile.in from Makefile.am templates";
      homepage = "https://www.gnu.org/software/automake/";
      license = "GPL-2.0-or-later";
    };
  }
