##! GNU Automake — generates Makefile.in from Makefile.am templates
{
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
