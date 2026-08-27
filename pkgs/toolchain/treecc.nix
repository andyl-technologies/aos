##! TreeCC - Aspect-oriented tree compiler generator
{
  mkDerivation,
  fetchurl,
  bash,
  gnumake,
  buildPackages,
  stdenv,
}: let
  version = "0.3.10";
in
  mkDerivation {
    pname = "treecc";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/old-gnu/dotgnu/pnet/treecc-${version}.tar.gz"
      ];
      hash = "sha256-Xp0gppOODG/t/tDKvH6emEAk5IgbdI0Hbox18a627+c=";
    };

    buildDeps =
      [bash gnumake]
      ++ (
        if stdenv.isCross
        then [buildPackages.automake buildPackages.treecc]
        else []
      );
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd treecc-${version}
          test "$(head -n 1 tests/run_tests)" = '#!/bin/sh'
          sed -i "1c #!$CONFIG_SHELL" tests/run_tests
        '';
      }
      {
        name = "configure";
        script =
          (
            if stdenv.isCross
            then ''
              # The bundled config.sub predates AArch64. Refresh it from the
              # current AOS-built canonical helper before cross configuration.
              cp ${buildPackages.automake}/share/automake-*/config.sub config.sub
            ''
            else ""
          )
          + ''
            "$CONFIG_SHELL" ./configure $configureFlags --prefix=$out
            ${
              if stdenv.isCross
              then ''sed -i "s|\$(top_builddir)/treecc|${buildPackages.treecc}/bin/treecc|g" examples/Makefile''
              else ""
            }
          '';
      }
      {
        name = "build";
        script = ''
          make SHELL="$CONFIG_SHELL" -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.isCross
            then ''echo "skipping target execution tests while cross-compiling for $AOS_TARGET_PLATFORM"''
            else ''make SHELL="$CONFIG_SHELL" -j$NIX_BUILD_CORES check''
          }
        '';
      }
      {
        name = "install";
        script = ''
          make SHELL="$CONFIG_SHELL" install
          test -x "$out/bin/treecc"

          sourceDir=$PWD
          cd "$TMPDIR"
          ${
            if stdenv.isCross
            then "${buildPackages.treecc}/bin/treecc"
            else ''"$out/bin/treecc"''
          } \
            -o expr_c.c \
            -h expr_c.h \
            "$sourceDir/examples/expr_c.tc"
          test -s expr_c.c
          test -s expr_c.h
          cc -I. -c expr_c.c -o expr_c.o
          test -s expr_c.o
          cd "$sourceDir"

          forbidden_shebangs=$(find "$out" -type f -exec grep -I -n -E \
            '^#![[:space:]]*((/bin|/usr/bin|/usr/local/bin)/((ba|da|k|z)?sh)|(/bin|/usr/bin|/usr/local/bin)/env[[:space:]]+(-S[[:space:]]+)?((ba|da|k|z)?sh))([[:space:]]|$)' \
            {} + 2>/dev/null || true)
          if test -n "$forbidden_shebangs"; then
            printf '%s\n' "$forbidden_shebangs" >&2
            echo "forbidden host shell shebang found in treecc output" >&2
            exit 1
          fi

          placeholder_refs=$(find "$out" -type f \
            -exec grep -a -H -n -F '/nix/store/eeee' {} + \
            2>/dev/null || true)
          if test -n "$placeholder_refs"; then
            printf '%s\n' "$placeholder_refs" >&2
            echo "placeholder store reference found in treecc output" >&2
            exit 1
          fi

          dangling_links=$(find "$out" -type l -exec test ! -e {} \; -print)
          if test -n "$dangling_links"; then
            printf '%s\n' "$dangling_links" >&2
            echo "dangling symlink found in treecc output" >&2
            exit 1
          fi
        '';
      }
    ];

    meta = {
      description = "Aspect-oriented tree compiler generator";
      homepage = "https://www.gnu.org/projects/dotgnu/pnet.html";
      license = "GPL-2.0-or-later";
    };
  }
