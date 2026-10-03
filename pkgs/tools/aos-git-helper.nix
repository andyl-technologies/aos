##! aos-git-helper — Closed descriptor-based mechanics for the native Git owner
##!
##! This package supplies an executable, not an admission or publication owner.
##! Root image/namespace custody, private administration, aggregate ODB quota
##! and all-owner drain remain mandatory independent runtime prerequisites.
{
  mkDerivation,
  git,
  coreutils,
  stdenv,
}: let
  sourceDirectory = builtins.path {
    path = ./_aos-git-helper;
    name = "aos-git-helper-source";
  };
  gitProgram = "${git}/bin/git";
in
  assert git.version == "2.55.0" && git.pname == "git";
    mkDerivation {
      pname = "aos-git-helper";
      version = "1";
      src = sourceDirectory;
      dontStrip = true;

      buildDeps = [coreutils];
      runtimeDeps = [git];
      propagatedDeps = [];

      phases = [
        {
          name = "build";
          script = ''
            # Both builds use the same literal paths and pure plan/argv engine.
            for mode in production pure-test; do
              test_flag=
              output=aos-git-helper
              if test "$mode" = pure-test; then
                test_flag=-DAOS_GIT_HELPER_PLAN_TEST=1
                output=aos-git-helper-pure-test
              fi

              $CC -std=c17 -O2 -Wall -Wextra -Werror \
                '-DAOS_GIT_PROGRAM="${gitProgram}"' \
                "-DAOS_GIT_HELPER_PROGRAM=\"$out/libexec/aos-git-helper\"" \
                "-DAOS_GIT_EXEC_DIRECTORY=\"$out/libexec/aos-git-v1\"" \
                "-DAOS_GIT_EMPTY_HOOKS=\"$out/share/aos-git-v1/empty-hooks\"" \
                "-DAOS_GIT_EMPTY_TEMPLATE=\"$out/share/aos-git-v1/empty-template\"" \
                $test_flag ${sourceDirectory}/helper.c -o "$output"
            done
          '';
        }
        {
          name = "check";
          script =
            if stdenv.isCross
            then ''
              printf '%s\n' 'Git helper pure DATA tests: UNRUN (cross-built target)'
            ''
            else ''
              ./aos-git-helper-pure-test
            '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/libexec/aos-git-v1" \
              "$out/share/aos-git-v1/empty-hooks" \
              "$out/share/aos-git-v1/empty-template"

            cp aos-git-helper "$out/libexec/aos-git-helper"
            $STRIP -s "$out/libexec/aos-git-helper"
            chmod 0555 "$out/libexec/aos-git-helper"
            ln -s ${gitProgram} "$out/libexec/aos-git-v1/git"
            chmod 0555 "$out/libexec/aos-git-v1" \
              "$out/share/aos-git-v1/empty-hooks" \
              "$out/share/aos-git-v1/empty-template"
          '';
        }
      ];

      passthru.evidenceSources = [
        (builtins.path {
          path = ./aos-git-helper.nix;
          name = "aos-git-helper.nix";
        })
        (builtins.path {
          path = ./_aos-git-helper/helper.c;
          name = "aos-git-helper.c";
        })
      ];

      meta = {
        description = "Closed AOS Git descriptor execution mechanics";
        license = "Apache-2.0";
        platforms = ["x86_64-linux" "aarch64-linux"];
      };
    }
