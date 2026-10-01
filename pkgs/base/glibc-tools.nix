##! glibc-tools — complete libc utilities using distribution interpreters
{
  lib,
  mkDerivation,
  glibc,
  perl,
  bash,
}: let
  version = glibc.version;
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The installed target command and its offline query.";
        operation = "Execute the packaged command without network or persistent state.";
        expected = "The target command reports its documented query result.";
        files = {};
        steps = [
          {
            argv = ["@python@" "-c" "import subprocess\nresult = subprocess.run(['@out@/bin/getconf', 'ARG_MAX'], capture_output=True, text=True)\nassert result.returncode == 0 and (result.stdout.strip().isdigit() and int(result.stdout.strip()) > 0), (result.returncode, result.stdout, result.stderr)\nprint('glibc-tools command passed')\n"];
            exit_code = 0;
            stdout.exact = "glibc-tools command passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "An unknown command option or variable.";
        operation = "Parse and reject the invalid request.";
        expected = "The target command fails before performing the operation.";
        files = {};
        steps = [
          {
            argv = ["@python@" "-c" "import subprocess, sys\nresult = subprocess.run(['@out@/bin/getconf', 'AOS_UNKNOWN_VARIABLE'], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write('glibc-tools rejected invalid input\\n')\nraise SystemExit(7)\n"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "glibc-tools rejected invalid input\n";
          }
        ];
        artifacts = [];
      };
    };
    pname = "glibc-tools";
    version = glibc.versionRequirement or version;

    # The utility tree is target data copied by native build tools.
    src = glibc.bin;
    buildDeps = [];
    runtimeDeps = [glibc perl bash];
    dontNukeRefs = true;

    passthru.evidenceSources = glibc.passthru.evidenceSources;

    phases = [
      {
        name = "install";
        script = ''
          cp -R ${glibc.bin}/. "$out/"
          chmod -R u+w "$out"

          # The bootstrap utility export deliberately uses its tier's Perl.
          # Rebind mtrace to the distribution interpreter without losing tools.
          construction_perl=$(head -n 1 "$out/bin/mtrace" | sed 's/^#! *//')
          test -n "$construction_perl"
          sed -i "s|$construction_perl|${perl}/bin/perl|g" "$out/bin/mtrace"

          # xtrace locates its companion programs through the utility export.
          sed -i "s|${glibc.bin}/|$out/|g" "$out/bin/xtrace"
        '';
      }
    ];

    meta = {
      description = "Complete GNU C Library utilities with distribution interpreters";
      homepage = "https://www.gnu.org/software/libc/";
      license = "LGPL-2.1-or-later";
      build.os = "linux";
      execute.os = "linux";
    };
  }
