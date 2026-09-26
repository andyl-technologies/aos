##! bash-completion — Programmable completion functions for Bash
{
  lib,
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  gnumake,
}: let
  version = "2.18.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "bash-completion";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Bash loads the engine and exposes its command and word completion functions.";
        "files" = {};
        "input" = "The installed programmable-completion engine.";
        "operation" = "Load it in a clean Bash process and resolve its core completion helpers.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nscript = 'source \"@out@/share/bash-completion/bash_completion\"; declare -F _init_completion >/dev/null; declare -F _command >/dev/null'\nresult = subprocess.run([\"@bash@\", \"--noprofile\", \"--norc\", \"-c\", script], capture_output=True)\nassert result.returncode == 0, result.stderr\nprint(\"bash-completion data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "bash-completion data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Bash reports that the requested completion function is unavailable.";
        "files" = {};
        "input" = "A request for a completion helper that the installed engine does not define.";
        "operation" = "Load the engine and resolve the absent helper name.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nscript = 'source \"@out@/share/bash-completion/bash_completion\"; declare -F _aos_nonexistent_completion'\nresult = subprocess.run([\"@bash@\", \"--noprofile\", \"--norc\", \"-c\", script], capture_output=True)\nif result.returncode == 0:\n    raise SystemExit(2)\nsys.stderr.write(\"bash-completion rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "bash-completion rejected invalid input\n";
            };
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
        "https://github.com/scop/bash-completion/releases/download/${version}/bash-completion-${version}.tar.xz"
      ];
      hash = "sha256-iLz4UST3f3Ty8vi80WrEOC2AeoJ+3nQqZJQMcRauoz8=";
    };

    buildDeps = [autoconf automake gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    configureFlags = "--without-cowsay --without-gnuplot";

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-bash-completion";
        tool = self;
        command = "test -r ${self}/share/bash-completion/bash_completion";
      };
    };

    meta = {
      description = "Programmable completion functions for Bash";
      homepage = "https://github.com/scop/bash-completion";
      license = "GPL-2.0-or-later";
    };
  }
