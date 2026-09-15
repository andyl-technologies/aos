{
  lib,
  mkDerivation,
  fetchurl,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  gnumake,
}: let
  version = "4.10";
in
  mkDerivation {
    pname = "sed";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Sed writes the transformed line exactly.";
        "files" = {};
        "input" = "A line containing the decimal value 41.";
        "operation" = "Replace the value with 42 using a basic regular expression.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/sed"
              "s/41/42/"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdin" = "answer=41\n";
            "stdout" = {
              "exact" = "answer=42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Sed rejects the expression with its script-error status.";
        "files" = {};
        "input" = "A substitution expression with an unterminated regular expression.";
        "operation" = "Parse the malformed expression.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/sed"
              "s/[unterminated/42/"
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
      urls = ["https://mirrors.kernel.org/gnu/sed/sed-${version}.tar.xz"];
      hash = "sha256-uOchgrLslqNXTimYxHt6qmTMIM4ADY6awxPMB87PKMc=";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
    runtimeDeps = [];
    configureFlags = "--disable-nls";

    meta = {
      description = "GNU stream editor";
      homepage = "https://www.gnu.org/software/sed/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
