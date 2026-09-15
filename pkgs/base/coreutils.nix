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
  perl,
}: let
  version = "9.11";
in
  mkDerivation {
    pname = "coreutils";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Printf emits the exact padded record.";
        "files" = {};
        "input" = "A string and integer for a padded format conversion.";
        "operation" = "Format the values with GNU printf.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/printf"
              "%s:%03d\\n"
              "qualified"
              "7"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "qualified:007\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "GNU printf diagnoses the invalid number and returns status 1.";
        "files" = {};
        "input" = "A character that is not a valid integer operand.";
        "operation" = "Apply an integer conversion to the invalid operand.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/printf"
              "%d\\n"
              "x"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "0\n";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/coreutils/coreutils-${version}.tar.xz"];
      hash = "sha256-OUAk7aCllVIXztqc0SAeZdyPo6opwpURNaSVIdV8PMM=";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake perl];
    runtimeDeps = [];
    configureFlags = "--disable-nls --enable-single-binary=symlinks";

    meta = {
      description = "GNU core utilities";
      homepage = "https://www.gnu.org/software/coreutils/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
