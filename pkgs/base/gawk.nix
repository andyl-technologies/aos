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
  sed,
  bash,
}: let
  version = "5.4.1";
in
  mkDerivation {
    pname = "gawk";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Awk emits the exact aggregate.";
        "files" = {};
        "input" = "Two colon-delimited records.";
        "operation" = "Sum the numeric second fields with awk.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/awk"
              "-F:"
              "{ total += $2 } END { print total }"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdin" = "alpha:19\nbeta:23\n";
            "stdout" = {
              "exact" = "42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Awk rejects the syntax error with status 1.";
        "files" = {};
        "input" = "An awk program with an unterminated action.";
        "operation" = "Parse the malformed awk program.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/awk"
              "{ print $1"
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
      urls = ["https://mirrors.kernel.org/gnu/gawk/gawk-${version}.tar.xz"];
      hash = "sha256-B/b3NCt/6+QxP8LCVCrZPWT+IK2HFyABCfEFqCb1/Tc=";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake sed];
    runtimeDeps = [bash];
    configureFlags = "--disable-nls";
    postInstall = ''
      [ -f "$out/bin/gawk" ] && [ ! -e "$out/bin/awk" ] && ln -s gawk "$out/bin/awk"
      if [ -f "$out/bin/gawkbug" ]; then
        sed -i \
          -e "1s|^#!.*|#!${bash}/bin/bash|" \
          -e 's|^CC=.*|CC="gcc"|' \
          -e 's|^CFLAGS=.*|CFLAGS=""|' \
          "$out/bin/gawkbug"
      fi
    '';

    meta = {
      description = "GNU pattern scanning and processing language";
      homepage = "https://www.gnu.org/software/gawk/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
