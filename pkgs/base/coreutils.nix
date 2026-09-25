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
  stdenv,
}: let
  version = "9.11";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
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
    preConfigure =
      if stdenv.hostPlatform.isDarwin
      then ''
        # Gnulib passes translated messages as formats throughout Coreutils.
        # Preserve those calls while keeping Clang's format warning visible.
        export CFLAGS="''${CFLAGS:--g -O2} -Wno-error=format-security"
      ''
      else "";
    # Coreutils 9.10 made these commands opt-in; retain the AOS command set
    # and the server PATH's coreutils precedence over util-linux's kill.
    configureFlags = "--disable-nls --enable-single-binary=symlinks --enable-install-program=kill,uptime";

    meta = {
      description = "GNU core utilities";
      homepage = "https://www.gnu.org/software/coreutils/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
