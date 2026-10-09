{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
}: let
  version = "4.4";
in
  mkDerivation (
    {
      platformSupport = {
        build = [{abi = ["gnu"]; os = ["linux"];}];
        host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
        target = [];
        role = "public-package";
      };
      pname = "gnumake";
      qualification.packageProbe = lib.qualification.commandProbe {
        "primary" = {
          "artifacts" = [
            {
              "path" = "result.txt";
              "text" = "make result: 42\n";
            }
          ];
          "expected" = "Make runs the recipe and creates the exact output artifact.";
          "files" = {
            "Makefile" = "       value = 42\n       result.txt:\nprintf 'make result: %s\\n' '$(value)' > result.txt\n";
          };
          "input" = "A makefile deriving an output file from an input variable.";
          "operation" = "Build the declared target with GNU Make.";
          "steps" = [
            {
              "argv" = [
                "@out@/bin/make"
                "--no-print-directory"
                "result.txt"
              ];
              "exit_code" = 0;
              "stderr" = {
                "exact" = "";
              };
              "stdout" = {
                "exact" = "printf 'make result: %s\\n' '42' > result.txt\n";
              };
            }
          ];
        };
        "badInput" = {
          "artifacts" = [];
          "expected" = "Make rejects the target with status 2.";
          "files" = {
            "Makefile" = "all:\n\t@:\n";
          };
          "input" = "A requested target with no rule in an otherwise valid makefile.";
          "operation" = "Ask GNU Make to build the undefined target.";
          "steps" = [
            {
              "argv" = [
                "@out@/bin/make"
                "--no-print-directory"
                "missing-target"
              ];
              "exit_code" = 2;
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
        urls = ["https://mirrors.kernel.org/gnu/make/make-${version}.tar.gz"];
        hash = "062x21wpjjhxxv6bscipy015ilx7k1c22x6884wlp9rdhx74s7sq";
      };

      # The cross stdenv already supplies the native make used for this bootstrap.
      buildDeps = [m4 flex bison autoconf automake texinfo];
      runtimeDeps = [];
      configureFlags = "--disable-nls";

      meta = {
        description = "GNU Make build automation tool";
        homepage = "https://www.gnu.org/software/make/";
        license = "GPL-3.0-or-later";
        platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
      };
    }
    // (
      if stdenv.isCross && stdenv.hostPlatform.isDarwin
      then {
        postPatch = ''
          # Make 4.4's bundled glob predates modern C prototypes and wraps
          # realloc with a char-pointer-only K&R interface. Darwin's Clang 22
          # correctly rejects its char ** call sites; use the standard
          # pointer-generic signature adopted by the subsequent upstream code.
          sed -i '/^my_realloc (p, n)$/,/^     unsigned int n;$/ {
            s/^     char \*p;$/     void *p;/
          }' lib/glob.c
        '';
      }
      else {}
    )
  )
