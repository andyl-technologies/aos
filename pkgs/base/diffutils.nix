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
  gnumake,
  coreutils,
}: let
  version = "3.12";
in
  mkDerivation (
    {
      platformSupport = {
        build = [{abi = ["gnu"]; os = ["linux"];}];
        host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
        target = [];
        role = "public-package";
      };
      pname = "diffutils";
      qualification.packageProbe = lib.qualification.commandProbe {
        "primary" = {
          "artifacts" = [];
          "expected" = "Cmp confirms equality with a silent success.";
          "files" = {
            "left.txt" = "same bytes\n";
            "right.txt" = "same bytes\n";
          };
          "input" = "Two files with identical bytes.";
          "operation" = "Compare the files byte for byte.";
          "steps" = [
            {
              "argv" = [
                "@out@/bin/cmp"
                "@work@/primary/left.txt"
                "@work@/primary/right.txt"
              ];
              "exit_code" = 0;
              "stderr" = {
                "exact" = "";
              };
              "stdout" = {
                "exact" = "";
              };
            }
          ];
        };
        "badInput" = {
          "artifacts" = [];
          "expected" = "Cmp reports inequality through status 1.";
          "files" = {
            "left.txt" = "alpha\n";
            "right.txt" = "alpHa\n";
          };
          "input" = "Two files differing in one byte.";
          "operation" = "Compare the unequal files in silent mode.";
          "steps" = [
            {
              "argv" = [
                "@out@/bin/cmp"
                "--silent"
                "@work@/bad-input/left.txt"
                "@work@/bad-input/right.txt"
              ];
              "exit_code" = 1;
              "observes_rejection" = true;
              "stderr" = {
                "exact" = "";
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
        urls = ["https://mirrors.kernel.org/gnu/diffutils/diffutils-${version}.tar.xz"];
        hash = "sha256-fIt/n8hgkUH96pzs6FJJ0whiQ5H/Yd7a9Sj8szdyff0=";
      };

      buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
      runtimeDeps = [coreutils];
      configureFlags = "--disable-nls PR_PROGRAM=${coreutils}/bin/pr";

      meta = {
        description = "GNU file comparison utilities";
        homepage = "https://www.gnu.org/software/diffutils/";
        license = "GPL-3.0-or-later";
        platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
      };
    }
    // (
      if stdenv.isCross && stdenv.hostPlatform.isDarwin
      then {
        postPatch = ''
          # This old gnulib snapshot includes Apple's legacy libc.h and
          # nlist.h headers in its Mach VM implementation, but uses no
          # declarations from either. Modern Darwin SDKs expose the required
          # API through mach/mach.h directly.
          sed -i -e '/^#include <libc\.h>$/d' -e '/^#include <nlist\.h>$/d' \
            lib/stackvma.c
        '';
      }
      else if stdenv.isCross && stdenv.hostPlatform.isLinux
      then {
        # Configure selects this gnulib result for Linux, then erroneously
        # runs the locale probe even in cross mode. Preserve its own default.
        gl_cv_func_strcasecmp_works = "guessing yes";
      }
      else {}
    )
  )
