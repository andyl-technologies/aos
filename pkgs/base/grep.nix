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
  pcre2,
  stdenv,
}: let
  version = "3.12";
in
  mkDerivation ({
      platformSupport = {
        build = [{abi = ["gnu"]; os = ["linux"];}];
        host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
        target = [];
        role = "public-package";
      };
      pname = "grep";
      qualification.packageProbe = lib.qualification.commandProbe {
        "primary" = {
          "artifacts" = [];
          "expected" = "Grep emits exactly the two matching records.";
          "files" = {};
          "input" = "Three records, two of which end in a decimal digit.";
          "operation" = "Select records matching an extended regular expression.";
          "steps" = [
            {
              "argv" = [
                "@out@/bin/grep"
                "-E"
                "^[a-z]+[0-9]$"
              ];
              "exit_code" = 0;
              "stderr" = {
                "exact" = "";
              };
              "stdin" = "alpha1\nbeta\ngamma3\n";
              "stdout" = {
                "exact" = "alpha1\ngamma3\n";
              };
            }
          ];
        };
        "badInput" = {
          "artifacts" = [];
          "expected" = "Grep rejects the expression with status 2.";
          "files" = {};
          "input" = "An extended regular expression with an unterminated group.";
          "operation" = "Compile the invalid regular expression.";
          "steps" = [
            {
              "argv" = [
                "@out@/bin/grep"
                "-E"
                "("
              ];
              "exit_code" = 2;
              "observes_rejection" = true;
              "stdin" = "anything\n";
              "stdout" = {
                "exact" = "";
              };
            }
          ];
        };
      };

      inherit version;

      src = fetchurl {
        urls = ["https://mirrors.kernel.org/gnu/grep/grep-${version}.tar.xz"];
        hash = "sha256-JkmyfA6Q5jLq3NdXvgbG6aT0jZQd5R58D4P/dkCKB7k=";
      };

      buildDeps = [m4 flex bison autoconf automake texinfo gnumake sed];
      runtimeDeps = [bash pcre2];
      configureFlags = "--disable-nls";
      postInstall = ''
        for f in "$out/bin/egrep" "$out/bin/fgrep"; do
          [ -f "$f" ] || continue
          sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$f"
        done
      '';

      meta = {
        description = "GNU pattern matching utility";
        homepage = "https://www.gnu.org/software/grep/";
        license = "GPL-3.0-or-later";
        platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
      };
    }
    // (
      if stdenv.hostPlatform.isDarwin
      then {
        postPatch = ''
          # Gnulib still uses obsolete flat Darwin header names here. The Mach
          # declarations formerly supplied by libc.h are public through the
          # headers included afterward; nlist lives below mach-o in modern SDKs.
          sed -i '/^#include <libc\.h>$/d' lib/stackvma.c
          sed -i 's|^#include <nlist\.h>$|#include <mach-o/nlist.h>|' lib/stackvma.c
        '';
      }
      else {}
    ))
