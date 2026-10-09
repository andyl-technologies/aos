##! GNU libiberty — Portable support functions and symbol demangling.
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
}: let
  version = "2.43";
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
    pname = "libiberty";
    qualification.packageProbe = lib.qualification.commandProbe (let
      source = ''
        #include <libiberty/demangle.h>
        #include <stdlib.h>
        #include <string.h>

        int main(int argc, char **argv) {
            if (argc != 2) return 2;
            char *result = cplus_demangle(argv[1], DMGL_PARAMS | DMGL_ANSI);
            if (result == NULL) return 7;
            int failed = strcmp(result, "answer()") != 0;
            free(result);
            return failed;
        }
      '';
      compile = {
        argv = ["@cc@" "probe.c" "-I@out@/include" "-L@out@/lib" "-liberty" "-o" "probe"];
        exit_code = 0;
        stdout.exact = "";
        stderr.exact = "";
      };
    in {
      primary = {
        input = "The Itanium C++ ABI symbol _Z6answerv.";
        operation = "Demangle the symbol and check the result.";
        expected = "The demangler returns answer().";
        files."probe.c" = source;
        artifacts = [];
        steps = [
          compile
          {
            argv = ["@work@/primary/probe" "_Z6answerv"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A malformed mangled symbol.";
        operation = "Demangle an invalid symbol.";
        expected = "The demangler returns null and the consumer records rejection.";
        files."probe.c" = source;
        artifacts = [];
        steps = [
          compile
          {
            argv = ["@work@/bad-input/probe" "_Zinvalid"];
            exit_code = 7;
            observes_rejection = true;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
      };
    });
    version = "=${version}.0";

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/binutils/binutils-${version}.tar.xz"
        "https://ftpmirror.gnu.org/gnu/binutils/binutils-${version}.tar.xz"
      ];
      hash = "sha256-tTYG9EOsjwHR1fycOUl/KvMi2Z4UzqXAtLEk1jA3k2U=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [zlib];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd binutils-${version}/libiberty
          # Shared consumers require the PIC archive, not the ordinary static archive.
          sed -i 's|$(INSTALL_DATA) $(TARGETLIB) |$(INSTALL_DATA) pic/$(TARGETLIB) |' Makefile.in
        '';
      }
      {
        name = "configure";
        script = ''
          "$CONFIG_SHELL" ./configure \
            --prefix="$out" \
            --enable-shared \
            --enable-install-libiberty
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"
        '';
      }
      {
        name = "check";
        script = ''
          make check SHELL="$CONFIG_SHELL"
        '';
      }
      {
        name = "install";
        script = ''
          make install SHELL="$CONFIG_SHELL" MULTIOSDIR=.
          test -s "$out/lib/libiberty.a"
          mkdir -p "$out/share/licenses/libiberty"
          cp COPYING.LIB "$out/share/licenses/libiberty/"
        '';
      }
    ];

    meta = {
      description = "GNU portable support functions and C++ symbol demangling";
      homepage = "https://www.gnu.org/software/binutils/";
      license = "LGPL-2.1-or-later";
    };
  }
