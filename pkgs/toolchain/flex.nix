##! flex — Fast lexical analyzer generator
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  stdenv,
}: let
  version = "2.6.4";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "flex";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The scanner emits the expected token classes and values.";
        "files" = {
          "scanner.l" = "%option noyywrap\n%{\n#include <stdio.h>\n%}\n%%\n[0-9]+       { printf(\"integer:%s\\n\", yytext); }\n[[:alpha:]]+ { printf(\"word:%s\\n\", yytext); }\n[[:space:]]+ ;\n.            { return 2; }\n%%\nint main(void) { return yylex(); }\n";
        };
        "input" = "A scanner recognizing decimal integers and words.";
        "operation" = "Generate and compile the scanner, then tokenize a fixed input.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/flex"
              "-o"
              "scanner.c"
              "scanner.l"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@cc@"
              "scanner.c"
              "-o"
              "scanner"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/scanner"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdin" = "alpha 42\n";
            "stdout" = {
              "exact" = "word:alpha\ninteger:42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Flex rejects the malformed rule with status 1.";
        "files" = {
          "invalid.l" = "%option noyywrap\n%%\n[abc { return 0; }\n%%\n";
        };
        "input" = "A scanner specification with an unterminated character class.";
        "operation" = "Ask Flex to generate a scanner from the malformed rule.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/flex"
              "-o"
              "invalid.c"
              "invalid.l"
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
      urls = [
        "https://github.com/westes/flex/releases/download/v${version}/flex-${version}.tar.gz"
      ];
      hash = "sha256-6HquAyvwfCb4WsDtMlCZjDdiHZX4vXSLMfFbM8Re6ZU=";
    };

    buildDeps = [
      gnumake
      m4
    ];
    # flex exec()s m4 at runtime to expand the generated scanner skeleton
    # templates; without m4 in runtimeDeps, the scrubPhase nuke-refs pass
    # would rewrite flex's hardcoded m4 path and break every downstream
    # `make flex` invocation.
    runtimeDeps = [m4];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd flex-${version}
        '';
      }
      {
        name = "configure";
        script =
          (
            if stdenv.hostPlatform.isDarwin
            then ''
              # Flex builds stage1flex for the build machine. Autoconf already
              # separates its flags, but the native AOS compiler wrapper would
              # otherwise still inherit the target SDK and hardening settings.
              native_cc="$BUILD_CC"
              mkdir -p .aos-build-tools
              cat > .aos-build-tools/cc-for-build <<EOF
              #!$CONFIG_SHELL
              unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
              unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
              exec "$native_cc" "\$@"
              EOF
              chmod +x .aos-build-tools/cc-for-build
              export CC_FOR_BUILD="$PWD/.aos-build-tools/cc-for-build"
              export CFLAGS_FOR_BUILD=
              export CPPFLAGS_FOR_BUILD=
              export LDFLAGS_FOR_BUILD=

              # Darwin malloc(0) and realloc(0) return usable allocations.
              # Avoid configuring target replacement functions into the
              # config.h shared with the native stage1 generator.
              export ac_cv_func_malloc_0_nonnull=yes
              export ac_cv_func_realloc_0_nonnull=yes

              # libfl intentionally supplies main() while leaving yylex() to
              # the generated scanner linked by its consumer. Mach-O requires
              # that plugin-style unresolved symbol policy to be explicit.
              sed -i \
                's/^libfl_la_LDFLAGS = \(.*\)$/libfl_la_LDFLAGS = \1 -Wl,-undefined,dynamic_lookup/' \
                src/Makefile.in
            ''
            else if stdenv.isCross && stdenv.hostPlatform.isLinux
            then ''
              # AOS glibc returns nonnull allocations for malloc(0) and
              # realloc(NULL, 0); Flex's cross defaults incorrectly assume no.
              export ac_cv_func_malloc_0_nonnull=yes
              export ac_cv_func_realloc_0_nonnull=yes

              # stage1flex always compiles this fallback during cross builds,
              # even when the target libc needs no allocation replacement.
              sed -i 's/void \*malloc ();/#include <stdlib.h>/' lib/malloc.c

              # The installed generator executes m4 at runtime. PATH contains
              # build tools, so configure must record the target dependency.
              export M4=${m4}/bin/m4
            ''
            else ""
          )
          + ''
            ./configure \
              $configureFlags \
              --prefix=$out
          '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "flex — fast lexical analyzer generator";
      homepage = "https://github.com/westes/flex";
      license = "BSD-2-Clause";
    };
  }
