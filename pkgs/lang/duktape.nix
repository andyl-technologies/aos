##! duktape — Embeddable JavaScript engine
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  stdenv,
}: let
  version = "2.7.0";
  sharedLibraryPlatform =
    if stdenv.hostPlatform.isDarwin
    then "DETECTED_OS=Darwin"
    else "";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "duktape";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <duktape.h>\n\nint main(void) {\n    duk_context *context = duk_create_heap_default();\n    if (context == NULL) {\n        return 2;\n    }\n    if (duk_peval_string(context, \"[19, 23].reduce(function(a, b) { return a + b; }, 0)\") != 0\n        || duk_get_int(context, -1) != 42) {\n        duk_destroy_heap(context);\n        return 3;\n    }\n    duk_destroy_heap(context);\n    return puts(\"duktape api passed\") == EOF;\n}\n";
        };
        "input" = "A JavaScript expression reducing an integer array.";
        "operation" = "Evaluate the expression with Duktape and verify its numeric result.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lduktape"
              "-lm"
              "-o"
              "primary-consumer"
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
              "@work@/primary/primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "duktape api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <duktape.h>\n\nint main(void) {\n    duk_context *context = duk_create_heap_default();\n    if (context == NULL) {\n        return 2;\n    }\n    int status = duk_peval_string(context, \"function broken( {\");\n    duk_destroy_heap(context);\n    if (status == 0) {\n        return 3;\n    }\n    fputs(\"duktape rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A JavaScript function declaration with an incomplete parameter list.";
        "operation" = "Evaluate the malformed source with protected Duktape evaluation.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lduktape"
              "-lm"
              "-o"
              "bad-input-consumer"
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
              "@work@/bad-input/bad-input-consumer"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "duktape rejected invalid input\n";
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
      urls = ["https://duktape.org/duktape-${version}.tar.xz"];
      hash = "sha256-kPjS+otVZ8aJmDDd7ywD88J5YLEayiIvoXqnrGE8KJA=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd duktape-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" -f Makefile.cmdline
          # Upstream detects the build host with uname, which is Linux here.
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              sed -i \
                -e 's|-Wl,$(LD_SONAME_ARG),libduktape\.|-Wl,$(LD_SONAME_ARG),$(INSTALL_PREFIX)$(LIBDIR)/libduktape.|g' \
                -e 's|-Wl,$(LD_SONAME_ARG),libduktaped\.|-Wl,$(LD_SONAME_ARG),$(INSTALL_PREFIX)$(LIBDIR)/libduktaped.|g' \
                Makefile.sharedlibrary
              make -j"$NIX_BUILD_CORES" -f Makefile.sharedlibrary ${sharedLibraryPlatform} INSTALL_PREFIX="$out"
            ''
            else ''make -j"$NIX_BUILD_CORES" -f Makefile.sharedlibrary''
          }
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm755 duk "$out/bin/duk"
          make -f Makefile.sharedlibrary ${sharedLibraryPlatform} INSTALL_PREFIX="$out" install
          sed -i "s|^prefix=/usr/local$|prefix=$out|" \
            "$out/lib/pkgconfig/duktape.pc"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-duktape";
        library = self;
        libs = ["-lduktape"];
        testSource = ''
          #include <duktape.h>

          int main(void) {
              duk_context *context = duk_create_heap_default();
              if (context == NULL) {
                  return 1;
              }
              duk_destroy_heap(context);
              return 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-duktape";
        tool = self;
        command = "printf 'print(6 * 7);' | duk | grep -qx 42";
      };
    };

    meta = {
      description = "Embeddable JavaScript engine focused on portability";
      homepage = "https://duktape.org/";
      license = "MIT";
      mainProgram = "duk";
    };
  }
