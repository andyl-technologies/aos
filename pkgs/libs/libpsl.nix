##! libpsl — Public Suffix List library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  python3,
  libidn2,
  libunistring,
  publicsuffix-list,
}: let
  version = "0.23.3";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libpsl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "co.uk is public while example.co.uk is not itself a public suffix.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libpsl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libpsl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libpsl.h>\nint main(void) {\n    const psl_ctx_t *context = psl_builtin();\n    if (context == NULL) return 2;\n    return psl_is_public_suffix(context, \"co.uk\")\n        && !psl_is_public_suffix(context, \"example.co.uk\") ? pass() : 3;\n}\n\n";
        };
        "input" = "The public suffix co.uk and the private domain example.co.uk.";
        "operation" = "Query both names through libpsl's built-in suffix context.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpsl"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "libpsl primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libpsl does not classify the malformed name as a public suffix.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libpsl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libpsl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libpsl.h>\nint main(void) {\n    const psl_ctx_t *context = psl_builtin();\n    if (context == NULL || psl_is_public_suffix(context, \"example..com\")) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A domain with an empty label between two dots.";
        "operation" = "Query the malformed domain through the public-suffix classifier.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpsl"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "libpsl rejected invalid input\n";
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
      urls = ["https://github.com/rockdaboot/libpsl/releases/download/${version}/libpsl-${version}.tar.gz"];
      hash = "sha256-k5QfhaHnvVk/qU8pkjPLXfyRzRRP2aeKbOt1ABxbA74=";
    };

    buildDeps = [gnumake pkg-config python3];
    runtimeDeps = [libidn2 libunistring publicsuffix-list];
    propagatedDeps = [libidn2 libunistring];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd libpsl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix="$out" \
            --enable-runtime=libidn2 \
            --enable-builtin \
            --disable-man \
            --with-psl-distfile="${publicsuffix-list}/share/publicsuffix/public_suffix_list.dat" \
            --with-psl-file="${publicsuffix-list}/share/publicsuffix/public_suffix_list.dat" \
            --with-psl-testfile="${publicsuffix-list}/share/publicsuffix/test_psl.txt"
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libpsl";
        library = self;
        libs = ["-lpsl"];
        testSource = ''
          #include <libpsl.h>

          int main(void) {
              const psl_ctx_t *ctx = psl_builtin();
              return ctx != 0 && psl_is_public_suffix(ctx, "com") ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "C library for the Public Suffix List";
      homepage = "https://rockdaboot.github.io/libpsl/";
      license = "MIT";
      mainProgram = "psl";
    };
  }
