##! utf8proc — UTF-8 Unicode processing library
{
  lib,
  mkDerivation,
  fetchurl,
  cmake,
  ninja,
  stdenv,
}: let
  version = "2.11.3";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "utf8proc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <utf8proc.h>\n\nint main(void) {\n    const utf8proc_uint8_t input[] = {0xe2, 0x82, 0xac};\n    utf8proc_int32_t codepoint = 0;\n    if (utf8proc_iterate(input, sizeof(input), &codepoint) != 3 || codepoint != 0x20ac) {\n        return 2;\n    }\n    return puts(\"utf8proc api passed\") == EOF;\n}\n";
        };
        "input" = "The three-byte UTF-8 encoding of U+20AC EURO SIGN.";
        "operation" = "Decode the sequence through utf8proc_iterate and verify its code point and width.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lutf8proc"
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
              "exact" = "utf8proc api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <utf8proc.h>\n\nint main(void) {\n    const utf8proc_uint8_t input[] = {0xc0, 0xaf};\n    utf8proc_int32_t codepoint = 0;\n    if (utf8proc_iterate(input, sizeof(input), &codepoint) != UTF8PROC_ERROR_INVALIDUTF8) {\n        return 2;\n    }\n    fputs(\"utf8proc rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "An overlong two-byte UTF-8 encoding.";
        "operation" = "Decode the malformed sequence through utf8proc_iterate.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lutf8proc"
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
              "exact" = "utf8proc rejected invalid input\n";
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
      urls = [
        "https://github.com/JuliaStrings/utf8proc/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-q/7VC21NpRNFcTZhNwKQ9PR0cmPuc9yQNWKZ38eZDHg=";
    };

    buildDeps = [cmake ninja];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd utf8proc-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX="$out" \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DBUILD_SHARED_LIBS=ON \
            -DUTF8PROC_ENABLE_TESTING=ON
        '';
      }
      {
        name = "build";
        script = ''ninja -C build -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "check";
        # Cross-target test programs run during target qualification.
        script = if stdenv.isCross then ":" else ''ninja -C build test'';
      }
      {
        name = "install";
        script = ''ninja -C build install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-utf8proc";
        library = self;
        libs = ["-lutf8proc"];
        testSource = ''
          #include <stdio.h>
          #include <utf8proc.h>

          int main(void) {
              printf("%s\n", utf8proc_version());
              return utf8proc_codepoint_valid(0x1f642) ? 0 : 1;
          }
        '';
      };
    };

    meta = {
      description = "UTF-8 Unicode processing library";
      homepage = "https://juliastrings.github.io/utf8proc/";
      license = "MIT AND Unicode-3.0";
    };
  }
