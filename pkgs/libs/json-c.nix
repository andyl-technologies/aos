##! json-c — JSON parser/generator for C
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  cmake,
  gnumake,
  pkg-config,
}: let
  version = "0.19";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "json-c";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The parsed array contains two integers whose sum is 42.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"json-c primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"json-c rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <json-c/json.h>\nint main(void) {\n    struct json_object *root = json_tokener_parse(\"[19,23]\");\n    if (root == NULL || json_object_array_length(root) != 2) return 2;\n    int sum = json_object_get_int(json_object_array_get_idx(root, 0))\n        + json_object_get_int(json_object_array_get_idx(root, 1));\n    json_object_put(root);\n    return sum == 42 ? pass() : 3;\n}\n\n";
        };
        "input" = "A JSON array containing two integers.";
        "operation" = "Parse the array and sum its elements through json-c.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ljson-c"
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
              "exact" = "json-c primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "json-c records an incomplete-input error instead of returning a value.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"json-c primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"json-c rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <json-c/json.h>\nint main(void) {\n    struct json_tokener *tokener = json_tokener_new();\n    struct json_object *root = json_tokener_parse_ex(tokener, \"[1,\", 3);\n    enum json_tokener_error error = json_tokener_get_error(tokener);\n    if (root != NULL || error == json_tokener_success) return 2;\n    json_tokener_free(tokener);\n    return reject();\n}\n\n";
        };
        "input" = "A truncated JSON array.";
        "operation" = "Parse the malformed array with an explicit json_tokener.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ljson-c"
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
              "exact" = "json-c rejected invalid input\n";
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
        "https://s3.amazonaws.com/json-c_releases/releases/json-c-${version}.tar.gz"
        "https://github.com/json-c/json-c/archive/refs/tags/json-c-${version}-20240915.tar.gz"
      ];
      hash = "sha256-N60CSZAuMBvZBSv3EuUR/Mas/07KrUtZAKrZzlZOJt4=";
    };

    buildDeps = [
      cmake
      gnumake
      pkg-config
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if isDarwinCross
          then ''
            tar xf $src
            cd json-c-${version}

            # Cross CMake uses static-library try-compiles, which falsely
            # report ELF-only linker switches as supported. Keep the probes
            # for other hosts, but never apply them to a Mach-O link.
            sed -i \
              -e 's/if (DISABLE_BSYMBOLIC STREQUAL "OFF" AND BSYMBOLIC_WORKS)/if (DISABLE_BSYMBOLIC STREQUAL "OFF" AND BSYMBOLIC_WORKS AND NOT APPLE)/' \
              -e 's/if (VERSION_SCRIPT_WORKS)/if (VERSION_SCRIPT_WORKS AND NOT APPLE)/' \
              CMakeLists.txt
          ''
          else ''
            tar xf $src
            cd json-c-${version}
          '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DBUILD_SHARED_LIBS=ON \
            -DBUILD_STATIC_LIBS=OFF \
            -DBUILD_APPS=OFF \
            -DBUILD_TESTING=OFF \
            -DDISABLE_WERROR=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build . -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install .
        '';
      }
    ];

    meta = {
      description = "JSON parser and generator for C";
      homepage = "https://github.com/json-c/json-c";
      license = "MIT";
    };
  }
