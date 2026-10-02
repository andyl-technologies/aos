##! jansson — C library for encoding, decoding and manipulating JSON data
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  stdenv,
  gnumake,
  cmake,
  ninja,
}: let
  upstream = mkGithubUpstream {
    unitId = "jansson-2";
    family = "jansson";
    stream = "2";
    owner = "pkgs/libs/jansson.nix";
    version = "2.15.1";
    upstreamId = "v2.15.1";
    repository = "akheron/jansson";
    provider = "github-releases";
    tagPrefix = "v";
    major = 2;
    source = {
      authority = "github.com";
      path = [
        "akheron"
        "jansson"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {literal = "v";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-2/lcsK+QP0+4thUH2WtFtn230UeWiO3jUuHVcTlNBvc=";
    };
  };
  inherit (upstream) version;
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "jansson";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The parser returns an object whose answer member is the integer 42.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"jansson primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"jansson rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <jansson.h>\nint main(void) {\n    json_error_t error;\n    json_t *root = json_loads(\"{\\\"answer\\\":42}\", 0, &error);\n    if (root == NULL) return 2;\n    json_t *answer = json_object_get(root, \"answer\");\n    int ok = json_is_integer(answer) && json_integer_value(answer) == 42;\n    json_decref(root);\n    return ok ? pass() : 3;\n}\n\n";
        };
        "input" = "A JSON object containing an integer member.";
        "operation" = "Parse the object and read the member through Jansson's public API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ljansson"
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
              "exact" = "jansson primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Jansson reports a parse error and does not return a JSON value.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"jansson primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"jansson rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <jansson.h>\nint main(void) {\n    json_error_t error;\n    json_t *root = json_loads(\"{\\\"answer\\\":42,}\", 0, &error);\n    if (root != NULL || error.line != 1) { json_decref(root); return 2; }\n    return reject();\n}\n\n";
        };
        "input" = "A JSON object with a trailing comma.";
        "operation" = "Pass the malformed document to json_loads.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ljansson"
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
              "exact" = "jansson rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [
      gnumake
      cmake
      ninja
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
            cd jansson-${version}

            # Cross CMake uses static-library try-compiles, which falsely
            # report ELF symbol-version linker switches as supported. Mach-O
            # shared libraries do not use GNU symbol-version scripts.
            sed -i \
              -e 's/if (SYMVER_WORKS)/if (SYMVER_WORKS AND NOT APPLE)/' \
              -e 's/if (VSCRIPT_WORKS)/if (VSCRIPT_WORKS AND NOT APPLE)/' \
              CMakeLists.txt
          ''
          else ''
            tar xf $src
            cd jansson-${version}
          '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DJANSSON_BUILD_SHARED_LIBS=ON \
            -DJANSSON_BUILD_DOCS=OFF
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-jansson";
        library = self;
        libs = ["-ljansson"];
        testSource = ''
          #include <jansson.h>
          #include <stdio.h>
          int main() {
            json_t *obj = json_object();
            if (!obj) return 1;
            json_decref(obj);
            printf("jansson version: %s\n", JANSSON_VERSION);
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "jansson — C library for encoding, decoding and manipulating JSON data";
      homepage = "https://github.com/akheron/jansson";
      license = "MIT";
    };
  }
