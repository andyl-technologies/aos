##! editline — Small line editing library (troglobit editline)
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  ncurses,
}: let
  upstream = mkGithubUpstream {
    unitId = "editline-2";
    family = "editline";
    stream = "2";
    owner = "pkgs/libs/editline.nix";
    version = "2.1.0";
    upstreamId = "2.1.0";
    repository = "troglobit/editline";
    provider = "github-releases";
    tagPrefix = "";
    major = 2;
    source = {
      authority = "github.com";
      path = [
        "troglobit"
        "editline"
        "releases"
        "download"
        {
          parts = [
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
          ];
        }
        {
          parts = [
            {literal = "editline-";}
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
      hash = "sha256-GJ4XklPAky0VzpT1Pozeegw4OD858R87ktQM0Yg5Z48=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "editline";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <editline.h>\n\nint main(void) {\n    char buffer[128] = {0};\n    rl_initialize();\n    add_history(\"alpha\");\n    add_history(\"beta\");\n    if (write_history(\"history.txt\") != 0) {\n        rl_uninitialize();\n        return 2;\n    }\n    FILE *history = fopen(\"history.txt\", \"r\");\n    if (history == NULL) {\n        rl_uninitialize();\n        return 3;\n    }\n    size_t length = fread(buffer, 1, sizeof(buffer) - 1, history);\n    fclose(history);\n    rl_uninitialize();\n    buffer[length] = '\\0';\n    if (strstr(buffer, \"alpha\") == NULL || strstr(buffer, \"beta\") == NULL) {\n        return 4;\n    }\n    return puts(\"editline api passed\") == EOF;\n}\n";
        };
        "input" = "Two fixed history entries and a writable history path.";
        "operation" = "Add the entries and serialize them through editline's history API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-leditline"
              "-o"
              "primary"
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
              "@work@/primary/primary"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "editline api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API rejects the malformed boundary and the consumer returns the fixed rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <editline.h>\n\nint main(void) {\n    rl_initialize();\n    int status = read_history(\"absent-history.txt\");\n    rl_uninitialize();\n    if (status == 0) {\n        return 2;\n    }\n    fputs(\"editline rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A history-file path that does not exist.";
        "operation" = "Read the missing history file through editline's history API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-leditline"
              "-o"
              "bad-input"
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
              "@work@/bad-input/bad-input"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "editline rejected invalid input\n";
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

    buildDeps = [gnumake];
    runtimeDeps = [ncurses];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd editline-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static
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
      description = "editline — small line editing library";
      homepage = "https://github.com/troglobit/editline";
      license = "ISC";
    };
  }
