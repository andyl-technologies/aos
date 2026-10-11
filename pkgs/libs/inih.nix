##! inih — Simple .INI file parser library
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "inih";
    family = "inih";
    stream = "rolling";
    owner = "pkgs/libs/inih.nix";
    version = "62";
    upstreamId = "r62";
    repository = "benhoyt/inih";
    provider = "github-releases";
    tagPrefix = "r";
    versionScheme = "numeric";
    source = {
      authority = "github.com";
      path = [
        "benhoyt"
        "inih"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {literal = "r";}
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
      hash = "sha256-nBX6dRu4CT0ELa4bnxJetFGYwyxnBM1UgczeRg1PgVE=";
    };
  };
  inherit (upstream) version;
  sharedLibrary =
    if stdenv.hostPlatform.isDarwin
    then "libinih.0.dylib"
    else "libinih.so.0";
  sharedLink =
    if stdenv.hostPlatform.isDarwin
    then "libinih.dylib"
    else "libinih.so";
  sharedFlags =
    if stdenv.hostPlatform.isDarwin
    then "-dynamiclib -Wl,-install_name,$out/lib/${sharedLibrary}"
    else "-shared -Wl,-soname,${sharedLibrary}";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "inih";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "inih invokes the callback with the exact mapping and returns success.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"inih primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"inih rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <ini.h>\nstatic int handler(void *seen, const char *section, const char *name, const char *value) {\n    int *matched = seen;\n    *matched = strcmp(section, \"qualification\") == 0\n        && strcmp(name, \"answer\") == 0 && strcmp(value, \"42\") == 0;\n    return 1;\n}\nint main(void) {\n    int matched = 0;\n    int status = ini_parse_string(\"[qualification]\\nanswer=42\\n\", handler, &matched);\n    return status == 0 && matched ? pass() : 2;\n}\n\n";
        };
        "input" = "An INI section containing answer=42.";
        "operation" = "Parse the document and validate the callback's section, key, and value.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-linih"
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
              "exact" = "inih primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "inih reports the one-based line number of the syntax error.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"inih primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"inih rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <ini.h>\nstatic int handler(void *unused, const char *section, const char *name, const char *value) {\n    (void)unused; (void)section; (void)name; (void)value; return 1;\n}\nint main(void) {\n    if (ini_parse_string(\"[unclosed\\nanswer=42\\n\", handler, NULL) != 1) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "An INI section header with no closing bracket.";
        "operation" = "Parse the malformed document through ini_parse_string.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-linih"
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
              "exact" = "inih rejected invalid input\n";
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
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd inih-r${version}
        '';
      }
      {
        name = "build";
        script = ''
          $CC -c -fPIC -o ini.o ini.c
          $CC ${sharedFlags} -o ${sharedLibrary} ini.o
          $AR rcs libinih.a ini.o
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/include $out/lib $out/lib/pkgconfig

          cp ini.h $out/include/

          cp ${sharedLibrary} $out/lib/
          ln -s ${sharedLibrary} $out/lib/${sharedLink}
          cp libinih.a $out/lib/

          cat > $out/lib/pkgconfig/inih.pc << PCEOF
          prefix=$out
          libdir=$out/lib
          includedir=$out/include

          Name: inih
          Description: simple .INI file parser
          Version: ${version}
          Libs: -L$out/lib -linih
          Cflags: -I$out/include
          PCEOF
        '';
      }
    ];

    meta = {
      description = "Simple .INI file parser library";
      homepage = "https://github.com/benhoyt/inih";
      license = "BSD-3-Clause";
    };
  }
