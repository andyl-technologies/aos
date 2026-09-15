##! pcre2 — Perl Compatible Regular Expressions (version 2)
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "pcre2-10";
    family = "pcre2";
    stream = "10";
    owner = "pkgs/libs/pcre2.nix";
    version = "10.48";
    upstreamId = "pcre2-10.48";
    repository = "PCRE2Project/pcre2";
    provider = "github-releases";
    tagPrefix = "pcre2-";
    major = 10;
    versionScheme = "numeric";
    source = {
      authority = "github.com";
      path = [
        "PCRE2Project"
        "pcre2"
        "releases"
        "download"
        {
          parts = [
            {literal = "pcre2-";}
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
            {literal = "pcre2-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.bz2";}
          ];
        }
      ];
      hash = "sha256-tsaP3286wxOItQqon/D8ScAMmHwW57UUZJHRIAPyyO0=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "pcre2";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The engine reports the whole match and one capture.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"pcre2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"pcre2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#define PCRE2_CODE_UNIT_WIDTH 8\n#include <pcre2.h>\nint main(void) {\n    int error; PCRE2_SIZE offset;\n    pcre2_code *code = pcre2_compile((PCRE2_SPTR)\"answer=([0-9]+)\", PCRE2_ZERO_TERMINATED, 0, &error, &offset, NULL);\n    if (code == NULL) return 2;\n    pcre2_match_data *data = pcre2_match_data_create_from_pattern(code, NULL);\n    int matches = pcre2_match(code, (PCRE2_SPTR)\"answer=42\", 9, 0, 0, data, NULL);\n    pcre2_match_data_free(data); pcre2_code_free(code);\n    return matches == 2 ? pass() : 3;\n}\n\n";
        };
        "input" = "A regular expression with a numeric capture and matching text.";
        "operation" = "Compile and match the expression through PCRE2's 8-bit API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpcre2-8"
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
              "exact" = "pcre2 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "PCRE2 returns no compiled pattern and sets an error code.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"pcre2 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"pcre2 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#define PCRE2_CODE_UNIT_WIDTH 8\n#include <pcre2.h>\nint main(void) {\n    int error = 0; PCRE2_SIZE offset = 0;\n    pcre2_code *code = pcre2_compile((PCRE2_SPTR)\"(unclosed\", PCRE2_ZERO_TERMINATED, 0, &error, &offset, NULL);\n    if (code != NULL || error == 0) { pcre2_code_free(code); return 2; }\n    return reject();\n}\n\n";
        };
        "input" = "A regular expression with an unclosed group.";
        "operation" = "Compile the malformed expression through PCRE2.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpcre2-8"
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
              "exact" = "pcre2 rejected invalid input\n";
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
          cd pcre2-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --enable-unicode \
            --enable-pcre2-8 \
            --enable-pcre2-16 \
            --enable-pcre2-32 \
            --enable-jit=auto \
            --enable-jit-sealloc
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libpcre2-8.so"];
      };

      link = testing.mkLinkCheck {
        pname = "lib-pcre2";
        library = self;
        libs = ["-lpcre2-8"];
        testSource = ''
          #define PCRE2_CODE_UNIT_WIDTH 8
          #include <pcre2.h>
          #include <stdio.h>
          int main() {
            int major = PCRE2_MAJOR;
            int minor = PCRE2_MINOR;
            printf("pcre2 version: %d.%d\n", major, minor);
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "pcre2 — Perl Compatible Regular Expressions (version 2)";
      homepage = "https://www.pcre.org/";
      license = "BSD-3-Clause";
    };
  }
