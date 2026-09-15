##! Oniguruma — regular expression library
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "oniguruma-6";
    family = "oniguruma";
    stream = "6";
    owner = "pkgs/libs/oniguruma.nix";
    version = "6.9.10";
    upstreamId = "v6.9.10";
    repository = "kkos/oniguruma";
    provider = "github-releases";
    tagPrefix = "v";
    major = 6;
    source = {
      authority = "github.com";
      path = [
        "kkos"
        "oniguruma"
        "releases"
        "download"
        {
          parts = [
            {literal = "v";}
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
            {literal = "onig-";}
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
      hash = "sha256-Klz8WuJZ5Ol/hraN//wVLNr/6U4gYLdwy4JyONdp/AU=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "oniguruma";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The search matches the complete answer=42 string.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"oniguruma primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"oniguruma rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <oniguruma.h>\nint main(void) {\n    const OnigUChar pattern[] = \"answer=([0-9]+)\"; const OnigUChar text[] = \"answer=42\";\n    OnigRegex regex; OnigErrorInfo error; OnigRegion *region = onig_region_new();\n    int status = onig_new(&regex, pattern, pattern + strlen((char *)pattern), ONIG_OPTION_NONE, ONIG_ENCODING_ASCII, ONIG_SYNTAX_DEFAULT, &error);\n    if (status != ONIG_NORMAL) return 2;\n    status = onig_search(regex, text, text + strlen((char *)text), text, text + strlen((char *)text), region, ONIG_OPTION_NONE);\n    int ok = status == 0 && region->beg[0] == 0 && region->end[0] == 9;\n    onig_region_free(region, 1); onig_free(regex); onig_end();\n    return ok ? pass() : 3;\n}\n\n";
        };
        "input" = "A regular expression with a numeric capture and matching text.";
        "operation" = "Compile and search the expression through Oniguruma.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lonig"
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
              "exact" = "oniguruma primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The compiler returns a negative syntax-error code.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"oniguruma primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"oniguruma rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <oniguruma.h>\nint main(void) {\n    const OnigUChar pattern[] = \"(unclosed\"; OnigRegex regex; OnigErrorInfo error;\n    int status = onig_new(&regex, pattern, pattern + strlen((char *)pattern), ONIG_OPTION_NONE, ONIG_ENCODING_ASCII, ONIG_SYNTAX_DEFAULT, &error);\n    if (status >= 0) { onig_free(regex); return 2; }\n    onig_end(); return reject();\n}\n\n";
        };
        "input" = "A regular expression with an unclosed group.";
        "operation" = "Compile the malformed expression through Oniguruma.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lonig"
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
              "exact" = "oniguruma rejected invalid input\n";
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
          cd onig-${version}
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
            --enable-posix-api=yes
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
      link = testing.mkLinkCheck {
        pname = "lib-oniguruma";
        library = self;
        libs = ["-lonig"];
        testSource = ''
          #include <oniguruma.h>
          #include <stdio.h>
          int main() {
            printf("oniguruma version: %s\n", onig_version());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "Oniguruma — regular expression library";
      homepage = "https://github.com/kkos/oniguruma";
      license = "BSD-2-Clause";
    };
  }
