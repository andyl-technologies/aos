##! numactl — NUMA policy tools and libnuma
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "numactl-2";
    family = "numactl";
    stream = "2";
    owner = "pkgs/libs/numactl.nix";
    version = "2.0.19";
    upstreamId = "v2.0.19";
    repository = "numactl/numactl";
    provider = "github-releases";
    tagPrefix = "v";
    major = 2;
    source = {
      authority = "github.com";
      path = [
        "numactl"
        "numactl"
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
            {literal = "numactl-";}
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
      hash = "sha256-8mcqA4HLWRlunCRr+LzEPVVovEV3AKaX8aHfdiua+IQ=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "numactl";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libnuma reports exactly two selected bits at the requested positions.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"numactl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"numactl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <numa.h>\nint main(void) {\n    struct bitmask *mask = numa_bitmask_alloc(8);\n    if (mask == NULL) return 2;\n    numa_bitmask_setbit(mask, 1);\n    numa_bitmask_setbit(mask, 4);\n    int valid = numa_bitmask_weight(mask) == 2\n        && numa_bitmask_isbitset(mask, 1) == 1\n        && numa_bitmask_isbitset(mask, 4) == 1;\n    numa_bitmask_free(mask);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "An eight-bit NUMA mask with bits one and four selected.";
        "operation" = "Allocate, update, and inspect the mask through libnuma.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnuma"
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
              "exact" = "numactl primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libnuma rejects the expression by returning null.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"numactl primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"numactl rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <numa.h>\nint main(void) {\n    struct bitmask *mask = numa_parse_nodestring(\"qualification-invalid\");\n    if (mask != NULL) {\n        numa_bitmask_free(mask);\n        return 2;\n    }\n    return reject();\n}\n\n";
        };
        "input" = "A NUMA node expression containing words instead of a node range.";
        "operation" = "Parse the malformed expression through numa_parse_nodestring.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lnuma"
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
              "exact" = "libnuma: Warning: unparseable node description `qualification-invalid'\n\nnumactl rejected invalid input\n";
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
          cd numactl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --enable-shared \
            --enable-static
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
      ...
    }: {
      cli = testing.mkToolCheck {
        pname = "tool-numactl";
        tool = self;
        command = "numactl --show";
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libnuma.so"];
      };
    };

    meta = {
      description = "NUMA policy control tools and library";
      homepage = "https://github.com/numactl/numactl";
      license = "LGPL-2.1-only";
    };
  }
