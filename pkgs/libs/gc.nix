##! gc — Boehm-Demers-Weiser conservative garbage collector
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  stdenv,
  lib,
  libatomic_ops,
}: let
  upstream = mkGithubUpstream {
    unitId = "gc-8";
    family = "gc";
    stream = "8";
    owner = "pkgs/libs/gc.nix";
    version = "8.2.12";
    upstreamId = "v8.2.12";
    repository = "ivmai/bdwgc";
    provider = "github-releases";
    tagPrefix = "v";
    major = 8;
    source = {
      authority = "github.com";
      path = [
        "ivmai"
        "bdwgc"
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
            {literal = "gc-";}
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
      hash = "sha256-QuUZStBqtv+4Bsg+uZwDRitJXZec2ngvPHLAivgzzU4=";
    };
    riskFloor = "normal";
  };
  inherit (upstream) version;
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  needsExternalAtomicOps = stdenv.isCross && stdenv.hostPlatform.isLinux;
in
  mkDerivation {
    pname = "gc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <gc.h>\n\nint main(void) {\n    GC_INIT();\n    char *buffer = GC_malloc(32);\n    if (buffer == NULL) {\n        return 2;\n    }\n    strcpy(buffer, \"managed allocation\");\n    if (GC_base(buffer + 4) != buffer || strcmp(buffer, \"managed allocation\") != 0) {\n        return 3;\n    }\n    return puts(\"gc api passed\") == EOF;\n}\n";
        };
        "input" = "A managed byte buffer containing a fixed string.";
        "operation" = "Allocate the buffer with GC_malloc and recover its managed allocation base.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgc"
              "-pthread"
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
              "exact" = "gc api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API reports the rejected boundary and the consumer returns the fixed rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdint.h>\n#include <stdio.h>\n#include <gc.h>\n\nint main(void) {\n    GC_INIT();\n    if (GC_base((void *)(uintptr_t)42) != NULL) {\n        return 2;\n    }\n    fputs(\"gc rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "An address that does not belong to a garbage-collected allocation.";
        "operation" = "Query the allocation base for the unmanaged address.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgc"
              "-pthread"
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
              "exact" = "gc rejected invalid input\n";
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
    runtimeDeps = lib.optional needsExternalAtomicOps libatomic_ops;
    propagatedDeps = [];

    # The upstream compiler-intrinsics probe is an AC_RUN_IFELSE and is
    # unconditionally skipped while cross-compiling.  Darwin Clang provides
    # the required atomic builtins, so select that supported backend directly.
    configureFlags =
      if isDarwinCross
      then "--with-libatomic-ops=none"
      else "";

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf $src
            cd gc-${version}
          '';
        }
      ]
      ++ (
        if isDarwinCross
        then [
          {
            name = "darwin-libtool";
            script = ''
              # Libtool treats any -single_module diagnostic as rejection and
              # falls back to a relocatable C++ prelink.  Modern ld64 treats
              # single-module dylibs as the default and warns that the option
              # is obsolete, while ld64.lld intentionally does not implement
              # the fallback's `-r`.  Seed the successful semantic result so
              # Libtool uses its normal one-step Darwin dylib link.
              export lt_cv_apple_cc_single_mod=yes
            '';
          }
        ]
        else []
      )
      ++ [
        {
          name = "configure";
          script = ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --disable-static \
              --enable-cplusplus \
              --enable-large-config \
              --enable-threads=posix
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
      description = "gc — Boehm-Demers-Weiser conservative garbage collector";
      homepage = "https://www.hboehm.info/gc/";
      license = "MIT";
    };
  }
