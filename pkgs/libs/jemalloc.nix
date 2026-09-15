##! jemalloc — general-purpose scalable concurrent malloc implementation
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  bash,
  perl,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "jemalloc-5";
    family = "jemalloc";
    stream = "5";
    owner = "pkgs/libs/jemalloc.nix";
    version = "5.3.1";
    upstreamId = "5.3.1";
    repository = "jemalloc/jemalloc";
    provider = "github-releases";
    major = 5;
    source = {
      authority = "github.com";
      path = [
        "jemalloc"
        "jemalloc"
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
            {literal = "jemalloc-";}
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
      hash = "sha256-OCa8gCMvIu1cRmLzA095nKMW6BkQO9x7uZAYpCFwb5I=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "jemalloc";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The allocation succeeds and its usable size is at least 64 bytes.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"jemalloc primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"jemalloc rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <jemalloc/jemalloc.h>\nint main(void) {\n    void *memory = mallocx(64, 0);\n    if (memory == NULL || sallocx(memory, 0) < 64) return 2;\n    memset(memory, 0x5a, 64); dallocx(memory, 0);\n    return pass();\n}\n\n";
        };
        "input" = "A request for a 64-byte allocation and its usable size.";
        "operation" = "Allocate, query, write, and free memory through jemalloc's public API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ljemalloc"
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
              "exact" = "jemalloc primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "jemalloc rejects the overflowing request by returning a null pointer.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"jemalloc primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"jemalloc rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdint.h>\n#include <jemalloc/jemalloc.h>\nint main(void) {\n    if (mallocx(SIZE_MAX, 0) != NULL) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "An allocation request whose size is the maximum size_t value.";
        "operation" = "Request the impossible allocation through mallocx.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ljemalloc"
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
              "exact" = "jemalloc rejected invalid input\n";
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
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [bash perl]
      else [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd jemalloc-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          patch -p1 < ${./jemalloc-gcc-16.patch}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            # jemalloc's C++ allocator API hard-codes GNU libstdc++ for its
            # link probe and shared library. Darwin's ABI uses libc++, and
            # its C++ driver supplies the target runtime search path.
            sed -i 's|-lstdc++|-lc++|g' configure
            sed -i \
              's|^\t$(CC) $(DSO_LDFLAGS)|\t$(CXX) $(DSO_LDFLAGS)|' \
              Makefile.in
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --enable-static
          ''
          else ''
            ./configure \
              $configureFlags \
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
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            for script in "$out/bin/jemalloc-config" "$out/bin/jemalloc.sh"; do
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$script"
            done
            sed -i "1s|^#!.*|#!${perl}/bin/perl|" "$out/bin/jeprof"
          ''
          else ''
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
        pname = "lib-jemalloc";
        library = self;
        libs = ["-ljemalloc" "-lpthread" "-ldl"];
        testSource = ''
          #include <jemalloc/jemalloc.h>
          #include <stdio.h>
          #include <string.h>
          int main() {
            const char *v = NULL;
            size_t sz = sizeof(v);
            if (mallctl("version", &v, &sz, NULL, 0) != 0 || v == NULL) return 1;
            printf("jemalloc version: %s\n", v);

            void *p = malloc(1024);
            if (!p) return 2;
            memset(p, 0, 1024);
            free(p);
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "jemalloc — general-purpose scalable concurrent malloc implementation";
      homepage = "https://jemalloc.net/";
      license = "BSD-2-Clause";
    };
  }
