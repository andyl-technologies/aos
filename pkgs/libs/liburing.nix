##! liburing — Linux io_uring userspace library
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "liburing-2";
    family = "liburing";
    stream = "2";
    owner = "pkgs/libs/liburing.nix";
    version = "2.15";
    upstreamId = "liburing-2.15";
    repository = "axboe/liburing";
    provider = "github-releases";
    tagPrefix = "liburing-";
    major = 2;
    versionScheme = "numeric";
    source = {
      authority = "github.com";
      path = [
        "axboe"
        "liburing"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {literal = "liburing-";}
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
      hash = "sha256-jQUvJiLcs2eMuu5f9YKodXJnKmwKVlM83aW2XLY2Ego=";
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
    pname = "liburing";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Liburing creates a usable kernel ring and releases it successfully.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"liburing primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"liburing rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <liburing.h>\nint main(void) {\n    struct io_uring ring = {0};\n    if (io_uring_queue_init(1, &ring, 0) != 0) return 2;\n    io_uring_queue_exit(&ring);\n    return pass();\n}\n\n";
        };
        "input" = "A request for an io_uring queue containing one entry.";
        "operation" = "Initialize and release the queue through liburing.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-luring"
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
              "exact" = "liburing primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Liburing rejects the zero-sized queue with EINVAL.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"liburing primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"liburing rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <errno.h>\n#include <liburing.h>\nint main(void) {\n    struct io_uring ring = {0};\n    int status = io_uring_queue_init(0, &ring, 0);\n    return status == -EINVAL ? reject() : 2;\n}\n\n";
        };
        "input" = "A request for an io_uring queue containing zero entries.";
        "operation" = "Submit the invalid queue size through io_uring_queue_init.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-luring"
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
              "exact" = "liburing rejected invalid input\n";
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
          cd liburing-liburing-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --libdir=$out/lib \
            --includedir=$out/include
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
      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["liburing.so"];
      };

      link = testing.mkLinkCheck {
        pname = "lib-uring";
        library = self;
        libs = ["-luring"];
        testSource = ''
          #include <liburing.h>
          int main(void) {
            struct io_uring ring;
            return io_uring_queue_init(1, &ring, 0) < 0;
          }
        '';
      };
    };

    meta = {
      description = "Userspace library for the Linux io_uring API";
      homepage = "https://github.com/axboe/liburing";
      license = "LGPL-2.1-or-later";
    };
  }
