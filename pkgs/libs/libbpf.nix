##! libbpf - userspace library for loading and managing BPF programs
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  pkg-config,
  elfutils,
  zlib,
  zstd,
}: let
  upstream = mkGithubUpstream {
    unitId = "libbpf-1";
    family = "libbpf";
    stream = "1";
    owner = "pkgs/libs/libbpf.nix";
    version = "1.7.0";
    upstreamId = "v1.7.0";
    repository = "libbpf/libbpf";
    provider = "github-releases";
    tagPrefix = "v";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "libbpf"
        "libbpf"
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
      hash = "sha256-erX+/794VX9iby4+MgR4hSg5RJRxWjD8IHD83cIFG3s=";
    };
    riskFloor = "high";
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
    pname = "libbpf";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libbpf reports Invalid argument and matches its public version constants.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libbpf primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libbpf rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <errno.h>\n#include <string.h>\n#include <bpf/libbpf.h>\n#include <bpf/libbpf_version.h>\nint main(void) {\n    char message[64] = {0};\n    int status = libbpf_strerror(-EINVAL, message, sizeof(message));\n    int valid = status == 0 && strcmp(message, \"Invalid argument\") == 0\n        && libbpf_major_version() == LIBBPF_MAJOR_VERSION\n        && libbpf_minor_version() == LIBBPF_MINOR_VERSION;\n    return valid ? pass() : 2;\n}\n\n";
        };
        "input" = "The EINVAL error number and libbpf's compiled version constants.";
        "operation" = "Resolve the error text and query the linked library version.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lbpf"
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
              "exact" = "libbpf primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libbpf returns an error pointer instead of constructing a BPF object.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libbpf primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libbpf rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <stdarg.h>\n#include <bpf/libbpf.h>\nstatic int quiet(enum libbpf_print_level level, const char *format, va_list arguments) {\n    (void)level; (void)format; (void)arguments;\n    return 0;\n}\nint main(void) {\n    const char bytes[] = \"not an ELF object\";\n    libbpf_set_print(quiet);\n    struct bpf_object *object = bpf_object__open_mem(bytes, sizeof(bytes), NULL);\n    long error = libbpf_get_error(object);\n    if (error == 0) {\n        bpf_object__close(object);\n        return 2;\n    }\n    return reject();\n}\n\n";
        };
        "input" = "A byte sequence that is not an ELF object.";
        "operation" = "Open the malformed bytes through bpf_object__open_mem.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lbpf"
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
              "exact" = "libbpf rejected invalid input\n";
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
      pkg-config
    ];
    runtimeDeps = [
      elfutils
      zlib
      zstd
    ];
    propagatedDeps = [
      elfutils
      zlib
      zstd
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libbpf-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -C src -j$NIX_BUILD_CORES \
            PREFIX=$out \
            LIBDIR=$out/lib \
            INCLUDEDIR=$out/include \
            UAPIDIR=$out/include
        '';
      }
      {
        name = "install";
        script = ''
          make -C src install \
            PREFIX=$out \
            LIBDIR=$out/lib \
            INCLUDEDIR=$out/include \
            UAPIDIR=$out/include
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libbpf";
        library = self;
        extraDeps = [
          elfutils
          zlib
          zstd
        ];
        libs = [
          "-lbpf"
          "-lelf"
          "-lz"
          "-lzstd"
        ];
        testSource = ''
          #include <bpf/libbpf.h>
          #include <stdio.h>
          int main() {
            printf("libbpf: %s\n", libbpf_version_string());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libbpf - userspace library for loading and managing BPF programs";
      homepage = "https://github.com/libbpf/libbpf";
      license = "LGPL-2.1-only OR BSD-2-Clause";
    };
  }
