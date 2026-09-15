##! libseccomp — Seccomp (secure computing) userspace library
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  gperf,
}: let
  upstream = mkGithubUpstream {
    unitId = "libseccomp-2";
    family = "libseccomp";
    stream = "2";
    owner = "pkgs/libs/libseccomp.nix";
    version = "2.6.1";
    upstreamId = "v2.6.1";
    repository = "seccomp/libseccomp";
    provider = "github-releases";
    tagPrefix = "v";
    major = 2;
    riskFloor = "high";
    source = {
      authority = "github.com";
      path = [
        "seccomp"
        "libseccomp"
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
            {literal = "libseccomp-";}
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
      hash = "sha256-UB9mxmciXVN5G5fh18+Fq3ZMKX0EiB9g849FHEsO4b4=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libseccomp";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The name resolves to the SCMP_ARCH_X86_64 token.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libseccomp primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libseccomp rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <seccomp.h>\nint main(void) {\n    uint32_t architecture = seccomp_arch_resolve_name(\"x86_64\");\n    return architecture == SCMP_ARCH_X86_64 ? pass() : 2;\n}\n\n";
        };
        "input" = "The canonical x86_64 audit architecture name.";
        "operation" = "Resolve the name through libseccomp and compare its audit token.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lseccomp"
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
              "exact" = "libseccomp primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libseccomp returns its zero invalid-architecture token.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libseccomp primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libseccomp rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <seccomp.h>\nint main(void) {\n    if (seccomp_arch_resolve_name(\"qualification_arch_does_not_exist\") != 0) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "An audit architecture name absent from libseccomp's registry.";
        "operation" = "Resolve the unknown name through seccomp_arch_resolve_name.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lseccomp"
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
              "exact" = "libseccomp rejected invalid input\n";
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
      gperf
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libseccomp-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --disable-static \
            --enable-shared
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
      description = "libseccomp — enhanced seccomp (mode 2) userspace library";
      homepage = "https://github.com/seccomp/libseccomp";
      license = "LGPL-2.1-only";
    };
  }
