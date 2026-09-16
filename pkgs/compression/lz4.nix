##! LZ4 — Extremely fast compression algorithm
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "lz4-1";
    family = "lz4";
    stream = "1";
    owner = "pkgs/compression/lz4.nix";
    version = "1.10.0";
    upstreamId = "v1.10.0";
    repository = "lz4/lz4";
    provider = "github-releases";
    tagPrefix = "v";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "lz4"
        "lz4"
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
            {literal = "lz4-";}
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
      hash = "sha256-U3USkEdEs14jKRIFXM+Oxm12hjn/Or5XiNkNeS7F9Is=";
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
    pname = "lz4";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The recovered bytes equal the original string.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"lz4 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"lz4 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <lz4.h>\nint main(void) {\n    const char input[] = \"AOS qualification\"; char compressed[128], output[128];\n    int size = LZ4_compress_default(input, compressed, sizeof(input), sizeof(compressed));\n    if (size <= 0) return 2;\n    int recovered = LZ4_decompress_safe(compressed, output, size, sizeof(output));\n    return recovered == sizeof(input) && memcmp(input, output, sizeof(input)) == 0 ? pass() : 3;\n}\n\n";
        };
        "input" = "A fixed string compressed into a bounded block.";
        "operation" = "Compress and decompress the bytes through the LZ4 block API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-llz4"
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
              "exact" = "lz4 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "LZ4_decompress_safe returns a negative corruption status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"lz4 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"lz4 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <lz4.h>\nint main(void) {\n    const char invalid[] = {(char)0xf0}; char output[32];\n    if (LZ4_decompress_safe(invalid, output, sizeof(invalid), sizeof(output)) >= 0) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A truncated LZ4 block whose token declares missing literal bytes.";
        "operation" = "Decompress the invalid block with the safe decoder.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-llz4"
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
              "exact" = "lz4 rejected invalid input\n";
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

    # The build machine's uname remains Linux during a cross build. Tell the
    # upstream makefiles which target naming and install-name rules to use.
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd lz4-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out -j$NIX_BUILD_CORES ${
            if stdenv.hostPlatform.isDarwin
            then "TARGET_OS=Darwin"
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out ${
            if stdenv.hostPlatform.isDarwin
            then "TARGET_OS=Darwin"
            else ""
          }
        '';
      }
    ];

    meta = {
      description = "LZ4 — extremely fast compression algorithm";
      homepage = "https://lz4.org";
      license = "BSD-2-Clause";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-lz4";
        library = self;
        libs = ["-llz4"];
        testSource = ''
          #include <lz4.h>
          #include <stdio.h>
          int main() {
            printf("lz4 version: %s\n", LZ4_versionString());
            return 0;
          }
        '';
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["liblz4.so"];
      };

      cli-roundtrip = testing.mkVMTest {
        name = "lib-lz4-cli-roundtrip";
        rootfsDeps = [self];
        testScript = ''
          echo "lz4 round-trip test data 1234567890" > /tmp/original.txt
          lz4 /tmp/original.txt /tmp/compressed.lz4
          lz4 -d /tmp/compressed.lz4 /tmp/decompressed.txt
          ORIG=$(cat /tmp/original.txt)
          RESULT=$(cat /tmp/decompressed.txt)
          if [ "$ORIG" != "$RESULT" ]; then
            echo "==> ERROR: decompressed data does not match original" >&2
            exit 1
          fi
          echo "==> lz4 CLI round-trip: PASS"
        '';
      };
    };
  }
