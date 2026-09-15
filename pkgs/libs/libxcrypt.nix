##! libxcrypt — Extended crypt library for DES/MD5/SHA/Blowfish password hashing
{
  lib,
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  perl,
}: let
  upstream = mkGithubUpstream {
    unitId = "libxcrypt-4";
    family = "libxcrypt";
    stream = "4";
    owner = "pkgs/libs/libxcrypt.nix";
    version = "4.5.2";
    upstreamId = "v4.5.2";
    repository = "besser82/libxcrypt";
    provider = "github-releases";
    tagPrefix = "v";
    major = 4;
    source = {
      authority = "github.com";
      path = [
        "besser82"
        "libxcrypt"
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
            {literal = "libxcrypt-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.xz";}
          ];
        }
      ];
      hash = "sha256-cVE6McAaQovM1TZ6Mv2V8RXW2sUPtbYMd51ceUKuwHE=";
    };
    riskFloor = "high";
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libxcrypt";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "libxcrypt returns a SHA-512 salt beginning with the requested prefix.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libxcrypt primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libxcrypt rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <crypt.h>\nint main(void) {\n    const unsigned char entropy[16] = {0}; char salt[CRYPT_GENSALT_OUTPUT_SIZE];\n    char *result = crypt_gensalt_rn(\"$6$\", 5000, (const char *)entropy, sizeof(entropy), salt, sizeof(salt));\n    return result == salt && strncmp(salt, \"$6$\", 3) == 0 ? pass() : 2;\n}\n\n";
        };
        "input" = "A SHA-512 crypt prefix, round count, and fixed entropy bytes.";
        "operation" = "Generate a salt through crypt_gensalt_rn.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcrypt"
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
              "exact" = "libxcrypt primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libxcrypt rejects the request by returning a null pointer.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libxcrypt primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libxcrypt rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <crypt.h>\nint main(void) {\n    const unsigned char entropy[16] = {0}; char salt[CRYPT_GENSALT_OUTPUT_SIZE];\n    if (crypt_gensalt_rn(\"$qualification$\", 0, (const char *)entropy, sizeof(entropy), salt, sizeof(salt)) != NULL) return 2;\n    return reject();\n}\n\n";
        };
        "input" = "A password-hash prefix that names no supported method.";
        "operation" = "Generate a salt using the unsupported prefix.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcrypt"
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
              "exact" = "libxcrypt rejected invalid input\n";
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
      perl
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libxcrypt-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-hashes=strong,glibc \
            --enable-obsolete-api=no \
            --disable-failure-tokens \
            --disable-static
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
      description = "libxcrypt — extended crypt library for password hashing";
      homepage = "https://github.com/besser82/libxcrypt";
      license = "LGPL-2.1-or-later";
    };
  }
