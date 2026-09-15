##! libsepol — SELinux binary policy manipulation library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  flex,
}: let
  version = "3.11";
in
  mkDerivation {
    pname = "libsepol";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Libsepol accepts the kernel policy type and supported version.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libsepol primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libsepol rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <sepol/policydb.h>\nint main(void) {\n    sepol_policydb_t *policy = NULL;\n    if (sepol_policydb_create(&policy) != 0 || policy == NULL) return 2;\n    int minimum = sepol_policy_kern_vers_min();\n    int maximum = sepol_policy_kern_vers_max();\n    int valid = minimum > 0 && maximum >= minimum\n        && sepol_policydb_set_typevers(policy, SEPOL_POLICY_KERN) == 0\n        && sepol_policydb_set_vers(policy, (unsigned int)minimum) == 0;\n    sepol_policydb_free(policy);\n    return valid ? pass() : 3;\n}\n\n";
        };
        "input" = "A new policy database configured for the minimum supported kernel policy version.";
        "operation" = "Create the database and set its type and version through libsepol.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lsepol"
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
              "exact" = "libsepol primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libsepol rejects the type with status -1.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libsepol primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libsepol rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <sepol/policydb.h>\nint main(void) {\n    sepol_policydb_t *policy = NULL;\n    if (sepol_policydb_create(&policy) != 0 || policy == NULL) return 2;\n    int status = sepol_policydb_set_typevers(policy, 99);\n    sepol_policydb_free(policy);\n    return status == -1 ? reject() : 3;\n}\n\n";
        };
        "input" = "A policy database type outside libsepol's declared type set.";
        "operation" = "Apply the unsupported type through sepol_policydb_set_typevers.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lsepol"
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
              "exact" = "libsepol rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/SELinuxProject/selinux/releases/download/${version}/selinux-${version}.tar.gz"
      ];
      hash = "sha256-a21Hqw81/hwJvaDGKCHI2XoMvn9ulASzON973gGCxPQ=";
    };

    buildDeps = [
      gnumake
      flex
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd selinux-${version}/libsepol
        '';
      }
      {
        name = "build";
        script = ''
          make PREFIX=$out SHLIBDIR=$out/lib -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install PREFIX=$out SHLIBDIR=$out/lib
        '';
      }
    ];

    meta = {
      description = "libsepol — SELinux binary policy manipulation library";
      homepage = "https://github.com/SELinuxProject/selinux";
      license = "LGPL-2.1-or-later";
    };
  }
