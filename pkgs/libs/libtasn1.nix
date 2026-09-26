{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "4.21.0";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libtasn1";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "libtasn1 builds and releases the definition tree.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libtasn1 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libtasn1 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libtasn1.h>\nint main(void) {\n    asn1_node definitions = NULL; char error[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};\n    int status = asn1_parser2tree(\"schema.asn\", &definitions, error);\n    if (status != ASN1_SUCCESS || definitions == NULL) return 2;\n    asn1_delete_structure(&definitions);\n    return pass();\n}\n\n";
          "schema.asn" = "QUALIFICATION DEFINITIONS EXPLICIT TAGS ::= BEGIN\nAnswer ::= INTEGER\nEND\n";
        };
        "input" = "An ASN.1 module declaring one integer type.";
        "operation" = "Parse the module through asn1_parser2tree.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ltasn1"
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
              "exact" = "libtasn1 primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libtasn1 returns a syntax error and no usable tree.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libtasn1 primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libtasn1 rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <libtasn1.h>\nint main(void) {\n    asn1_node definitions = NULL; char error[ASN1_MAX_ERROR_DESCRIPTION_SIZE] = {0};\n    int status = asn1_parser2tree(\"invalid.asn\", &definitions, error);\n    if (definitions != NULL) asn1_delete_structure(&definitions);\n    if (status == ASN1_SUCCESS) return 2;\n    return reject();\n}\n\n";
          "invalid.asn" = "QUALIFICATION DEFINITIONS ::= BEGIN\nAnswer ::= INTEGER\n";
        };
        "input" = "An ASN.1 module missing its terminating END declaration.";
        "operation" = "Parse the incomplete module through asn1_parser2tree.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ltasn1"
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
              "exact" = "libtasn1 rejected invalid input\n";
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
        "https://ftp.gnu.org/gnu/libtasn1/libtasn1-${version}.tar.gz"
        "https://mirrors.dotsrc.org/gnu/libtasn1/libtasn1-${version}.tar.gz"
      ];
      hash = "sha256-HYpESiI8xUZCQHdzRuEl3lHY5qvwuLrHQqyEYJFn3Ic=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libtasn1-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --disable-static \
            --disable-doc \
            --disable-nls
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
      description = "ASN.1 and DER structure parsing/encoding library";
      homepage = "https://www.gnu.org/software/libtasn1/";
      license = "LGPL-2.1-or-later";
    };
  }
