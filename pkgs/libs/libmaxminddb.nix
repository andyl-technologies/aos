##! libmaxminddb — MaxMind DB file reader
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.13.3";
in
  mkDerivation {
    pname = "libmaxminddb";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns version 1.13.3 and the documented diagnostic.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libmaxminddb primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libmaxminddb rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <maxminddb.h>\nint main(void) {\n    int valid = strcmp(MMDB_lib_version(), \"1.13.3\") == 0\n        && strcmp(MMDB_strerror(MMDB_INVALID_METADATA_ERROR),\n                  \"The MaxMind DB file contains invalid metadata\") == 0;\n    return valid ? pass() : 2;\n}\n\n";
        };
        "input" = "The library's compiled version and invalid-metadata status.";
        "operation" = "Query the version and translate the status through libmaxminddb.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lmaxminddb"
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
              "exact" = "libmaxminddb primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Libmaxminddb returns MMDB_INVALID_METADATA_ERROR.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libmaxminddb primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libmaxminddb rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <maxminddb.h>\nint main(void) {\n    MMDB_s database = {0};\n    int status = MMDB_open(\"invalid.mmdb\", MMDB_MODE_MMAP, &database);\n    if (status == MMDB_SUCCESS) {\n        MMDB_close(&database);\n        return 2;\n    }\n    return status == MMDB_INVALID_METADATA_ERROR ? reject() : 3;\n}\n\n";
          "invalid.mmdb" = "not a MaxMind database\n";
        };
        "input" = "A short text file that is not a MaxMind database.";
        "operation" = "Open the malformed database through MMDB_open.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lmaxminddb"
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
              "exact" = "libmaxminddb rejected invalid input\n";
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
        "https://github.com/maxmind/libmaxminddb/releases/download/${version}/libmaxminddb-${version}.tar.gz"
      ];
      hash = "sha256-pmUC6nbq2+F/LNb9cIlGd3JTly0q6BV97hsjovtSgXE=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    configureFlags = "--disable-static";

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libmaxminddb";
        library = self;
        libs = ["-lmaxminddb"];
        testSource = ''
          #include <maxminddb.h>

          int main(void) {
              MMDB_s database = {0};
              MMDB_close(&database);
              return MMDB_lib_version() == NULL;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-libmaxminddb";
        tool = self;
        command = "mmdblookup --version";
      };
    };

    meta = {
      description = "C library for reading MaxMind DB files";
      homepage = "https://github.com/maxmind/libmaxminddb";
      license = "Apache-2.0";
      mainProgram = "mmdblookup";
    };
  }
