##! lmdb — Lightning Memory-Mapped Database
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.0.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "lmdb";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "LMDB returns the exact committed two-byte value.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"lmdb primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"lmdb rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <string.h>\n#include <lmdb.h>\nint main(void) {\n    MDB_env *environment = NULL; MDB_txn *transaction = NULL; MDB_dbi database;\n    MDB_val key = {6, (void *)\"answer\"}, value = {2, (void *)\"42\"}, observed;\n    if (mdb_env_create(&environment) != 0 || mdb_env_set_mapsize(environment, 1048576) != 0) return 2;\n    if (mdb_env_open(environment, \".\", 0, 0600) != 0) return 3;\n    if (mdb_txn_begin(environment, NULL, 0, &transaction) != 0 || mdb_dbi_open(transaction, NULL, 0, &database) != 0) return 4;\n    if (mdb_put(transaction, database, &key, &value, 0) != 0 || mdb_txn_commit(transaction) != 0) return 5;\n    if (mdb_txn_begin(environment, NULL, MDB_RDONLY, &transaction) != 0 || mdb_get(transaction, database, &key, &observed) != 0) return 6;\n    int ok = observed.mv_size == 2 && memcmp(observed.mv_data, \"42\", 2) == 0;\n    mdb_txn_abort(transaction); mdb_env_close(environment);\n    return ok ? pass() : 8;\n}\n\n";
        };
        "input" = "The key answer and value 42 in a fresh local LMDB environment.";
        "operation" = "Create the database, commit the pair, and read it in a new transaction.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-llmdb"
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
              "exact" = "lmdb primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "LMDB returns a nonzero filesystem error.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"lmdb primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"lmdb rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <lmdb.h>\nint main(void) {\n    MDB_env *environment = NULL;\n    if (mdb_env_create(&environment) != 0) return 2;\n    int status = mdb_env_open(environment, \"missing-qualification-directory\", MDB_RDONLY, 0);\n    mdb_env_close(environment);\n    if (status == 0) return 3;\n    return reject();\n}\n\n";
        };
        "input" = "A read-only environment path that does not exist.";
        "operation" = "Open the missing path through mdb_env_open.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-llmdb"
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
              "exact" = "lmdb rejected invalid input\n";
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
        "https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_${version}.tar.gz"
      ];
      hash = "sha256-fOHbS4wT9g4IgfElNzQMc/teASXbpNqmZJojFDQYVds=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd lmdb-LMDB_${version}/libraries/liblmdb
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" CC="$CC" AR="$AR"
        '';
      }
      {
        name = "check";
        script = ''
          make test CC="$CC" AR="$AR"
        '';
      }
      {
        name = "install";
        script = ''
          make install prefix="$out" CC="$CC" AR="$AR"
          mkdir -p "$out/lib/pkgconfig"
          cat > "$out/lib/pkgconfig/lmdb.pc" << EOF
          prefix=$out
          libdir=$out/lib
          includedir=$out/include

          Name: lmdb
          Description: Lightning Memory-Mapped Database
          Version: ${version}
          Libs: -L$out/lib -llmdb
          Cflags: -I$out/include
          EOF
          ln -s lmdb.pc "$out/lib/pkgconfig/liblmdb.pc"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-lmdb";
        library = self;
        libs = ["-llmdb"];
        testSource = ''
          #include <lmdb.h>

          int main(void) {
              MDB_env *environment = NULL;
              if (mdb_env_create(&environment) != 0) return 1;
              mdb_env_close(environment);
              return 0;
          }
        '';
      };
      tool = testing.mkToolCheck {
        pname = "tool-lmdb";
        tool = self;
        command = "mdb_stat -V";
      };
    };

    meta = {
      description = "Fast memory-mapped key-value database";
      homepage = "https://www.openldap.org/software/repo.html";
      license = "OLDAP-2.8";
    };
  }
