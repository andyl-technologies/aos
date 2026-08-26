##! SQLite — Self-contained SQL database engine
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "3.51.2";
  # SQLite uses a year+version encoding for the download filename
  srcVersion = "3510200";
in
  mkDerivation {
    pname = "sqlite";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.sqlite.org/2026/sqlite-autoconf-${srcVersion}.tar.gz"
      ];
      hash = "sha256-+9ifhmsUA7tmoUMGVEAInddhAPIjgxTZInSggtTyt7s=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd sqlite-autoconf-${srcVersion}
        '';
      }
      {
        name = "configure";
        script = ''
          export CFLAGS="$CFLAGS \
            -DSQLITE_ENABLE_COLUMN_METADATA \
            -DSQLITE_ENABLE_FTS3 \
            -DSQLITE_ENABLE_FTS3_PARENTHESIS \
            -DSQLITE_ENABLE_FTS4 \
            -DSQLITE_ENABLE_FTS5 \
            -DSQLITE_ENABLE_RTREE \
            -DSQLITE_ENABLE_UNLOCK_NOTIFY \
            -DSQLITE_ENABLE_DBSTAT_VTAB \
            -DSQLITE_SECURE_DELETE \
            -DSQLITE_MAX_VARIABLE_NUMBER=250000"
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --enable-fts5
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
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-sqlite";
        library = self;
        libs = ["-lsqlite3"];
        testSource = ''
          #include <sqlite3.h>
          #include <stdio.h>
          int main() {
            printf("sqlite version: %s\n", sqlite3_libversion());
            return 0;
          }
        '';
      };

      cli = testing.mkVMTest {
        name = "tool-sqlite3-cli";
        rootfsDeps = [
          self
          pkgs.coreutils
        ];
        testScript = ''
                RESULT=$(sqlite3 :memory: "SELECT 1+1;")
                if [ "$RESULT" != "2" ]; then
                  echo "FAIL: expected 2, got '$RESULT'" >&2
                  exit 1
                fi

                # Test table creation and query
                sqlite3 /tmp/test.db << 'SQL'
          CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, value INTEGER);
          INSERT INTO items VALUES (1, 'alpha', 10);
          INSERT INTO items VALUES (2, 'beta', 20);
          INSERT INTO items VALUES (3, 'gamma', 30);
          SQL
                SUM=$(sqlite3 /tmp/test.db "SELECT SUM(value) FROM items;")
                test "$SUM" = "60"

                echo "==> sqlite3 cli: passed"
        '';
      };
    };

    meta = {
      description = "SQLite — self-contained SQL database engine";
      homepage = "https://www.sqlite.org";
      license = "public-domain";
    };
  }
