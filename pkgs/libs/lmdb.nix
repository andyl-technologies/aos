##! lmdb — Lightning Memory-Mapped Database
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.9.35";
in
  mkDerivation {
    pname = "lmdb";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/LMDB/lmdb/archive/refs/tags/LMDB_${version}.tar.gz"
      ];
      hash = "sha256-GLAh/VidMMwIhgqVUKMK5RY3EXRROF6VgWFtp1EyZjI=";
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
