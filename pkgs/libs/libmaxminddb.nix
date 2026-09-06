##! libmaxminddb — MaxMind DB file reader
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.13.3";
in
  mkDerivation {
    pname = "libmaxminddb";
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
