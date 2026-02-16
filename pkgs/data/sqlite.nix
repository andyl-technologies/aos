##! SQLite — Self-contained SQL database engine
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "3.47.2";
  # SQLite uses a year+version encoding for the download filename
  srcVersion = "3470200";
in
mkDerivation {
  pname = "sqlite";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.sqlite.org/2024/sqlite-autoconf-${srcVersion}.tar.gz"
    ];
    hash = "sha256-8bLuQSwo10cryVupljaNbwzc8ANir/2tsn7ShsF5VAs=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

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
          -DSQLITE_ENABLE_JSON1 \
          -DSQLITE_ENABLE_DBSTAT_VTAB \
          -DSQLITE_SECURE_DELETE \
          -DSQLITE_MAX_VARIABLE_NUMBER=250000"
        ./configure \
          --prefix=$out \
          --enable-shared \
          --disable-static \
          --enable-fts5 \
          --enable-json1
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
    description = "SQLite — self-contained SQL database engine";
    homepage = "https://www.sqlite.org";
    license = "public-domain";
  };
}
