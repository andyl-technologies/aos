##! FreeType — font rendering library
{
  mkDerivation,
  fetchurl,
  make,
  zlib,
}:
let
  version = "2.13.3";
in
mkDerivation {
  pname = "freetype";
  inherit version;

  src = fetchurl {
    urls = [
      "https://download.savannah.gnu.org/releases/freetype/freetype-${version}.tar.xz"
    ];
    hash = "sha256-BVA1BmbUJ8dNrrhdWse7NTrLpfdpVjlZlTEanG8GMok=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ zlib ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd freetype-${version}
      '';
    }
    {
      name = "build";
      script = ''
        $CONFIG_SHELL ./configure \
          --prefix=$out \
          --enable-freetype-config \
          --with-zlib=yes \
          --without-bzip2 \
          --without-png \
          --without-harfbuzz \
          --without-brotli
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
    description = "FreeType — font rendering library";
    homepage = "https://freetype.org";
    license = "FTL OR GPL-2.0-or-later";
  };
}
