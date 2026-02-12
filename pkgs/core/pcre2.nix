# pcre2 — Perl Compatible Regular Expressions (version 2)
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "10.44";
in
mkDerivation {
  pname = "pcre2";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${version}/pcre2-${version}.tar.bz2"
    ];
    hash = "sha256-008C4RPPcZOh6/J3DTrFJwiNSF1OBH7RDl0hfG713pY=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd pcre2-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --enable-shared \
          --disable-static \
          --enable-unicode \
          --enable-pcre2-8 \
          --enable-pcre2-16 \
          --enable-pcre2-32
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
    description = "pcre2 — Perl Compatible Regular Expressions (version 2)";
    homepage = "https://www.pcre.org/";
    license = "BSD-3-Clause";
  };
}
