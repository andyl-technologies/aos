##! jq — Lightweight command-line JSON processor
{
  mkDerivation,
  fetchurl,
  make,
  oniguruma,
}:

let
  version = "1.7.1";
in
mkDerivation {
  pname = "jq";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/jqlang/jq/releases/download/jq-${version}/jq-${version}.tar.gz"
    ];
    hash = "sha256-R4ycoSn9LjRD/icxS0VeIR4NjGC8j/ffcDhz3u7lgMI=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ oniguruma ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd jq-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-maintainer-mode \
          --with-oniguruma
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
    description = "Lightweight command-line JSON processor";
    homepage = "https://jqlang.github.io/jq/";
    license = "MIT";
  };
}
