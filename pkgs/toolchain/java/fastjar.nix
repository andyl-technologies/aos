##! fastjar — Fast pure-C implementation of the jar tool
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
}:
let
  version = "0.98";
in
mkDerivation {
  pname = "fastjar";
  inherit version;

  src = fetchurl {
    urls = [
      "https://download.savannah.gnu.org/releases/fastjar/fastjar-${version}.tar.gz"
    ];
    hash = "sha256-8Varxd6GWPIu6PCNenLIj5QJ69jHkz6UZrCEKv6y8UU=";
  };

  buildDeps = [gnumake];
  runtimeDeps = [zlib];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd fastjar-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure --prefix=$out
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
    description = "FastJar — pure-C implementation of Java jar tool";
    homepage = "https://savannah.nongnu.org/projects/fastjar";
    license = "GPL-2.0";
  };
}
