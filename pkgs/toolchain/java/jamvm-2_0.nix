##! jamvm-2_0 — JamVM 2.0.0 Java Virtual Machine with Classpath 0.99
{
  mkDerivation,
  fetchurl,
  gnumake,
  classpath-0_99,
  zlib,
}:
let
  version = "2.0.0";
in
mkDerivation {
  pname = "jamvm-2_0";
  inherit version;

  src = fetchurl {
    urls = [
      "https://downloads.sourceforge.net/project/jamvm/jamvm/JamVM%20${version}/jamvm-${version}.tar.gz"
    ];
    hash = "sha256-dkKOlt8K6d2WTHp8dMHpqDfi8xLDnpo1f6gXj37/gNo=";
  };

  buildDeps = [ gnumake ];
  runtimeDeps = [
    classpath-0_99
    zlib
  ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd jamvm-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --with-classpath-install-dir=${classpath-0_99}
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
    description = "JamVM 2.0.0 — Java Virtual Machine with Classpath 0.99";
    homepage = "https://jamvm.sourceforge.net/";
    license = "GPL-2.0";
  };
}
