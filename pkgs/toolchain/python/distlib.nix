##! distlib — Low-level Python packaging library
{
  mkDerivation,
  fetchurl,
  python3,
}:
let
  version = "0.3.9";
in
mkDerivation {
  pname = "distlib";
  inherit version;

  src = fetchurl {
    urls = [
      "https://files.pythonhosted.org/packages/source/d/distlib/distlib-${version}.tar.gz"
    ];
    hash = "sha256-pg8g3qZGuKM/Pndy903AstB3LSg37hNCoAZFyB7flAM=";
  };

  buildDeps = [ python3 ];
  runtimeDeps = [ python3 ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd distlib-${version}
      '';
    }
    {
      name = "install";
      script = ''
        SITE=$out/lib/python3.14/site-packages
        mkdir -p $SITE
        cp -r distlib $SITE/
        mkdir -p $SITE/distlib-${version}.dist-info
        printf 'Metadata-Version: 2.1\nName: distlib\nVersion: ${version}\n' \
          > $SITE/distlib-${version}.dist-info/METADATA
        printf 'distlib\n' \
          > $SITE/distlib-${version}.dist-info/top_level.txt
        touch $SITE/distlib-${version}.dist-info/INSTALLER
      '';
    }
  ];

  meta = {
    description = "distlib — low-level Python packaging library";
    homepage = "https://distlib.readthedocs.io/";
    license = "Python-2.0";
  };
}
