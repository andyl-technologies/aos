##! hdparm — Get/set SATA/IDE device parameters
{
  mkDerivation,
  fetchurl,
  gnumake,
}:
let
  version = "9.65";
in
mkDerivation {
  pname = "hdparm";
  inherit version;

  src = fetchurl {
    urls = [
      "https://sourceforge.net/projects/hdparm/files/hdparm/hdparm-${version}.tar.gz"
    ];
    hash = "sha256-0Ukp+RDQYJMucX6TgkJdR8LnFEI1pTcT1VqU995TWks=";
  };

  buildDeps = [ gnumake ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd hdparm-${version}
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
        make install prefix=$out sbindir=$out/sbin bindir=$out/bin mandir=$out/share/man
      '';
    }
  ];

  meta = {
    description = "Get/set SATA/IDE device parameters";
    homepage = "https://sourceforge.net/projects/hdparm/";
    license = "BSD";
  };
}
