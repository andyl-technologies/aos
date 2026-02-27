##! CUPS — Common UNIX Printing System (headers for compilation)
{
  mkDerivation,
  fetchurl,
}:
let
  version = "2.4.12";
in
mkDerivation {
  pname = "cups";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/OpenPrinting/cups/releases/download/v${version}/cups-${version}-source.tar.gz"
    ];
    hash = "sha256-sd3hkaSuJ2DEciDILKYVWijDgnAebBoBWdEFSZAjHVk=";
  };

  buildDeps = [ ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd cups-${version}
      '';
    }
    {
      name = "install";
      script = ''
        # Install public CUPS headers needed by OpenJDK and other packages
        mkdir -p $out/include/cups
        cp cups/*.h $out/include/cups/
      '';
    }
  ];

  meta = {
    description = "CUPS — Common UNIX Printing System (headers for compilation)";
    homepage = "https://openprinting.github.io/cups/";
    license = "Apache-2.0";
  };
}
