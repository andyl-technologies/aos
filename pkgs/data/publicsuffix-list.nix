##! publicsuffix-list — Public suffix database
{
  mkDerivation,
  fetchurl,
}: let
  version = "0-unstable-2026-05-13";
  revision = "e452c7058d6946bd76952b128c12f5ce87a5acb8";
in
  mkDerivation {
    pname = "publicsuffix-list";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/publicsuffix/list/archive/${revision}.tar.gz"];
      hash = "sha256-iWiIx6FTHRpdhMsWMqcKjVMlaZ2PWf7Epr6ILQXyW60=";
    };

    buildDeps = [];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd list-${revision}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/publicsuffix"
          cp public_suffix_list.dat tests/test_psl.txt "$out/share/publicsuffix/"
        '';
      }
    ];

    meta = {
      description = "Cross-vendor public domain suffix database";
      homepage = "https://publicsuffix.org/";
      license = "MPL-2.0";
    };
  }
