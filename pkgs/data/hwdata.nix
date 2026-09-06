##! hwdata — Hardware identification databases
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.406";
in
  mkDerivation {
    pname = "hwdata";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/vcrhonek/hwdata/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-HM/RynI1lbH+h5T0FX7FY1vh6+210TdptL510LdbwZk=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd hwdata-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix="$out" --datadir="$out/share"
        '';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    meta = {
      description = "Hardware identification databases";
      homepage = "https://github.com/vcrhonek/hwdata";
      license = "GPL-2.0-or-later";
    };
  }
