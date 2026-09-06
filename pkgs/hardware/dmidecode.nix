##! dmidecode — SMBIOS and DMI hardware information decoder
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "3.7";
in
  mkDerivation {
    pname = "dmidecode";
    inherit version;
    src = fetchurl {
      urls = ["https://download.savannah.gnu.org/releases/dmidecode/dmidecode-${version}.tar.xz"];
      hash = "sha256-LDrtEshaHmqUENQG1eQXxFVGbcG8fIkni7Ms98rZHoo=";
    };
    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd dmidecode-${version}
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES" CC="$CC"'';
      }
      {
        name = "install";
        script = ''
          make install prefix="$out"
          "$out/sbin/dmidecode" --version | grep -qx '${version}'
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-dmidecode";
        tool = self;
        command = "dmidecode --version | grep -qx '${version}'";
      };
    };
    meta = {
      description = "Reports system hardware information from SMBIOS and DMI tables";
      homepage = "https://www.nongnu.org/dmidecode/";
      license = "GPL-2.0-or-later";
      mainProgram = "dmidecode";
    };
  }
