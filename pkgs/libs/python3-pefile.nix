##! python3-pefile — pure-Python Portable Executable reader/writer
##!
##! Required by systemd-ukify (systemd's UKI assembler) at runtime —
##! ukify imports pefile to append sections (.osrel, .cmdline, .linux,
##! .initrd) to the sd-stub PE-COFF binary. See pkgs/system/systemd.nix
##! for the wrap that puts this package on ukify's Python search path.
{
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "2024.8.26";
  # Hardcoded to match python3.nix's site-packages layout
  # (python3 exposes 3.14; adjust here if python3.nix is bumped).
  pyVersion = "3.14";
in
  mkDerivation {
    pname = "python3-pefile";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/erocarrera/pefile/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-EW7Cm2iepPDt5zJ+u9eUzol35eqpdWU5NEHTQE3uzaM=";
    };

    buildDeps = [];
    runtimeDeps = [python3];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pefile-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site=$out/lib/python${pyVersion}/site-packages
          mkdir -p "$site"
          cp pefile.py peutils.py "$site/"
          cp -r ordlookup "$site/"
        '';
      }
    ];

    meta = {
      description = "pefile — pure-Python Portable Executable reader/writer";
      homepage = "https://github.com/erocarrera/pefile";
      license = "MIT";
    };
  }
