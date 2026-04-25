##! python3-pyelftools — pure-Python ELF / DWARF parsing library
##!
##! Required by systemd-ukify and by systemd's meson configure probe
##! (which rejects the build if `import elftools` fails when
##! -Dukify=enabled). pyelftools has no external Python dependencies —
##! pure-Python walking of ELF section tables, DWARF debug info, and
##! the .note sections that sd-stub uses.
{
  mkDerivation,
  fetchurl,
  python3,
}: let
  version = "0.32";
  pyVersion = "3.14";
in
  mkDerivation {
    pname = "python3-pyelftools";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/eliben/pyelftools/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-gtA5m8500WL7p1s1aK1Hv0jtLF4Ci3ICa9wvZ4kD3n0=";
    };

    buildDeps = [];
    runtimeDeps = [python3];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd pyelftools-${version}
        '';
      }
      {
        name = "install";
        script = ''
          site=$out/lib/python${pyVersion}/site-packages
          mkdir -p "$site"
          cp -r elftools "$site/"
        '';
      }
    ];

    meta = {
      description = "pyelftools — pure-Python ELF/DWARF parser";
      homepage = "https://github.com/eliben/pyelftools";
      license = "Unlicense";
    };
  }
