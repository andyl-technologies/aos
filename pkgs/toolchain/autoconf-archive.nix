##! autoconf-archive — Collection of reusable Autoconf macros
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2024.10.16";
in
  mkDerivation {
    pname = "autoconf-archive";
    inherit version;
    src = fetchurl {
      urls = ["https://ftpmirror.gnu.org/autoconf-archive/autoconf-archive-${version}.tar.xz"];
      hash = "sha256-e81dABkW86UO10NvT3AOPSsbrePtgDIZxZLWJQKlc2M=";
    };
    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd autoconf-archive-${version}
        '';
      }
      {
        name = "configure";
        script = ''./configure $configureFlags --prefix="$out"'';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          test -f "$out/share/aclocal/ax_pthread.m4"
        '';
      }
    ];
    meta = {
      description = "Provides reusable macros for GNU Autoconf";
      homepage = "https://www.gnu.org/software/autoconf-archive/";
      license = "GPL-3.0-only";
    };
  }
