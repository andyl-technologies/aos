##! mandoc — mdoc and man document formatter
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
}: let
  version = "1.14.6";
in
  mkDerivation {
    pname = "mandoc";
    inherit version;

    src = fetchurl {
      urls = ["https://mandoc.bsd.lv/snapshots/mandoc-${version}.tar.gz"];
      hash = "sha256-i/DVcPAecKbhJIhAiIcMvtdTfzYyjVEpCesQzVMXnZw=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [zlib];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd mandoc-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          cat >configure.local <<EOF
          PREFIX="$out"
          SBINDIR="$out/bin"
          MANPATH_DEFAULT="/run/current-system/sw/share/man"
          MANPATH_BASE="/run/current-system/sw/share/man"
          OSNAME="AOS"
          CC="$CC"
          AR="$AR"
          LD_OHASH="-lutil"
          LN="ln -sf"
          HAVE_WCHAR=1
          UTF8_LOCALE="C.UTF-8"
          EOF
          "$CONFIG_SHELL" ./configure
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-mandoc";
        tool = self;
        command = "printf '.Dd September 5, 2026\\n.Dt TEST 1\\n.Os\\n.Sh NAME\\n.Nm test\\n.Nd test document\\n' | mandoc -Tlint";
      };
    };

    meta = {
      description = "mdoc and man document formatter";
      homepage = "https://mandoc.bsd.lv/";
      license = "BSD-3-Clause";
      mainProgram = "mandoc";
    };
  }
