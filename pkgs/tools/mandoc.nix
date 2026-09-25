##! mandoc — mdoc and man document formatter
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  stdenv,
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
          ${
            if stdenv.hostPlatform.isDarwin
            then ''
              # Configure executes probes; these interfaces are in the Darwin
              # SDK and must be declared for a Linux-hosted build.
              HAVE_NTOHL=1
              HAVE_NANOSLEEP=1
              HAVE_ISBLANK=1
              HAVE_STRLCAT=1
              HAVE_STRLCPY=1
            ''
            else ""
          }
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
