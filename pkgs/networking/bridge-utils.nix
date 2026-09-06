##! bridge-utils — Legacy Linux Ethernet bridge administration tools
{
  mkDerivation,
  fetchurl,
  autoconf,
  gnumake,
}: let
  version = "1.7.1";
in
  mkDerivation {
    pname = "bridge-utils";
    inherit version;
    src = fetchurl {
      urls = ["https://kernel.org/pub/linux/utils/net/bridge-utils/bridge-utils-${version}.tar.xz"];
      hash = "sha256-ph2L5PGhQFxgyO841UTwwYwFszubB+W0sxAzU2Fl5g4=";
    };
    buildDeps = [autoconf gnumake];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd bridge-utils-${version}
        '';
      }
      {
        name = "patch";
        script = ''
          sed -i '/AC_PROG_RANLIB/a AC_CHECK_TOOL([AR], [ar])' configure.ac
          sed -i 's/^AR=ar$/AR=@AR@/' libbridge/Makefile.in
        '';
      }
      {
        name = "configure";
        script = ''
          autoconf
          ./configure $configureFlags --prefix="$out"
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install
          test -x "$out/sbin/brctl"
        '';
      }
    ];
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-bridge-utils";
        tool = self;
        command = "brctl show >/dev/null";
      };
    };
    meta = {
      description = "Configures Linux Ethernet bridges with brctl";
      homepage = "https://wiki.linuxfoundation.org/networking/bridge";
      license = "GPL-2.0-or-later";
      mainProgram = "brctl";
    };
  }
