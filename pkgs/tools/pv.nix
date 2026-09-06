##! pv — Pipeline progress monitor
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "1.10.5";
in
  mkDerivation {
    pname = "pv";
    inherit version;

    src = fetchurl {
      urls = ["https://www.ivarch.com/programs/sources/pv-${version}.tar.gz"];
      hash = "sha256-qyG0+GYigGRragLhufCWeQkY+JyVK74NBv73XTtS+xU=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd pv-${version}
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
        script = ''make install'';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-pv";
        tool = self;
        command = "printf test | pv -q >/dev/null";
      };
    };

    meta = {
      description = "Monitors the progress of data through a pipeline";
      homepage = "https://www.ivarch.com/programs/pv.shtml";
      license = "GPL-3.0-or-later";
      mainProgram = "pv";
    };
  }
