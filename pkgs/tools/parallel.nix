##! GNU parallel — Parallel shell job runner
{
  mkDerivation,
  fetchurl,
  gnumake,
  perl,
  procps-ng,
  coreutils,
  gawk,
}: let
  version = "20260422";
in
  mkDerivation {
    pname = "parallel";
    inherit version;

    src = fetchurl {
      urls = ["https://ftpmirror.gnu.org/parallel/parallel-${version}.tar.bz2"];
      hash = "sha256-ZkzxZdZuohey9JzZanhl7PkMnQYWWZzCq6jK1IHZB7s=";
    };

    buildDeps = [gnumake perl];
    runtimeDeps = [perl procps-ng coreutils gawk];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd parallel-${version}
        '';
      }
      {
        name = "configure";
        script = ''./configure $configureFlags --prefix="$out"'';
      }
      {
        name = "build";
        script = ''make SHELL="$CONFIG_SHELL" -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          for program in parallel sql niceload parcat parset parsort; do
            sed -i "1s|^#!.*|#!${perl}/bin/perl|" "src/$program"
          done
          make SHELL="$CONFIG_SHELL" install
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-parallel";
        tool = self;
        command = "parallel --version";
      };
    };

    meta = {
      description = "Executes shell jobs in parallel";
      homepage = "https://www.gnu.org/software/parallel/";
      license = "GPL-3.0-or-later";
      mainProgram = "parallel";
    };
  }
