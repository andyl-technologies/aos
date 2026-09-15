##! Native package ability projection smoke fixture.
{
  mkDerivation,
}:
  mkDerivation {
    pname = "ability-package-smoke";
    version = "1.0.0";
    src = null;
    runtimeDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/ability-package-smoke"
          cp ${./_ability-package-smoke}/default.nix "$out/share/ability-package-smoke/provider.nix"
        '';
      }
    ];

    abilities = ./_ability-package-smoke-module.nix;

    meta = {
      description = "Native package ability projection smoke fixture";
      license = "Apache-2.0";
    };
  }
