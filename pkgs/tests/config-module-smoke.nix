##! Package config-output smoke fixture.
{
  mkDerivation,
  bash,
}:
mkDerivation {
  pname = "config-module-smoke";
  version = "0";
  src = null;
  runtimeDeps = [bash];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/config-module-smoke"
        printf '%s\n' payload > "$out/share/config-module-smoke/payload.txt"
        ln -s '${bash}' "$out/share/config-module-smoke/bash"
      '';
    }
  ];

  abilities = ./_config-module-smoke/module.nix;

  meta = {
    description = "Package config-output smoke fixture";
    license = "Apache-2.0";
  };
}
