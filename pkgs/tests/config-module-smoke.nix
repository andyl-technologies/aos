##! Package config-output smoke fixture.
{mkDerivation, bash}:
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

  configModule = {
    src = ./_config-module-smoke;
    dependencies.bash = bash;
    moduleAbiCompat = {
      min = 1;
      max = 1;
    };
    declares = [
      "configModuleSmoke.command"
      "configModuleSmoke.enable"
      "configModuleSmoke.privateMessage"
    ];
    ownsRoots = [
      {
        root = "configModuleSmoke";
        interfaceAbi = 1;
        contributable = [];
      }
    ];
  };

  meta = {
    description = "Package config-output smoke fixture";
    license = "Apache-2.0";
  };
}
