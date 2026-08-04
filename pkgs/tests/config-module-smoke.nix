##! RFC-0011 package config-output smoke fixture.
{mkDerivation}:
mkDerivation {
  pname = "config-module-smoke";
  version = "0";
  src = null;

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/share/config-module-smoke"
        printf '%s\n' payload > "$out/share/config-module-smoke/payload.txt"
      '';
    }
  ];

  configModule = {
    src = ./_config-module-smoke;
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

  meta.description = "RFC-0011 package config-output smoke fixture";
}
