##! Test-only provider artifact used by the package ability smoke fixture.
{
  mkDerivation,
  python3,
}: let
  selfReferentialDependency = mkDerivation {
    pname = "ability-package-smoke-self-reference";
    version = "1.0.0";
    src = null;
    dontNukeRefs = true;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          printf '%s\n' "$out" > "$out/self-reference"
        '';
      }
    ];
  };
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "build-input";
    };
    pname = "ability-package-smoke-provider";
    version = "1.0.0";
    src = null;
    runtimeDeps = [selfReferentialDependency python3];
    meta.mainProgram = "ability-package-smoke-provider";

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          printf '#!${python3}/bin/python3\n' > "$out/bin/ability-package-smoke-provider"
          cat ${./_ability-package-smoke/handler.py} >> "$out/bin/ability-package-smoke-provider"
          chmod +x "$out/bin/ability-package-smoke-provider"
          cp ${./_ability-package-smoke}/module.nix "$out/default.nix"
          printf '%s\n' '${selfReferentialDependency}' > "$out/transitive-dependency"
        '';
      }
    ];
  }
