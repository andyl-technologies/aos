##! Test-only provider artifact used by the package ability smoke fixture.
{mkDerivation}: let
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
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "build-input";
    };
    pname = "ability-package-smoke-provider";
    version = "1.0.0";
    src = null;
    runtimeDeps = [selfReferentialDependency];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp ${./_ability-package-smoke}/default.nix "$out/default.nix"
          printf '%s\n' '${selfReferentialDependency}' > "$out/transitive-dependency"
        '';
      }
    ];
  }
