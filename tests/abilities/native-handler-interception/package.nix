##! Retains a qualification-only response barrier and the actual native backend.
{
  mkDerivation,
  python3,
  backend,
  backendExecutable,
  pname ? "native-handler-interception-${backend.pname}",
}:
assert builtins.match "bin/[A-Za-z0-9+._-]+" backendExecutable != null;
assert builtins.match "native-handler-interception-[A-Za-z0-9+._-]+" pname != null;
  mkDerivation {
    inherit pname;
    version = "1";
    src = ./.;
    module = ./module;
    moduleDeps = [backend];
    runtimeDeps = [python3 backend];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          printf '#!${python3}/bin/python3\n' > "$out/bin/native-handler-interception"
          printf 'BACKEND = "%s"\n' '${backend}/${backendExecutable}' >> "$out/bin/native-handler-interception"
          cat native-handler-interception.py >> "$out/bin/native-handler-interception"
          chmod 0555 "$out/bin/native-handler-interception"
        '';
      }
    ];
    meta = {
      description = "Qualification-only native backend response barrier";
      license = "Apache-2.0";
      mainProgram = "native-handler-interception";
    };
  }
