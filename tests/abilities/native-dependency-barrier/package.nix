##! Retains an independent native dependency marker for qualification flights.
{
  mkDerivation,
  python3,
}:
mkDerivation {
  pname = "native-dependency-barrier";
  version = "1";
  src = ./.;
  module = ./module;
  runtimeDeps = [python3];
  phases = [
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        printf '#!${python3}/bin/python3\n' > "$out/bin/native-dependency-barrier"
        cat native-dependency-barrier.py >> "$out/bin/native-dependency-barrier"
        chmod 0555 "$out/bin/native-dependency-barrier"
      '';
    }
  ];
  meta = {
    mainProgram = "native-dependency-barrier";
    license = "Apache-2.0";
  };
}
