{
  mkDerivation,
  writeShellScriptBin,
}: let
  recorder = writeShellScriptBin "landlock-argv-test-recorder" ''
    set -eu

    state_dir=$1
    shift
    mkdir -p "$state_dir"
    out=$state_dir/argv
    : > "$out"
    printf 'argc=%s\n' "$#" >> "$out"

    i=0
    for arg in "$@"; do
      i=$((i + 1))
      printf 'arg%s=<%s>\n' "$i" "$arg" >> "$out"
    done
  '';
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "build-input";
    };
    pname = "landlock-argv-test";
    version = "1.0.0";
    src = null;

    runtimeDeps = [recorder];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/landlock-argv-test"
          printf landlock-argv-test > "$out/share/landlock-argv-test/payload.txt"
          mkdir -p "$out/bin"
          ln -s ${recorder}/bin/landlock-argv-test-recorder \
            "$out/bin/landlock-argv-test-recorder"
        '';
      }
    ];

    abilities = ./_landlock-argv-test;

    meta = {
      description = "AOS Landlock exec argv preservation test payload";
      license = "Apache-2.0";
    };
  }
