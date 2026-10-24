##! Checks measurement selection, accounting, and failure handling with AOS Python.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
  source = builtins.path {
    path = ../.;
    name = "aos-bazel-measurement-tests";
    filter = path: type:
      (type == "directory" && baseNameOf path != "__pycache__")
      || pkgs.lib.hasSuffix ".py" (baseNameOf path);
  };
in
  pkgs.runCommand "aos-bazel-measurement-checks" {buildDeps = [pkgs.python3];} ''
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 -m unittest discover \
      -s ${source}/bench -p 'test_*.py'
    mkdir -p "$out"
    printf 'PASS\n' > "$out/result"
  ''
