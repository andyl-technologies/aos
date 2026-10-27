##! Compares declared CLI programs from two fresh native compiler executions.
{
  pkgs,
  first,
  second,
  installed,
  repeated,
  runtime,
}: let
  scripts = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-native-cli-repeatability-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_cache.py" "verify_native_cli_repeatability.py"];
  };
in
  pkgs.runCommand "aos-bazel-cli-native-source-path-repeatability" {
    buildDeps = [pkgs.python3];
    sharedBuildCache = false;
  } ''
    mkdir -p "$out"
    PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${scripts} ${pkgs.python3}/bin/python3 \
      ${scripts}/verify_native_cli_repeatability.py \
      --first ${first} --second ${second} \
      --installed ${installed} --repeated ${repeated} \
      --runtime ${runtime}/report.json --output "$out/evidence.json"
  ''
