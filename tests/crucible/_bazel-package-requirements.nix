##! Checks source-gate dependency requirements against the queried Bazel graph.
{
  pkgs,
  name,
  packages,
}: let
  requirements = builtins.toFile "${name}-package-requirements.json" (builtins.toJSON {
    schema_version = 1;
    inherit packages;
  });
in
  pkgs.runCommand "${name}-package-requirements" {
    buildDeps = [pkgs.python3];
    sharedBuildCache = false;
  } ''
    mkdir -p "$out"
    PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
      ${../../tools/bazel/tests/verify_package_requirements.py} \
      --graph ${pkgs.aosBazelArchitecture}/architecture.json \
      --requirements ${requirements} --output "$out/evidence.json"
    cp ${requirements} "$out/requirements.json"
    printf 'PASS\n' > "$out/result"
  ''
