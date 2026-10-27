##! Executes generated doctest runners with literal metadata and quoted arguments.
{pkgs}:
pkgs.runCommand "aos-bazel-rustdoc-runner-quoting" {
  buildDeps = [pkgs.rust pkgs.python3];
} ''
  rustc --edition=2021 \
    ${pkgs.aosBazelModules.rules_rust}/rust/private/rustdoc/rustdoc_test_writer.rs \
    -o writer
  mkdir -p "$out"
  ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_rustdoc_runner.py} \
    --writer "$PWD/writer" --bash ${pkgs.bash}/bin/bash --output "$out/evidence.json"
''
