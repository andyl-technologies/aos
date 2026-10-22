##! Separate Nix executions share only disk action results, never output bases.
{
  pkgs,
  workspace,
  trial ? "qualification-v1",
}: let
  lib = pkgs.lib;
  toolchains = pkgs.mkAosBazelToolchains {identity = "cache-proof:${trial}";};
  configured = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/tests/fixture"];
    inherit toolchains;
  };
  snapshot = edited:
    pkgs.runCommand "aos-bazel-cache-source-${
      if edited
      then "edited"
      else "original"
    }" {
      buildDeps = [pkgs.python3];
    } ''
      mkdir -p "$out"
      cp -a ${workspace.source}/. "$out/"
      chmod -R u+w "$out"
      ${lib.optionalString edited ''
        ${pkgs.python3}/bin/python3 - "$out" <<'PY'
        from pathlib import Path
        import sys

        root = Path(sys.argv[1]) / "tools/bazel/tests/fixture"
        for filename, original, replacement in [
            ("main.rs", "fixture_library::answer()", "fixture_library::answer() + 1"),
            ("main.cc", "fixture_answer()", "fixture_answer() + 1"),
        ]:
            path = root / filename
            text = path.read_text()
            if text.count(original) != 1:
                raise ValueError(f"fixture edit no longer applies: {filename}")
            path.write_text(text.replace(original, replacement))
        PY
      ''}
    '';
  build = name: edited: sharedBuildCache:
    pkgs.mkAosBazelBuild {
      pname = "aos-bazel-cache-${name}";
      workspace = configured // {source = snapshot edited;};
      targets = ["//tools/bazel/tests/fixture:package"];
      inherit sharedBuildCache;
    };
in rec {
  producer = build "producer" false true;
  consumer = (build "consumer" true true).overrideAttrs (previous: {
    # Establish order without exposing the producer execution tree. The
    # launcher strips the stdenv environment before action construction.
    buildDeps = previous.buildDeps ++ [producer];
  });
  uncached = build "uncached" true false;
  verify =
    pkgs.runCommand "aos-bazel-cross-derivation-cache-proof" {
      buildDeps = [pkgs.python3];
    } ''
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/verify_cache.py} \
        --producer ${producer} --consumer ${consumer} --uncached ${uncached} --output "$out"
    '';
}
