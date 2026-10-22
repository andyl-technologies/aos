##! Each invalidation experiment starts with its own cold local cache namespace.
{
  pkgs,
  workspace,
  trial,
}: let
  variants = ["header" "cpp-source" "rust-source" "generated-input" "generator-environment" "feature" "rust-flags" "tool-closure"];
  toolchains = variant: pkgs.mkAosBazelToolchains {identity = "invalidation:${trial}:${variant}";};
  configured = variant:
    pkgs.mkAosBazelWorkspace {
      root = ../..;
      sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/fixture"];
      toolchains = toolchains variant;
    };
  original = configured "baseline";
  snapshot = variant:
    pkgs.runCommand "aos-bazel-invalidation-source-${variant}" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      cp -a ${workspace.source}/. "$out/"
      chmod -R u+w "$out"
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/mutate_fixture.py} \
        --root "$out" --variant ${variant}
    '';
  experiment = variant: let
    cacheNamespace = "invalidation-${trial}-${variant}";
    baseline = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-${variant}-baseline";
      workspace = original;
      targets = ["//tools/bazel/tests/fixture:package"];
      inherit cacheNamespace;
    };
    candidate = (pkgs.mkAosBazelBuild {
      pname = "aos-bazel-invalidation-${variant}";
      workspace =
        (
          if variant == "tool-closure"
          then configured variant
          else original
        )
        // {source = snapshot variant;};
      targets = ["//tools/bazel/tests/fixture:package"];
      inherit cacheNamespace;
    }).overrideAttrs (previous: {buildDeps = previous.buildDeps ++ [baseline];});
  in
    pkgs.runCommand "aos-bazel-invalidation-proof-${variant}" {
      buildDeps = [pkgs.python3];
      selected = builtins.toJSON {${variant} = candidate;};
    } ''
      cp ${../../tools/bazel/tests/verify_cache.py} verify_cache.py
      cp ${../../tools/bazel/tests/verify_invalidation.py} verify_invalidation.py
      printf '%s\n' "$selected" > selected.json
      ${pkgs.python3}/bin/python3 verify_invalidation.py \
        --baseline ${baseline} --variants selected.json --output "$out"
    '';
in rec {
  cases = builtins.listToAttrs (map (variant: {
      name = variant;
      value = experiment variant;
    })
    variants);
  all = pkgs.runCommand "aos-bazel-cache-invalidation-matrix" {} ''
    mkdir -p "$out"
    ${pkgs.lib.concatStringsSep "\n" (map (variant: "cp ${cases.${variant}}/evidence.json \"$out/${variant}.json\"") variants)}
  '';
}
