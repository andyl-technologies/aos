##! Each invalidation experiment starts with its own cold local cache namespace.
{
  pkgs,
  workspace,
  trial,
}: let
  variants = ["header" "cpp-source" "rust-source" "generated-input" "generator-environment" "feature" "rust-flags" "link-flags" "tool-closure" "rust-cpu" "sysroot" "pgo"];
  sysroot = variant:
    pkgs.runCommand "aos-bazel-${variant}-headers" {} ''
      cp -as ${pkgs.glibc.dev}/. "$out/"
      chmod u+w "$out" "$out/include"
      printf '#define AOS_CACHE_SYSROOT_VALUE %s\n' ${
        if variant == "sysroot"
        then "43"
        else "42"
      } \
        > "$out/include/aos-cache-probe.h"
    '';
  sysrootCompiler = variant:
    pkgs.runCommand "aos-bazel-${variant}-compiler" {dontNukeRefs = true;} ''
      mkdir -p "$out/bin"
      for tool in cc c++; do
        cat > "$out/bin/$tool" <<COMPILER
      #!${pkgs.bash}/bin/bash
      exec ${pkgs.cc}/bin/$tool -isystem ${sysroot variant}/include "\$@"
      COMPILER
        chmod +x "$out/bin/$tool"
      done
    '';
  replacedRust =
    pkgs.runCommand "aos-bazel-replaced-rust-executable" {
      version = pkgs.rust.version;
      runtimeDeps = [pkgs.rust pkgs.bash];
      dontNukeRefs = true;
    } ''
      mkdir -p "$out/bin"
      cat > "$out/bin/rustc.unwrapped" <<'RUSTC'
      #!${pkgs.bash}/bin/bash
      exec ${pkgs.rust}/bin/rustc.unwrapped "$@"
      RUSTC
      chmod +x "$out/bin/rustc.unwrapped"
      ln -s ${pkgs.rust}/bin/rustdoc.unwrapped "$out/bin/rustdoc.unwrapped"
      ln -s ${pkgs.rust}/lib "$out/lib"
    '';
  toolchains = variant:
    pkgs.mkAosBazelToolchains ({
        identity = "invalidation:${trial}";
        # Replace an actual compiler executable and its realized closure while
        # keeping the logical Bazel compiler label and output behavior unchanged.
        rust =
          if variant == "tool-closure"
          then replacedRust
          else pkgs.rust;
      }
      // pkgs.lib.optionalAttrs (builtins.elem variant ["sysroot" "sysroot-baseline"]) {
        glibc = pkgs.glibc // {dev = sysroot variant;};
        cc = sysrootCompiler variant;
        # The overlay retains the original AOS headers through symlinks.
        # Declare their canonical source root as well as the selected overlay.
        extraHeaderRoots = [pkgs.glibc.dev];
      });
  configured = variant:
    pkgs.mkAosBazelWorkspace {
      root = ../..;
      sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/fixture"];
      toolchains = toolchains variant;
    };
  original = configured "baseline";
  profiles = import ./_bazel-pgo-profiles.nix {
    inherit pkgs;
    workspace = original;
    source = snapshot "pgo-generate";
  };
  snapshot = variant:
    pkgs.runCommand "aos-bazel-invalidation-source-${variant}" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      cp -a ${workspace.source}/. "$out/"
      chmod -R u+w "$out"
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/mutate_fixture.py} \
        --root "$out" --variant ${variant} --cpu ${
        if pkgs.stdenv.hostPlatform.isx86_64
        then "x86_64"
        else "aarch64"
      }
      ${pkgs.lib.optionalString (builtins.elem variant ["pgo" "pgo-baseline"]) ''
        cp ${profiles}/${
          if variant == "pgo"
          then "changed"
          else "baseline"
        }.profdata \
          "$out/tools/bazel/tests/fixture/cache.profdata"
      ''}
    '';
  experiment = variant: let
    cacheNamespace = "invalidation-${trial}-${variant}";
    baselineVariant =
      if builtins.elem variant ["sysroot" "rust-cpu" "pgo"]
      then "${variant}-baseline"
      else null;
    baseline = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-${variant}-baseline";
      workspace =
        if baselineVariant == null
        then original
        else (configured baselineVariant) // {source = snapshot baselineVariant;};
      targets = ["//tools/bazel/tests/fixture:package"];
      inherit cacheNamespace;
    };
    candidate = (pkgs.mkAosBazelBuild {
      pname = "aos-bazel-invalidation-${variant}";
      workspace =
        (
          if builtins.elem variant ["tool-closure" "sysroot"]
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
        --baseline ${baseline} --variants selected.json --output "$out" \
        ${pkgs.lib.optionalString (variant == "pgo") "--pgo-profiles ${profiles}"}
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
