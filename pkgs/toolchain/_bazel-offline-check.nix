##! Offline Bazel workspace runner for package checks.
##!
##! Builds a small root module with the packaged Bazel inside the Nix sandbox.
##! Bazel resolves its implicit `bazel_tools` dependency graph even for an
##! empty root module, so every module in that graph is overridden with the
##! source module used to build Bazel itself. Module metadata that the graph
##! reads but never fetches comes from the vendored registry snapshot.
{
  lib,
  runCommand,
  bazel,
  sourceModules,
  registry,
}: let
  # The resolved dependency graph of an empty Bazel 9 root module. Bazel
  # rejects overrides for modules outside the graph, so this list is exact.
  graphModules = [
    "abseil-cpp"
    "apple_support"
    "bazel_features"
    "bazel_skylib"
    "buildozer"
    "googletest"
    "platforms"
    "protobuf"
    "re2"
    "rules_apple"
    "rules_cc"
    "rules_java"
    "rules_jvm_external"
    "rules_kotlin"
    "rules_license"
    "rules_pkg"
    "rules_proto"
    "rules_python"
    "rules_shell"
    "rules_swift"
    "stardoc"
    "zlib"
  ];

  overrideFlags =
    map (name: "common --override_module=${name}=${sourceModules.${name}}") graphModules;

  bazelrc = lib.concatStringsSep "\n" ([
      "common --registry=file://${registry}"
      "common --repository_disable_download"
      "common --curses=no"
      "build --spawn_strategy=standalone"
    ]
    ++ overrideFlags);
in
  # Returns a check derivation. `files` maps workspace-relative paths to their
  # contents; `script` runs in the workspace with `run_bazel` available.
  {
    name,
    files,
    script,
    buildDeps ? [],
  }:
    runCommand name {inherit buildDeps;} ''
      workspace="$TMPDIR/workspace"
      mkdir -p "$workspace" "$TMPDIR/home"
      export HOME="$TMPDIR/home"
      export USER=nixbld

      ${lib.concatStrings (lib.mapAttrsToList (path: contents: ''
          mkdir -p "$workspace/$(dirname ${lib.escapeShellArg path})"
          cat > "$workspace/"${lib.escapeShellArg path} <<'AOS_BAZEL_CHECK_FILE'
          ${contents}
          AOS_BAZEL_CHECK_FILE
        '')
        files)}
      cat > "$workspace/.bazelrc" <<'AOS_BAZEL_CHECK_RC'
      ${bazelrc}
      AOS_BAZEL_CHECK_RC

      # Each invocation gets its own output base, so nothing carries over
      # between runs except what the caller passes explicitly.
      run_bazel() {
        output_base="$1"
        shift
        ${bazel}/bin/bazel --batch \
          --output_user_root="$TMPDIR/bazel-user-root" \
          --output_base="$output_base" \
          "$@"
      }

      cd "$workspace"
      mkdir -p "$out"
      ${script}
      printf 'PASS\n' > "$out/result"
    ''
