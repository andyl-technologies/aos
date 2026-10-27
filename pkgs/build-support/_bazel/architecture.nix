##! Exports separate production and complete Rust compilation dependency views.
{pkgs}: let
  root = ../../..;
  workspace = pkgs.mkAosBazelWorkspace {
    inherit root;
    # Qualification scripts and retained reports do not define the Rust graph.
    sourceDirectories = [
      "BUILD.bazel"
      "crates"
      "native"
      "tools/bazel/toolchains"
      "tools/bazel/rules"
      "tools/bazel/metadata"
      "tools/bazel/testing"
      "third_party/rust"
    ];
    repositories = pkgs.aosBazelRepositories;
    # Query needs the pinned rule implementations, but no crate archives,
    # application binaries, or profile-specific native libraries.
    analysisTargets = ["//tools/bazel/rules:dependency_profile"];
    batch = true;
  };
in
  pkgs.runCommand "aos-bazel-architecture" {
    buildDeps = [pkgs.python3 pkgs.bazel pkgs.openjdk];
  } ''
    cp -R ${workspace.source} workspace
    chmod -R u+w workspace
    cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
    mkdir -p "$out"

    ${pkgs.python3}/bin/python3 ${root + "/tools/bazel/launcher.py"} \
      --config ${workspace.configuration} --workspace "$PWD/workspace" \
      --output-base "$TMPDIR/bazel" --nix-sandbox -- query \
      'kind("(_source_package|rust_library|rust_binary|rust_proc_macro|rust_shared_library|rust_static_library|rust_test|_libtest_test|rust_doc|rust_doc_test|rust_clippy|rust_lint_config|cargo_build_script|alias|.*_profile_required) rule", //crates/... union //third_party/rust:all union //tools/bazel/rules:all) union kind("filegroup rule", //tools/bazel/rules:all)' \
      --output=streamed_jsonproto --proto:flatten_selects=false > "$out/rules.jsonl"

    ${pkgs.python3}/bin/python3 ${root + "/tools/bazel/metadata/export_architecture.py"} \
      --query "$out/rules.jsonl" --sdk-directory workspace/third_party/rust \
      --output "$out/architecture.json"
    cat > "$out/BUILD.bazel" <<'BUILD'
    exports_files(["architecture.json"], visibility = ["//visibility:public"])
    BUILD
    touch "$out/REPO.bazel"
  ''
