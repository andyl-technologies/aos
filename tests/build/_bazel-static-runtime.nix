##! Qualifies fully static target binaries while execution tools stay dynamic.
{pkgs}: let
  libraries = pkgs.mkAosBazelStaticLibraries {
    libraries = {
      sqlite = {
        package = pkgs.sqliteStatic;
        libraryFile = "lib/libsqlite3.a";
        linkage = "static";
        pkgConfigFiles = ["lib/pkgconfig/sqlite3.pc"];
      };
      zstd = {
        package = pkgs.zstdStaticMultithread;
        libraryFile = "lib/libzstd.a";
        linkage = "static";
        pkgConfigFiles = ["lib/pkgconfig/libzstd.pc"];
      };
    };
  };
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    repositories = pkgs.aosBazelRepositories // {aos_native = libraries;};
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/static-runtime" "tools/bazel/tests/native-libraries"];
    analysisTargets = ["//tools/bazel/tests/static-runtime:package"];
    rustcFlags = ["-Ctarget-feature=+crt-static" "-Crelocation-model=static"];
  };
in rec {
  inherit libraries workspace;
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-static-runtime-fixture";
    inherit workspace;
    targets = ["//tools/bazel/tests/static-runtime:package" "//tools/bazel/tests/static-runtime:license_closure"];
    sharedBuildCache = false;
    retainActionGraph = true;
  };
  package = pkgs.mkAosBazelPackage {
    pname = "aos-static-runtime-fixture";
    version = "1";
    inherit build;
    packageLabel = "//tools/bazel/tests/static-runtime:package";
  };
  all =
    pkgs.runCommand "aos-bazel-static-runtime-checks" {
      buildDeps = [pkgs.python3];
      outputChecks.out = {};
      exportReferencesGraph.package = [package];
    } ''
      mkdir -p "$out"
      cp ${../../tools/bazel/tests/verify_cache.py} verify_cache.py
      cp ${../../tools/bazel/tests/verify_static_runtime.py} verify_static_runtime.py
      ${pkgs.python3}/bin/python3 verify_static_runtime.py \
        --build ${build} --package ${package} --libraries ${libraries} \
        --readelf ${pkgs.binutils}/bin/readelf --output "$out/static-runtime.json"
      ${pkgs.python3}/bin/python3 - "$out/closure.json" <<'PYTHON'
      import json
      import os
      from pathlib import Path
      import sys

      graph = json.loads(Path(os.environ["NIX_ATTRS_JSON_FILE"]).read_text())["package"]
      references = {entry["path"]: entry["references"] for entry in graph}
      root = "${package}"
      # Static glibc embeds paths for optional locale, timezone and loader data.
      # Keep and report that Nix reference; ELF static linkage does not imply
      # that arbitrary libc functionality is independent of runtime data.
      runtime = json.loads(Path("${libraries}/static/closure.json").read_text())
      if set(references[root]) - {root, runtime["glibc"]}:
          raise ValueError(f"static package retained an unexpected runtime reference: {references[root]}")
      Path(sys.argv[1]).write_text(json.dumps({"root": root, "references": references[root],
          "glibc_data_reference": runtime["glibc"], "closure": graph}, indent=2) + "\n")
      PYTHON
    '';
}
