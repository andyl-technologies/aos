##! Qualifies explicit native-library providers before migrating store consumers.
{
  pkgs,
  linkage ? "shared",
}: let
  foreignCpu =
    if pkgs.stdenv.hostPlatform.isx86_64
    then "aarch64"
    else "x86_64";
  extension =
    if linkage == "shared"
    then "so"
    else "a";
  libraries = pkgs.mkAosBazelNativeLibraries {
    libraries = {
      sqlite = {
        inherit linkage;
        package =
          if linkage == "shared"
          then pkgs.sqlite
          else pkgs.sqliteStatic;
        libraryFile = "lib/libsqlite3.${extension}";
      };
      zstd = {
        inherit linkage;
        package =
          if linkage == "shared"
          then pkgs.zstd
          else pkgs.zstdStaticMultithread;
        libraryFile = "lib/libzstd.${extension}";
      };
    };
  };
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/fixture" "tools/bazel/tests/native-libraries"];
  };
in
  pkgs.runCommand "aos-bazel-${linkage}-native-library-check" {
    buildDeps = [pkgs.python3 pkgs.binutils];
    dontNukeRefs = true;
  } ''
    mkdir workspace
    cp -a ${workspace.source}/. workspace/
    chmod -R u+w workspace
    cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
    ${pkgs.python3}/bin/python3 - ${workspace.configuration} <<'PYTHON'
    import json
    from pathlib import Path
    import sys

    configuration = json.loads(Path(sys.argv[1]).read_text())
    configuration["repositories"]["aos_native"] = "${libraries}"
    Path("configuration.json").write_text(json.dumps(configuration))
    PYTHON
    mkdir -p "$out/evidence"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
      --config "$PWD/configuration.json" --workspace "$PWD/workspace" \
      --output-base "$TMPDIR/bazel" --nix-sandbox --batch --prepare-lock \
      -- test //tools/bazel/tests/native-libraries:doc //tools/bazel/tests/native-libraries:c_app //tools/bazel/tests/native-libraries:rust_app \
      //tools/bazel/tests/native-libraries:license_closure \
      --build_event_json_file="$out/evidence/events.json" \
      --execution_log_json_file="$out/evidence/execution.json"
    ${pkgs.python3}/bin/python3 ${../../tools/bazel/metadata/export_tests.py} \
      --events "$out/evidence/events.json" --output "$out/evidence/tests"
    cp ${../../tools/bazel/tests/verify_cache.py} verify_cache.py
    cp ${../../tools/bazel/tests/family_libtest.py} family_libtest.py
    cp ${../../tools/bazel/tests/verify_native_libraries.py} verify_native_libraries.py
    ${pkgs.python3}/bin/python3 verify_native_libraries.py \
      --build "$out" --libraries ${libraries} --readelf ${pkgs.binutils}/bin/readelf

    mkdir workspace/platform-probe
    cat > workspace/platform-probe/BUILD.bazel <<'BUILD'
    platform(
        name = "foreign",
        constraint_values = ["@platforms//cpu:${foreignCpu}", "@platforms//os:linux"],
    )
    BUILD
    ${pkgs.python3}/bin/python3 - <<'PYTHON'
    import json
    from pathlib import Path

    configuration = json.loads(Path("configuration.json").read_text())
    configuration["target_platform"] = "//platform-probe:foreign"
    Path("foreign.json").write_text(json.dumps(configuration))
    configuration["target_platform"] = None
    del configuration["repositories"]["aos_native"]
    Path("missing.json").write_text(json.dumps(configuration))
    PYTHON
    for rejection in foreign missing; do
      if ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
        --config "$PWD/$rejection.json" --workspace "$PWD/workspace" \
        --output-base "$TMPDIR/reject-$rejection" --nix-sandbox --batch \
        -- build @aos_native//:sqlite --nobuild > "$out/evidence/rejected-$rejection.log" 2>&1; then
        echo "native library unexpectedly accepted $rejection configuration" >&2
        exit 1
      fi
    done
    grep -F 'incompatible' "$out/evidence/rejected-foreign.log"
    grep -F 'must be supplied by Nix' "$out/evidence/rejected-missing.log"
    printf 'PASS\n' > "$out/result"
  ''
