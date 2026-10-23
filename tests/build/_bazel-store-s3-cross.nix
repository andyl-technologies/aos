##! Qualifies the S3 adapter family on an explicit foreign Linux target.
{pkgs}: let
  native = import ./_bazel-store-s3.nix {inherit pkgs;};
  targetPackages = (import ../.. {crossSystem = "aarch64-linux";}).pkgs;
  toolchains = pkgs.mkAosBazelCrossToolchains {inherit targetPackages;};
  libraries = pkgs.mkAosBazelNativeLibraries {
    platform = targetPackages.stdenv.hostPlatform;
    libraries = {
      sqlite = {
        package = targetPackages.sqlite;
        libraryFile = "lib/libsqlite3.so";
        pkgConfigFiles = ["lib/pkgconfig/sqlite3.pc"];
      };
      zstd = {
        package = targetPackages.zstdStaticMultithread;
        libraryFile = "lib/libzstd.a";
        linkage = "static";
        pkgConfigFiles = ["lib/pkgconfig/libzstd.pc"];
      };
    };
  };
  packages = [
    "crates/crucible/storage/crucible-store-s3"
  ];
  # Preserve both the ordinary unit tests and the ignored live-service suite.
  # A foreign build does not provision external S3 resources.
  targets = pkgs.lib.concatMap (directory: let
    files = builtins.readDir (../.. + "/${directory}/tests");
    integrations = map (pkgs.lib.removeSuffix ".rs") (builtins.filter
      (name: files.${name} == "regular" && pkgs.lib.hasSuffix ".rs" name)
      (builtins.attrNames files));
  in
    map (name: "//${directory}:${name}_binary") (["unit"] ++ integrations))
  packages;
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit toolchains;
    sourceInventory = ../../tools/bazel/metadata/store-s3-inventory.json;
    dependencyProfile = "store-s3";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.store-s3 // {aos_native = libraries;};
    targetPlatform = "//tools/bazel/toolchains:aarch64_linux";
    compileOnly = true;
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = map (directory: "//${directory}:unit") packages;
  };
  compilation =
    pkgs.runCommand "aos-bazel-store-s3-aarch64-compilation" {
      buildDeps = [pkgs.python3];
      outputs = ["out" "evidence"];
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
    } ''
      mkdir workspace tools
      cp -a ${workspace.source}/. workspace/
      chmod -R u+w workspace
      cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
      cp ${../../tools/bazel/tests/family_libtest.py} tools/family_libtest.py
      cp ${../../tools/bazel/tests/verify_cache.py} tools/verify_cache.py
      cp ${../../tools/bazel/tests/verify_cross_linux.py} tools/verify_cross_linux.py
      cp ${../../tools/bazel/tests/verify_family_cross.py} tools/verify_family_cross.py
      ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
        --config ${workspace.configuration} --workspace "$PWD/workspace" \
        --output-base "$TMPDIR/bazel" --nix-sandbox --batch \
        -- build ${pkgs.lib.escapeShellArgs targets} \
        --materialize_param_files \
        --build_event_json_file="$TMPDIR/events.json" \
        --execution_log_json_file="$TMPDIR/execution.json"
      ${pkgs.python3}/bin/python3 tools/verify_family_cross.py \
        --workspace "$PWD/workspace" --events "$TMPDIR/events.json" \
        --execution "$TMPDIR/execution.json" --parity ${native.oracle}/parity.json \
        --output "$out" --evidence "$evidence"
      cp "$TMPDIR/events.json" "$evidence/evidence/events.json"
    '';
  runtime = import ./_bazel-family-vm.nix {
    inherit pkgs targetPackages compilation;
    pname = "aos-bazel-store-s3-aarch64";
    loopbackNetworking = true;
    source = workspace.source;
  };
in
  runtime // {inherit compilation workspace libraries toolchains;}
