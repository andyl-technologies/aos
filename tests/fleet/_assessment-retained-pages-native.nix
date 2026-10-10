# Source-built test transport with real database custody and the packaged CLI.
{pkgs}: let
  native = pkgs.aos-hub;
  # Core's Hybrid tests include Worker source by path. The serving slice omits
  # those test-only files; retain the established integration-test source.
  source = pkgs.aos.passthru.testTargets.src;
  vendor = builtins.elemAt native.passthru.evidenceSources 1;
  selector = "db::assessment::read_snapshot_tests::actual_cli_retains_scan_pages_across_database_reopen";
in
  assert builtins.pathExists (source + "/crates/aos-hub-worker/src/oci_manifest_ingress.rs");
    pkgs.mkCargoPackage {
      pname = "aos-assessment-retained-pages-fixture";
      version = "0.1.0";
      src = source;
      cargoRoot = "crates";
      cargoWorkspaceMembers = import ./_hub-retained-workspace.nix source;
      cargoDeps = vendor;
      cargoBuildCommands = ["test --release --frozen --offline --no-run -p aos-hub-core --lib -j$NIX_BUILD_CORES"];
      cargoEnv = {
        OPENSSL_DIR = "${pkgs.openssl}";
        OPENSSL_LIB_DIR = "${pkgs.openssl}/lib";
        OPENSSL_INCLUDE_DIR = "${pkgs.openssl}/include";
        OPENSSL_NO_VENDOR = "1";
        OPENSSL_STATIC = "0";
        LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
        PROTOC = "${pkgs.protobuf}/bin/protoc";
      };
      buildDeps = [pkgs.perl pkgs.pkg-config pkgs.openssl pkgs.sqlite pkgs.protobuf pkgs.coreutils pkgs.grep];
      runtimeDeps = [pkgs.openssl pkgs.sqlite pkgs.zlib];
      installBins = false;
      doCheck = false;
      postInstall = ''
        selected="$NIX_BUILD_TOP/assessment-retained-pages-executables"
        jq -r '
          select(.reason == "compiler-artifact" and .target.name == "aos_hub_core"
            and .target.kind == ["lib"] and .profile.test == true)
          | .executable // empty
        ' "$NIX_BUILD_TOP/cargo-build-messages.jsonl" | sort -u > "$selected"
        test "$(wc -l < "$selected")" -eq 1
        IFS= read -r executable < "$selected"
        mkdir -p "$out/bin" "$out/nix-support"
        install -m 755 "$executable" "$out/bin/aos-assessment-retained-pages-fixture"
        "$out/bin/aos-assessment-retained-pages-fixture" --list --ignored --exact '${selector}' > "$out/nix-support/test-registration.txt"
        grep -Fx '${selector}: test' "$out/nix-support/test-registration.txt"
      '';
      passthru.testSelector = selector;
      meta.description = "Retained assessment scan-list database and CLI acceptance fixture";
    }
