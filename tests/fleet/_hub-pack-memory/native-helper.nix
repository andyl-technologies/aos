# Build the fixture-only lib-test from its explicitly captured auxiliary source.
# Ordinary Native/default workspace packages and their identities are unchanged.
{pkgs}: let
  native = pkgs.aos-hub;
  worker = pkgs.aos-hub-direct-guard-e2e.passthru.workerDist;
  selector = "storage_work::external_oci::tests::fleet::pack_memory::actual_pack_memory_native_consumer";
  externalOciSelector = "storage_work::external_oci::tests::fleet::actual_external_oci_fleet_origin";
  externalOciSetupSelector = "storage_work::external_oci::tests::fleet_setup::actual_external_oci_fleet_setup";
  cargoCommand = "test --release --frozen --offline --no-run -p aos-hub --lib --features postgres,required-live-dialects -j$NIX_BUILD_CORES";
in
  assert pkgs.stdenv.hostPlatform.isLinux && !pkgs.stdenv.isCross;
    pkgs.mkCargoPackage {
      pname = "aos-hub-pack-memory-contract";
      version = "0.1.0";
      src = native.src;
      cargoRoot = "crates";
      cargoWorkspaceMembers = import ../_hub-retained-workspace.nix native.src;
      cargoDeps = builtins.elemAt native.passthru.evidenceSources 1;
      # Native library tests import the pure Worker ledger and its regressions.
      postConfigure = ''
        mkdir -p aos-hub-worker/src
        cp ${worker.src}/crates/aos-hub-worker/src/hybrid_authority_state.rs aos-hub-worker/src/
        cp -r ${worker.src}/crates/aos-hub-worker/src/hybrid_authority_state aos-hub-worker/src/
      '';
      cargoBuildCommands = [cargoCommand];
      cargoEnv = {
        OPENSSL_DIR = "${pkgs.openssl}";
        OPENSSL_LIB_DIR = "${pkgs.openssl}/lib";
        OPENSSL_INCLUDE_DIR = "${pkgs.openssl}/include";
        OPENSSL_NO_VENDOR = "1";
        OPENSSL_STATIC = "0";
        LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
        PROTOC = "${pkgs.protobuf}/bin/protoc";
        AOS_HUB_CONSOLE_JS = "${pkgs.aos-hub-console-dist}/hub-console.js";
        AOS_HUB_CONSOLE_WASM = "${pkgs.aos-hub-console-dist}/hub-console_bg.wasm";
        AOS_HUB_CONSOLE_CSS = "${pkgs.aos-hub-console-dist}/hub-console.css";
      };
      buildDeps = [
        pkgs.perl
        pkgs.pkg-config
        pkgs.openssl
        pkgs.sqlite
        pkgs.protobuf
        pkgs.coreutils
        pkgs.grep
      ];
      runtimeDeps = [pkgs.openssl pkgs.sqlite pkgs.zlib];
      installBins = false;
      doCheck = false;

      postInstall = ''
        selected="$NIX_BUILD_TOP/managed-cleanup-test-executables"
        jq -r '
          select(.reason == "compiler-artifact"
            and .target.name == "aos_hub"
            and .target.kind == ["lib"]
            and .profile.test == true)
          | .executable // empty
        ' "$NIX_BUILD_TOP/cargo-build-messages.jsonl" | sort -u > "$selected"
        test "$(wc -l < "$selected")" -eq 1
        IFS= read -r executable < "$selected"
        test -f "$executable" && test -x "$executable"

        mkdir -p "$out/bin" "$out/nix-support"
        install -m 755 "$executable" "$out/bin/aos-hub-pack-memory-contract"
        "$out/bin/aos-hub-pack-memory-contract" \
          --list --ignored --exact '${selector}' \
          > "$out/nix-support/ignored-test-registration.txt"
        grep -Fx '${selector}: test' "$out/nix-support/ignored-test-registration.txt"
        "$out/bin/aos-hub-pack-memory-contract" \
          --list --ignored --exact '${externalOciSelector}' \
          > "$out/nix-support/external-oci-test-registration.txt"
        grep -Fx '${externalOciSelector}: test' "$out/nix-support/external-oci-test-registration.txt"
        "$out/bin/aos-hub-pack-memory-contract" \
          --list --ignored --exact '${externalOciSetupSelector}' \
          > "$out/nix-support/external-oci-setup-test-registration.txt"
        grep -Fx '${externalOciSetupSelector}: test' "$out/nix-support/external-oci-setup-test-registration.txt"
      '';

      # Ordinary fixup remains enabled. The tuple coordinator observes the final
      # installed ELF afterward; a pre-fixup digest would describe different bytes.
      passthru = {
        testSelector = selector;
        externalOciTestSelector = externalOciSelector;
        externalOciSetupTestSelector = externalOciSetupSelector;
        inherit cargoCommand;
        nativeFilteredSourceStorePath = toString native.src;
        workerFilteredSourceStorePath = toString worker.src;
        maximumExecutableBytes = 536870912;
      };
      meta.description = "Auxiliary current-source Native pack measurement consumer";
    }
