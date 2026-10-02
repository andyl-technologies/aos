# Build only the auxiliary lib-test executable from the selected runtime source.
# Ordinary Native/default workspace packages and their identities are unchanged.
{pkgs}: let
  native = pkgs.aos-hub;
  worker = pkgs.aos-hub-direct-guard-e2e.passthru.workerDist;
  selector = "storage_work::oci_cleanup::controlled::actual_managed_terminal_cleanup_pair";
  cargoCommand = "test --release --frozen --offline --no-run -p aos-hub --lib --features postgres,required-live-dialects -j$NIX_BUILD_CORES";
in
  assert pkgs.stdenv.hostPlatform.isLinux && !pkgs.stdenv.isCross;
    pkgs.mkCargoPackage {
      pname = "aos-hub-managed-cleanup-contract";
      version = "0.1.0";
      src = native.src;
      cargoRoot = "crates";
      cargoDeps = pkgs.fetchCargoVendor {
        src = native.src;
        name = "aos-vendor-0.1.0";
        sourceRoot = "source/crates";
        hash = "sha256-bFrGLJz08aNxlYogCpbDOy9Oh7uFIcLXm4lMe5Ce9no=";
      };
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
        install -m 755 "$executable" "$out/bin/aos-hub-managed-cleanup-contract"
        "$out/bin/aos-hub-managed-cleanup-contract" \
          --list --ignored --exact '${selector}' \
          > "$out/nix-support/ignored-test-registration.txt"
        grep -Fx '${selector}: test' "$out/nix-support/ignored-test-registration.txt"
      '';

      # Ordinary fixup remains enabled. The tuple coordinator observes the final
      # installed ELF afterward; a pre-fixup digest would describe different bytes.
      passthru = {
        testSelector = selector;
        inherit cargoCommand;
        nativeFilteredSourceStorePath = toString native.src;
        workerFilteredSourceStorePath = toString worker.src;
        maximumExecutableBytes = 536870912;
      };
      meta.description = "Auxiliary ignored Managed cleanup contract from the selected Hub source";
    }
