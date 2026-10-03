# Retain the host lib-test consumer of actual Worker verification observations.
# This auxiliary output shares the selected Worker source and does not replace
# its Wasm distribution, the ordinary Native service or any production command.
{pkgs}: let
  worker = pkgs.aos-hub-direct-guard-e2e.passthru.workerDist;
  selector = "external_object::stage::tests::observation::actual_verification_hold_observation";
  # The Native test-support dependency requires the ordinary test profile.
  cargoCommand = "test --frozen --offline --no-run -p aos-hub-worker --lib --features do-e2e -j$NIX_BUILD_CORES";
in
  assert pkgs.stdenv.hostPlatform.isLinux && !pkgs.stdenv.isCross;
    pkgs.mkCargoPackage {
      pname = "aos-hub-worker-verification-observation";
      version = "0.1.0";
      src = worker.src;
      cargoRoot = "crates";
      cargoDeps = pkgs.fetchCargoVendor {
        src = worker.src;
        name = "aos-vendor-0.1.0";
        sourceRoot = "source/crates";
        hash = "sha256-WGkOGTHCcEgqZb0Igesu7xXTnhmEifgKt1IS0ARGuCI=";
      };
      cargoBuildCommands = [cargoCommand];
      cargoEnv = {
        # Host tests also compile the Native service's development dependencies.
        OPENSSL_DIR = "${pkgs.openssl}";
        OPENSSL_LIB_DIR = "${pkgs.openssl}/lib";
        OPENSSL_INCLUDE_DIR = "${pkgs.openssl}/include";
        OPENSSL_NO_VENDOR = "1";
        OPENSSL_STATIC = "0";
        LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";
        AOS_HUB_WORKER_SOURCE_DIGEST = builtins.hashString "sha256" (toString worker.src);
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
        selected="$NIX_BUILD_TOP/worker-verification-test-executables"
        jq -r '
          select(.reason == "compiler-artifact"
            and .target.name == "aos_hub_worker"
            and .target.kind == ["cdylib", "rlib"]
            and .profile.test == true)
          | .executable // empty
        ' "$NIX_BUILD_TOP/cargo-build-messages.jsonl" | sort -u > "$selected"
        test "$(wc -l < "$selected")" -eq 1
        IFS= read -r executable < "$selected"
        test -f "$executable" && test -x "$executable"

        mkdir -p "$out/bin" "$out/nix-support"
        install -m 755 "$executable" "$out/bin/aos-hub-worker-verification-observation"
        "$out/bin/aos-hub-worker-verification-observation" \
          --list --ignored --exact '${selector}' \
          > "$out/nix-support/ignored-test-registration.txt"
        grep -Fx '${selector}: test' "$out/nix-support/ignored-test-registration.txt"
      '';

      passthru = {
        testSelector = selector;
        inherit cargoCommand;
        workerFilteredSourceStorePath = toString worker.src;
        maximumExecutableBytes = 536870912;
      };
      meta.description = "Auxiliary actual Worker verification observation consumer from the selected source";
    }
