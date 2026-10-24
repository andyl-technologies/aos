##! Runs the CLI comparison with the same AOS native libraries and real fixtures.
{
  pkgs,
  fleet ? false,
}: let
  inputs = import ./_bazel-registry-native-inputs.nix {inherit pkgs;};
  console = pkgs.aosBazelConsoleAssets;
  nativeLibraries = inputs.nativeLibraries ++ [pkgs.sqlite];
  nativeTools = inputs.nativeTools ++ [pkgs.python3 pkgs.alejandra pkgs.mtools pkgs.tpm2-tools pkgs.util-linux pkgs.aos-landlock];
  cacheFixtures = import ./fixtures/apm-profile-lifecycle.nix {
    inherit pkgs;
    cache = true;
  };
  lifecycleFixtures = import ./fixtures/apm-profile-lifecycle.nix {inherit pkgs;};
  cargoSetup =
    inputs.cargoSetup
    + ''
      export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
      # The CLI tool also brings ordinary zstd. Select the multithreaded archive
      # before pkg-config searches that tool package's single-threaded archive.
      export PKG_CONFIG_PATH="${pkgs.zstdStaticMultithread}/lib/pkgconfig:$PKG_CONFIG_PATH"
      # Legacy cache transport cases need a physical private store for --dump.
      export NIX_REMOTE=local
      export NIX_STORE_DIR="$TMPDIR/cli-store"
      export NIX_STATE_DIR="$TMPDIR/cli-state"
      export NIX_LOG_DIR="$TMPDIR/cli-log"
      mkdir -p "$NIX_STORE_DIR" "$NIX_STATE_DIR" "$NIX_LOG_DIR"
      ${pkgs.nix}/bin/nix-store --init
      export AOS_NATIVE_CACHE_FIXTURES="${cacheFixtures}/fixtures.json"
      export AOS_LIFECYCLE_FIXTURES="${lifecycleFixtures}/fixtures.json"
      export AOS_LIFECYCLE_PYTHON="${pkgs.python3}/bin/python3"
      export AOS_LIFECYCLE_REGISTRY_SCRIPT="${./fixtures/apm_lifecycle_registry.py}"
      export NIX_CONFIG="experimental-features = nix-command flakes"
      export AOS_HUB_CONSOLE_JS="${console}/hub-console.js"
      export AOS_HUB_CONSOLE_WASM="${console}/hub-console_bg.wasm"
      export AOS_HUB_CONSOLE_CSS="${console}/hub-console.css"
      export AOS_MCOPY="${pkgs.mtools}/bin/mcopy"
      export AOS_LANDLOCK_WRAPPER="${pkgs.aos-landlock}/bin/aos-landlock"
      export AOS_UNSHARE="${pkgs.util-linux}/bin/unshare"
      export AOS_PRLIMIT="${pkgs.util-linux}/bin/prlimit"
      export AOS_TPM2_CREATEEK="${pkgs.tpm2-tools}/bin/tpm2_createek"
      export AOS_TPM2_CREATEAK="${pkgs.tpm2-tools}/bin/tpm2_createak"
      export AOS_TPM2_READPUBLIC="${pkgs.tpm2-tools}/bin/tpm2_readpublic"
      export AOS_TPM2_QUOTE="${pkgs.tpm2-tools}/bin/tpm2_quote"
      export AOS_TPM2_PCRREAD="${pkgs.tpm2-tools}/bin/tpm2_pcrread"
      export AOS_TPM2_PCREXTEND="${pkgs.tpm2-tools}/bin/tpm2_pcrextend"
      export AOS_TPM2_CHECKQUOTE="${pkgs.tpm2-tools}/bin/tpm2_checkquote"
      export AOS_TPM2_FLUSHCONTEXT="${pkgs.tpm2-tools}/bin/tpm2_flushcontext"
      export RUST_TEST_THREADS="$NIX_BUILD_CORES"
    '';
in
  import ./_bazel-cargo-oracle.nix {
    inherit pkgs nativeLibraries nativeTools cargoSetup;
    pname = "aos-bazel-aos-cli-${
      if fleet
      then "fleet-"
      else ""
    }cargo";
    cargoSource = import ../../pkgs/tools/aos/_workspace-source.nix {
      inherit (pkgs) lib;
      includeIntegrationInputs = true;
    };
    packages = ["aos-cli"];
    cargoFlags = pkgs.lib.optionals fleet ["--features" "release-fleet-fixture"];
  }
