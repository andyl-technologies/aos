# Original-FD observation and custody with real read-only detached tmpfs roots.
#
# The Provider test uses synthetic signed DATA to qualify proof retention and
# substituted-FD refusal. This check does not qualify production ZFS, native
# admission, or manager authority.
{
  lib,
  testing,
  pkgs,
}: let
  packages = [
    "aos-sandbox-linux"
    "aos-sandbox-source-provider-security"
    "aos-sandbox-source-provider"
  ];
  packageFlags = builtins.concatStringsSep " " (map (name: "-p ${name}") packages);

  fixtures = pkgs.mkCargoPackage {
    pname = "aos-sandbox-source-provider-detached-root-vm-tests";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    # Provider's test-only journal dependency retains its release compile guard.
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES ${packageFlags}"
    ];
    # Run every default library test; ignored kernel fixtures stay guest-only.
    doCheck = true;
    cargoNextest = true;
    cargoTestFlags = "${packageFlags} --lib";
    installBins = false;
    buildDeps = [pkgs.protobuf];
    cargoEnv.PROTOC = "${pkgs.protobuf}/bin/protoc";
    runtimeDeps = [];

    # Pin the two guest executables before Nextest's default check phase.
    postBuild = ''
      mkdir detached-root-fixtures
      for crate in aos_sandbox_source_provider_security aos_sandbox_source_provider; do
        count=0
        for candidate in target/debug/deps/"$crate"-*; do
          if [ -f "$candidate" ] && [ -x "$candidate" ]; then
            install -m 0755 "$candidate" "detached-root-fixtures/$crate"
            count=$((count + 1))
          fi
        done
        if [ "$count" -ne 1 ]; then
          echo "expected exactly one $crate unit-test executable, found $count" >&2
          exit 1
        fi
      done
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      install -m 0755 detached-root-fixtures/* "$out/bin/"
    '';
  };
in
  testing.mkVMTest {
    name = "sandbox-source-provider-detached-root";
    rootfsDeps = [fixtures pkgs.coreutils pkgs.grep];
    memory = 512;
    testScript = ''
      set -eu
      exec > /dev/ttyS0 2>&1
      set -x
      unset LD_LIBRARY_PATH
      test "$(id -u)" = 0

      run_ignored_test() {
        executable=$1
        selector=$2
        "$executable" --ignored --exact "$selector" --list > /tmp/detached-root-selected-tests
        selected_count=$(${pkgs.grep}/bin/grep -c ': test$' /tmp/detached-root-selected-tests || true)
        if [ "$selected_count" -ne 1 ]; then
          echo "expected exactly one ignored test: $executable $selector; found $selected_count" >&2
          exit 1
        fi
        ${pkgs.grep}/bin/grep -Fx "$selector: test" /tmp/detached-root-selected-tests
        "$executable" --ignored --exact "$selector" --test-threads=1 --nocapture
      }

      run_ignored_test ${fixtures}/bin/aos_sandbox_source_provider_security \
        source_root_snapshot::tests::detached_physical_facts_do_not_fabricate_namespace_evidence
      run_ignored_test ${fixtures}/bin/aos_sandbox_source_provider \
        backend::tests::detached_native_original_proof_survives_duplication_and_security_handoff
    '';
  }
