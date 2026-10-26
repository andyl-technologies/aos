# Qualifies only the native stopped-owner reader against actual guest cgroups.
{
  lib,
  testing,
  pkgs,
}: let
  fixtures = pkgs.mkCargoPackage {
    pname = "aos-sandbox-method46-stopped-cgroup-tests";
    version = "0.1.0";
    src = import ../../pkgs/tools/aos/_workspace-source.nix {inherit lib;};
    cargoDeps = pkgs.aos.passthru.cargoDeps;
    cargoRoot = "crates";
    buildType = "debug";
    cargoBuildCommands = [
      "test --no-run --lib --frozen --offline -j$NIX_BUILD_CORES -p aos-sandbox-linux --features kernel-tests"
    ];
    # Ordinary tests run without the feature inside the build sandbox. The
    # fixed-name mutation fixture runs only in this dedicated disposable VM.
    doCheck = true;
    cargoTestFlags = "-p aos-sandbox-linux --lib";
    installBins = false;
    buildDeps = [pkgs.jq];
    runtimeDeps = [];
    RUST_MIN_STACK = "33554432";
    postBuild = import ../fleet/_cargo-libtest-artifact.nix {
      inherit lib pkgs;
      crate = "aos-sandbox-linux";
      destination = "kernel-fixtures/aos_sandbox_linux";
    };
    postInstall = ''
      install -D -m 0755 kernel-fixtures/aos_sandbox_linux "$out/bin/aos_sandbox_linux"
    '';
  };
  testName = "cgroup::method46_stopped_owner::kernel_tests::fixed_stopped_owners_retain_absence_empty_and_recursive_population";
in
  testing.mkVMTest {
    name = "sandbox-method46-stopped-cgroups";
    rootfsDeps = [fixtures pkgs.coreutils pkgs.grep];
    memory = 512;
    testScript = ''
      unset LD_LIBRARY_PATH
      export RUST_MIN_STACK=33554432
      export AOS_CGROUP_TEST_SLEEP=${pkgs.coreutils}/bin/sleep
      mkdir -p /sys/fs/cgroup
      mount -t cgroup2 none /sys/fs/cgroup

      # An exact test count prevents a missing feature/filter from reporting a
      # successful zero-test VM. Only the guest creates these fixed subtrees.
      ${fixtures}/bin/aos_sandbox_linux --exact --list ${testName} > /tmp/selected-tests
      selected_count=$(${pkgs.grep}/bin/grep -c ': test$' /tmp/selected-tests || true)
      test "$selected_count" -eq 1
      ${pkgs.grep}/bin/grep -Fx '${testName}: test' /tmp/selected-tests
      ${fixtures}/bin/aos_sandbox_linux --exact ${testName} --test-threads=1 --nocapture
      echo 'METHOD46 stopped-owner native cgroups: PASS'
    '';
  }
