# Runs the complete Publisher suite, including actual cgroup/process custody.
{
  lib,
  mkSystem,
  pkgs,
  ...
}: let
  tests = import ./_sandbox-native-unit-tests.nix {
    inherit lib pkgs;
    crate = "aos-sandbox-publisher";
    features = ["aos-sandbox-publisher/kernel-tests"];
  };
  system = mkSystem [
    ../../systems/server-test.nix
    {environment.systemPackages = [tests pkgs.util-linux];}
  ];
in {
  name = "sandbox-publisher-native-sessions";
  timeout = 600;
  bootTimeout = 240;
  machines.vm = {inherit system;};

  testScript = ''
    vm.wait_for_unit("multi-user.target", timeout=180)
    vm.succeed("install -d -m 0700 -o 1000 -g 1000 /var/lib/aos-sandbox-publisher-tests")
    vm.succeed("install -m 0755 ${tests}/bin/sandbox-unit-tests /var/lib/aos-sandbox-publisher-tests/suite")
    output = vm.succeed(
        "cd /var/lib/aos-sandbox-publisher-tests && "
        "RUST_MIN_STACK=33554432 ${pkgs.util-linux}/bin/setpriv "
        "--reuid=1000 --regid=1000 --clear-groups "
        "/var/lib/aos-sandbox-publisher-tests/suite --test-threads=1",
        timeout=180,
    )
    assert "test result: ok." in output, output
    assert "0 filtered out" in output, output
    for name in (
        "prepare_abort_closes_and_activation_authenticates_original_process",
        "fatal_receive_retires_transport_but_keeps_live_execution_reservation",
        "postcommit_prepared_retirement_keeps_exact_live_peer_pin",
        "same_cgroup_delegated_writer_is_not_the_registered_execution",
        "retired_original_process_must_exit_before_its_reservation_is_released",
    ):
        assert f"test publisher_sessions::kernel_tests::{name} ... ok" in output, output
  '';
}
