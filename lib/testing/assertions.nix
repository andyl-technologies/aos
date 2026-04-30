# lib/testing/assertions.nix — Shared shell test helpers
#
# Returns shell function definition strings that are embedded into
# VM and fleet test scripts. Extracted here so both harnesses share
# the same assertion logic.
#
# Usage (from vm.nix / fleet.nix):
#   assertions = import ./assertions.nix { inherit (pkgs) aos-agent-rpc; };
#   ... ${assertions.vmHelpers} ...
#   ... ${assertions.fleetHelpers} ...
#   ... ${assertions.fleetVsockHelpers} ...
{aos-agent-rpc}: let
  rpc = "${aos-agent-rpc}/bin/aos-agent-rpc";

  # Assertion helpers for single-VM tests.
  # These call run_in_guest() which must be defined before they are used.
  vmAssertions = ''
    # Assert that a command exits 0 in the guest.
    assert_success() {
      local cmd="$1"
      local desc="''${2:-$cmd}"
      RESULT=$(run_in_guest "$cmd")
      EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code')
      if [ "$EXIT_CODE" != "0" ]; then
        echo "FAIL: $desc"
        echo "  command: $cmd"
        echo "  exit_code: $EXIT_CODE"
        echo "  stdout: $(echo "$RESULT" | jq -r '.stdout')"
        echo "  stderr: $(echo "$RESULT" | jq -r '.stderr')"
        return 1
      fi
      echo "PASS: $desc"
    }

    # Assert that a command's stdout contains a substring.
    assert_output_contains() {
      local cmd="$1"
      local expected="$2"
      local desc="''${3:-$cmd contains $expected}"
      RESULT=$(run_in_guest "$cmd")
      STDOUT=$(echo "$RESULT" | jq -r '.stdout')
      if ! echo "$STDOUT" | grep -q "$expected"; then
        echo "FAIL: $desc"
        echo "  expected to contain: $expected"
        echo "  actual output: $STDOUT"
        return 1
      fi
      echo "PASS: $desc"
    }
  '';

  # Assertion helpers for fleet (multi-VM) tests.
  # These call run_on() which must be defined before they are used.
  fleetAssertions = ''
    # Assert a command succeeds on a specific machine.
    assert_on() {
      local machine="$1"
      local cmd="$2"
      local desc="''${3:-[$machine] $cmd}"
      RESULT=$(run_on "$machine" "$cmd")
      EXIT_CODE=$(echo "$RESULT" | jq -r '.exit_code')
      if [ "$EXIT_CODE" != "0" ]; then
        echo "FAIL: $desc"
        echo "  stdout: $(echo "$RESULT" | jq -r '.stdout')"
        echo "  stderr: $(echo "$RESULT" | jq -r '.stderr')"
        return 1
      fi
      echo "PASS: $desc"
    }

    # Assert a command's stdout contains a substring on a specific machine.
    assert_output_on() {
      local machine="$1"
      local cmd="$2"
      local expected="$3"
      local desc="''${4:-[$machine] $cmd contains $expected}"
      RESULT=$(run_on "$machine" "$cmd")
      STDOUT=$(echo "$RESULT" | jq -r '.stdout')
      if ! echo "$STDOUT" | grep -q "$expected"; then
        echo "FAIL: $desc"
        echo "  expected to contain: $expected"
        echo "  actual output: $STDOUT"
        return 1
      fi
      echo "PASS: $desc"
    }
  '';
in {
  # Store path to the binary, for inline calls in vm.nix / fleet.nix.
  rpcBin = rpc;

  # Shell helpers for single-VM tests (Firecracker vsock driver).
  # Expects $VSOCK_UDS and jq in the environment.
  vmHelpers = ''
    run_in_guest() {
      ${rpc} --driver firecracker "$VSOCK_UDS" "$1"
    }
    ${vmAssertions}
  '';

  # Shell helpers for fleet tests (QEMU virtio-serial driver).
  # Expects AGENT_SOCK_<name> variables and jq in the environment.
  fleetHelpers = ''
    run_on() {
      local machine="$1"
      local cmd="$2"
      local sock_var="AGENT_SOCK_$machine"
      ${rpc} --driver qemu "''${!sock_var}" "$cmd"
    }
    ${fleetAssertions}
  '';

  # Shell helpers for fleet tests (Firecracker vsock driver).
  # Expects VSOCK_UDS_<name> variables and jq in the environment.
  fleetVsockHelpers = ''
    run_on() {
      local machine="$1"
      local cmd="$2"
      local uds_var="VSOCK_UDS_$machine"
      ${rpc} --driver firecracker "''${!uds_var}" "$cmd"
    }
    ${fleetAssertions}
  '';
}
