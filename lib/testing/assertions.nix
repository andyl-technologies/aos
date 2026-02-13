# lib/testing/assertions.nix — Shared shell test helpers
#
# Returns shell function definition strings that are embedded into
# VM and fleet test scripts. Extracted here so both harnesses share
# the same assertion logic.
#
# Usage (from vm.nix):
#   assertions = import ./assertions.nix;
#   ... ${assertions.vmHelpers} ...
#
# Usage (from fleet.nix):
#   assertions = import ./assertions.nix;
#   ... ${assertions.mkFleetHelpers "${pkgs.socat}/bin/socat"} ...

rec {
  # Shell helpers for single-VM tests.
  # Expects these shell variables/commands in the environment:
  #   $AGENT_SOCK — path to the virtio-serial Unix socket
  #   socat, jq   — in $PATH
  vmHelpers = ''
    # Send a command to the guest agent and read one JSON response line.
    run_in_guest() {
      local cmd="$1"
      (printf '%s\n' "$cmd"; sleep 30) | socat - UNIX-CONNECT:"$AGENT_SOCK" 2>/dev/null | head -1
    }

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

  # Shell helpers for fleet (multi-VM) tests.
  # Takes the absolute path to the socat binary (from nixpkgs).
  # Expects per-machine AGENT_SOCK_<name> variables and jq in $PATH.
  mkFleetHelpers = socatBin: ''
    # Run a command on a specific machine by name.
    run_on() {
      local machine="$1"
      local cmd="$2"
      local sock_var="AGENT_SOCK_$machine"
      echo "$cmd" | ${socatBin} - UNIX-CONNECT:"''${!sock_var}"
    }

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
  '';
}
