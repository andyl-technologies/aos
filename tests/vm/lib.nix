# tests/vm/lib.nix — QEMU test harness with virtio-serial guest agent
#
# Inspired by:
# - Guix marionette: virtio-serial for structured guest communication
# - NixOS VM tests: declarative test scripts
# - Kola: purpose-built for immutable OS testing
#
# Our implementation: Nix + shell + a tiny guest agent.
#
# Architecture:
#   Host side:  QEMU with virtio-serial, chardev socket, socat for I/O
#   Guest side: /dev/virtio-ports/aos.test.agent, shell agent reads/executes
#
# The guest agent opens the virtio-serial port, signals readiness via JSON,
# and then enters a read-eval-respond loop. The host sends shell commands
# over the Unix socket; the agent executes them and returns structured JSON
# with exit_code, stdout, and stderr.

{ pkgs, lib }:

let
  # ---------------------------------------------------------------------------
  # Guest agent — injected into test images
  # ---------------------------------------------------------------------------
  # Opens /dev/virtio-ports/aos.test.agent and executes commands from host.
  # Protocol:
  #   Guest -> Host: {"status":"ready"}
  #   Host  -> Guest: <shell command string>
  #   Guest -> Host: {"exit_code":<int>,"stdout":"<escaped>","stderr":"<escaped>"}
  #   Host  -> Guest: SHUTDOWN
  #   Guest -> Host: {"status":"shutdown"}  (then powers off)

  guestAgent = pkgs.mkDerivation {
    pname = "aos-test-guest-agent";
    version = "0";
    src = null;

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p $out/bin $out/lib/systemd/system

          # --- Agent binary (shell script) ---
          cat > $out/bin/aos-test-agent << 'AGENT'
#!/bin/sh
# AOS VM Test Guest Agent
# Communicates over virtio-serial with the host test harness.

set -u

AGENT_PORT="/dev/virtio-ports/aos.test.agent"

# Wait for the virtio port to appear
while [ ! -e "$AGENT_PORT" ]; do
  sleep 0.1
done

# Signal ready
echo '{"status":"ready"}' > "$AGENT_PORT"

# Read and execute commands
while IFS= read -r cmd; do
  # Handle shutdown
  if [ "$cmd" = "SHUTDOWN" ]; then
    echo '{"status":"shutdown"}' > "$AGENT_PORT"
    poweroff -f
    exit 0
  fi

  # Execute command and capture output
  stdout=$(eval "$cmd" 2>/tmp/agent-stderr)
  exit_code=$?
  stderr=$(cat /tmp/agent-stderr 2>/dev/null || echo "")

  # Escape special characters for JSON output
  stdout_escaped=$(printf '%s' "$stdout" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g' | tr '\n' '\034' | sed 's/\034/\\n/g')
  stderr_escaped=$(printf '%s' "$stderr" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g' | tr '\n' '\034' | sed 's/\034/\\n/g')

  # Send JSON response
  printf '{"exit_code":%d,"stdout":"%s","stderr":"%s"}\n' \
    "$exit_code" "$stdout_escaped" "$stderr_escaped" > "$AGENT_PORT"
done < "$AGENT_PORT"
AGENT
          chmod +x $out/bin/aos-test-agent

          # --- systemd unit ---
          cat > $out/lib/systemd/system/aos-test-agent.service << 'UNIT'
[Unit]
Description=AOS VM Test Guest Agent
After=multi-user.target
ConditionPathExists=/dev/virtio-ports/aos.test.agent

[Service]
Type=simple
ExecStart=/opt/aos-test/bin/aos-test-agent
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
UNIT
        '';
      }
    ];
  };

  # ---------------------------------------------------------------------------
  # Build a test image with the guest agent injected
  # ---------------------------------------------------------------------------
  mkTestImage = { system, name }:
    let
      baseImage = import ../../images/builder.nix {
        inherit pkgs lib system;
        inherit name;
        diskSize = "8G";
        espSize = "512M";
        rootSize = "4G";
      };
    in baseImage;
    # NOTE: To fully integrate the guest agent, the image builder would
    # need to copy guestAgent into /opt/aos-test/ and enable the systemd
    # unit. This is left as a TODO since the image builder currently does
    # not support post-build injection hooks.

  # ---------------------------------------------------------------------------
  # Create a VM test derivation
  # ---------------------------------------------------------------------------
  # mkVMTest boots a QEMU VM with virtio-serial, waits for the guest agent,
  # then executes the test script which uses helper functions to run commands
  # in the guest and assert on their results.

  mkVMTest = { name, system, testScript, timeout ? 120 }:
    pkgs.mkDerivation {
      pname = "aos-vm-test-${name}";
      version = "0";
      src = null;

      buildDeps = [ pkgs.socat pkgs.jq ];

      phases = [
        {
          name = "test";
          script = ''
            set -euo pipefail

            IMAGE="${mkTestImage { inherit system name; }}"
            AGENT_SOCK="$TMPDIR/agent.sock"
            MONITOR_SOCK="$TMPDIR/monitor.sock"
            SERIAL_LOG="$TMPDIR/serial.log"

            # Launch QEMU with virtio-serial agent and monitor socket
            qemu-system-x86_64 \
              -machine q35,accel=kvm \
              -cpu host \
              -m 2048 \
              -smp 2 \
              -nographic \
              -drive file="$IMAGE",format=raw,if=virtio,readonly=on \
              -device virtio-serial \
              -device virtserialport,chardev=agent,name=aos.test.agent \
              -chardev socket,id=agent,path="$AGENT_SOCK",server=on,wait=off \
              -monitor unix:"$MONITOR_SOCK",server,nowait \
              -serial file:"$SERIAL_LOG" \
              -no-reboot &
            QEMU_PID=$!

            # Cleanup handler
            cleanup() {
              kill "$QEMU_PID" 2>/dev/null || true
              wait "$QEMU_PID" 2>/dev/null || true
            }
            trap cleanup EXIT

            # Wait for agent to become ready
            echo "Waiting for guest agent..."
            DEADLINE=$((SECONDS + ${builtins.toString timeout}))
            AGENT_READY=0
            while [ "$SECONDS" -lt "$DEADLINE" ]; do
              if [ -S "$AGENT_SOCK" ]; then
                RESPONSE=$(timeout 5 ${pkgs.socat}/bin/socat - UNIX-CONNECT:"$AGENT_SOCK" 2>/dev/null || true)
                if echo "$RESPONSE" | grep -q '"ready"'; then
                  echo "Guest agent ready."
                  AGENT_READY=1
                  break
                fi
              fi
              sleep 1
            done

            if [ "$AGENT_READY" -ne 1 ]; then
              echo "TIMEOUT: Guest agent did not become ready within ${builtins.toString timeout}s"
              echo "--- Serial log ---"
              cat "$SERIAL_LOG" 2>/dev/null || true
              exit 1
            fi

            # -----------------------------------------------------------------
            # Test helper functions
            # -----------------------------------------------------------------

            # Send a command to the guest and return the JSON response
            run_in_guest() {
              local cmd="$1"
              echo "$cmd" | ${pkgs.socat}/bin/socat - UNIX-CONNECT:"$AGENT_SOCK"
            }

            # Assert that a command exits successfully in the guest
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

            # Assert that a command's stdout contains an expected string
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

            # -----------------------------------------------------------------
            # Run the test script
            # -----------------------------------------------------------------
            echo ""
            echo "==> Running test: ${name}"
            echo ""

            ${testScript}

            # -----------------------------------------------------------------
            # Shutdown
            # -----------------------------------------------------------------
            echo ""
            echo "Shutting down guest..."
            run_in_guest "SHUTDOWN" || true
            wait "$QEMU_PID" 2>/dev/null || true
            trap - EXIT

            echo ""
            echo "==> All tests passed for: ${name}"
            mkdir -p $out
            cp "$SERIAL_LOG" $out/serial.log 2>/dev/null || true
            echo "PASS" > $out/result
          '';
        }
      ];

      requiredSystemFeatures = [ "kvm" ];
    };

in {
  inherit mkVMTest mkTestImage guestAgent;
}
