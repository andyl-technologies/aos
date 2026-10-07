# Controlled Linux ACK comparison; timing remains advisory.
{
  pkgs,
  testing,
  rootfsDeps,
  attemptHostSetupScript,
  productionFlightCommand,
}: let
  vmTest = testing.mkVMTest {
    name = "crucible-linux-boot-ack-poll-pair";
    memory = 8192;
    timeout = 1200;
    rootfsDeps = rootfsDeps ++ [pkgs.python3 "${./linux-boot-ack-poll.py}"];
    testScript = ''
      set -eu
      ${attemptHostSetupScript}
      # Both fresh children use the same feature-enabled binary and guest profile.
      unset CRUCIBLE_CONTROL_CALLBACK_WITNESS CRUCIBLE_CONTROL_CALLBACK_STAGE_MIN_TOKEN \
        CRUCIBLE_MATERIALIZATION_DIAGNOSTIC_MAX_EVENTS CRUCIBLE_TIME_OWNERSHIP_WITNESS \
        CRUCIBLE_GUEST_CLOCK_READ_FLIGHT CRUCIBLE_PHASE4_PARTITION_PROBE \
        CRUCIBLE_PRODUCTION_PLUGIN_FLIGHT_BLOCK_RECOVERY_ONLY
      export CRUCIBLE_LINUX_BOOT_ACK_POLL_PAIR=1
      result=/tmp/linux-ack-poll.result
      capture=/tmp/linux-ack-poll.log
      if ${productionFlightCommand} /tmp/unused-linux-runtime-summary \
        > "$result" 2> "$capture"; then
        :
      else
        original_status=$?
        ${pkgs.coreutils}/bin/tail -c 16384 "$result" >&2 || true
        ${pkgs.coreutils}/bin/tail -c 65536 "$capture" >&2 || true
        exit "$original_status"
      fi
      if ${pkgs.python3}/bin/python3 ${./linux-boot-ack-poll.py} "$result"; then
        :
      else
        original_status=$?
        ${pkgs.coreutils}/bin/tail -c 16384 "$result" >&2 || true
        ${pkgs.coreutils}/bin/tail -c 65536 "$capture" >&2 || true
        exit "$original_status"
      fi
      cat "$result"
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-linux-boot-ack-poll-pair";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.sed pkgs.python3 vmTest];
    passthru = {inherit vmTest;};
    phases = [
      {
        name = "retain-result";
        script = ''
          set -eu
          ${pkgs.python3}/bin/python3 ${./linux-boot-ack-poll-tests.py} ${./linux-boot-ack-poll.py}
          mkdir -p "$out"
          ${pkgs.sed}/bin/sed 's/\r$//' "${vmTest}/serial.log" > "$out/vm-serial.log"
          cp "${vmTest}/fc.log" "$out/vm-monitor.log"
          ${pkgs.python3}/bin/python3 ${./linux-boot-ack-poll.py} \
            --serial "$out/vm-serial.log" "$out"
        '';
      }
    ];
  }
