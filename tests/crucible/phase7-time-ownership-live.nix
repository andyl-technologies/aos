# Loads the production plugin; parser fixtures alone cannot qualify ownership.
{
  pkgs,
  testing,
  productionFlightCommand,
  rootfsDeps,
  attemptHostSetupScript,
}:
testing.mkVMTest {
  name = "crucible-production-time-ownership-live";
  memory = 8192;
  timeout = 1200;
  rootfsDeps = rootfsDeps ++ [pkgs.python3];
  testScript = ''
    set -eu
    ${attemptHostSetupScript}
    export CRUCIBLE_TIME_OWNERSHIP_WITNESS=1
    result=/tmp/time-ownership-result
    capture=/tmp/time-ownership-native-receipts
    ${productionFlightCommand} /tmp/time-ownership-runtime-summary \
      > "$result" 2> "$capture"
    for evidence in PASS \
      diagnostic_mode=time-ownership \
      loaded_production_plugin=true \
      idle_hold_clock_unchanged=true \
      authorized_exact_timer_wake_raw_unchanged=true; do
      ${pkgs.grep}/bin/grep -Fxq "$evidence" "$result"
    done
    ${pkgs.python3}/bin/python3 ${./phase7-time-ownership-receipts.py} "$capture" \
      >> "$result"
    cat "$result"
    ${pkgs.python3}/bin/python3 - "$capture" <<'PY'
    import sys
    for line in open(sys.argv[1], "rb"):
        if line.startswith((b"CRUCIBLE-TIME-OWNER-V1 ", b"CRUCIBLE-TIME-HOLD-V1 ")):
            sys.stdout.buffer.write(line)
    PY
  '';
}
