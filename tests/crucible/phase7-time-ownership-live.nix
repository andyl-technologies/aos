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

    report_failure() {
      failure_status=$1
      failure_stage=$2
      # Diagnostic I/O must never replace the original producer/check failure.
      ${pkgs.python3}/bin/python3 - "$failure_stage" "$failure_status" "$result" "$capture" <<'PY' || true
    import os
    import sys

    stage, status, result, capture = sys.argv[1:]
    output = sys.stdout.buffer
    print(f"time-ownership failure stage={stage} status={status}", flush=True)

    def tail(path, limit, label):
        print(f"--- {label} (last {limit} bytes) ---", flush=True)
        try:
            with open(path, "rb") as stream:
                stream.seek(0, os.SEEK_END)
                stream.seek(max(0, stream.tell() - limit))
                data = stream.read(limit)
        except OSError:
            print(f"{label} unavailable", flush=True)
            return
        output.write(data)
        output.write(b"\n")
        output.flush()

    tail(result, 16 * 1024, "original result")
    print("--- selected original ownership/hold rows (unvalidated) ---", flush=True)
    prefixes = (b"CRUCIBLE-TIME-OWNER-V1 ", b"CRUCIBLE-TIME-HOLD-V1 ")
    input_limit = 16 * 1024 * 1024
    selected_limit = 64 * 1024
    read_bytes = selected_bytes = 0
    truncated = omitted = False
    try:
        with open(capture, "rb") as stream:
            while read_bytes < input_limit:
                line = stream.readline(min(257, input_limit - read_bytes))
                if not line:
                    break
                read_bytes += len(line)
                complete = line.endswith(b"\n")
                if line.startswith(prefixes):
                    if not complete or len(line) > 256:
                        omitted = True
                    elif selected_bytes + len(line) > selected_limit:
                        truncated = True
                        break
                    else:
                        output.write(line)
                        selected_bytes += len(line)
                # Skip the rest of a long line; its fragments are not rows.
                while not complete and read_bytes < input_limit:
                    line = stream.readline(min(257, input_limit - read_bytes))
                    if not line:
                        break
                    read_bytes += len(line)
                    complete = line.endswith(b"\n")
            truncated |= os.fstat(stream.fileno()).st_size > read_bytes
    except OSError:
        print("selected original rows unavailable", flush=True)
    output.flush()
    if omitted:
        print("oversized or incomplete selected rows omitted", flush=True)
    if truncated:
        print("selected rows truncated at 16 MiB input or 64 KiB output", flush=True)
    tail(capture, 64 * 1024, "original diagnostic stderr")
    PY
      exit "$failure_status"
    }

    if ${productionFlightCommand} /tmp/time-ownership-runtime-summary \
      > "$result" 2> "$capture"; then
      :
    else
      report_failure "$?" producer
    fi

    for evidence in PASS \
      diagnostic_mode=time-ownership \
      loaded_production_plugin=true \
      idle_hold_clock_unchanged=true \
      authorized_exact_timer_wake_raw_unchanged=true; do
      if ${pkgs.grep}/bin/grep -Fxq "$evidence" "$result"; then
        :
      else
        report_failure "$?" "required-result:$evidence"
      fi
    done

    if ${pkgs.python3}/bin/python3 ${./phase7-time-ownership-receipts.py} "$capture" \
      >> "$result"; then
      :
    else
      report_failure "$?" parser
    fi
    cat "$result"
    ${pkgs.python3}/bin/python3 - "$capture" <<'PY'
    import sys
    for line in open(sys.argv[1], "rb"):
        if line.startswith((b"CRUCIBLE-TIME-OWNER-V1 ", b"CRUCIBLE-TIME-HOLD-V1 ")):
            sys.stdout.buffer.write(line)
    PY
  '';
}
