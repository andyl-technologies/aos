"""Retain the bounded pending-selectable witness without replacing a flight result."""

import re
import sys

INPUT_LIMIT = 16 * 1024 * 1024
ROW_LIMIT = 512
ROW_COUNT = 24
OUTPUT_LIMIT = ROW_LIMIT * ROW_COUNT
PREFIX = b"CRUCIBLE-SELECTABLE-RESUME-V1 "
PHASES = (
    b"pending",
    b"provider-unavailable",
    b"prepare-start-enter",
    b"prepare-start-return",
    b"stopped",
    b"resume-pending",
    b"resume-consumed",
    b"native-entry",
    b"native-return",
    b"rust-entry",
    b"pause-return",
    b"network-return",
    b"idle-control-return",
    b"idle-error",
    b"reply-enter",
    b"reply-dequeued",
    b"reply-completed",
    b"reply-return",
    b"control-return",
    b"already-running-return",
    b"running-return",
)

OPTION = rb"(?:None|Some\([0-9]+\))"
NATIVE = rb"(?:None|Some\(\([0-9]+, [0-9]+, [0-9]+, [0-9]+, [0-9]+, -?[0-9]+\)\))"

RECORD = re.compile(
    re.escape(PREFIX) + rb"phase=(?:" + b"|".join(PHASES) + rb") "
    rb"pid=[0-9]+ sequence=[0-9]+ request_vcpu=[0-9]+ vcpu=[0-9]+ raw=" + OPTION +
    rb" ps=" + OPTION + rb" read=" + OPTION + rb" write=" + OPTION +
    rb" native=" + NATIVE + rb"\n"
)


def retain(source, destination):
    """Forward complete bounded records and an explicit capture-coverage notice."""
    scanned = 0
    forwarded = 0
    rows = 0
    malformed = 0
    oversized = False
    input_capped = False
    output_capped = False
    at_line_start = True

    while scanned < INPUT_LIMIT:
        chunk = source.readline(min(ROW_LIMIT + 1, INPUT_LIMIT - scanned))
        if not chunk:
            break
        scanned += len(chunk)
        complete = chunk.endswith(b"\n")
        if at_line_start and chunk.startswith(PREFIX):
            if len(chunk) > ROW_LIMIT or not complete:
                oversized = True
            elif RECORD.fullmatch(chunk) is None:
                malformed += 1
            elif rows == ROW_COUNT or forwarded + len(chunk) > OUTPUT_LIMIT:
                output_capped = True
            else:
                destination.write(chunk)
                forwarded += len(chunk)
                rows += 1
        at_line_start = complete
    else:
        # Do not exceed the hard input ceiling to probe an additional byte.
        input_capped = True

    notice = (
        f"CRUCIBLE-SELECTABLE-RESUME-CAPTURE-V1 rows={rows} bytes={forwarded} "
        f"scanned={scanned} input_capped={int(input_capped)} "
        f"output_capped={int(output_capped)} malformed={malformed} "
        f"oversized={int(oversized)} absence_is_not_callback_proof=1\n"
    ).encode("ascii")
    if len(notice) > 256:
        raise ValueError("capture notice exceeded its fixed bound")
    destination.write(notice)


def main():
    try:
        with open(sys.argv[1], "rb") as source:
            retain(source, sys.stdout.buffer)
    except (OSError, ValueError, IndexError):
        # This program is advisory. Its caller retains and exits with the
        # producer's original status even when a diagnostic sink is unusable.
        try:
            sys.stdout.buffer.write(
                b"CRUCIBLE-SELECTABLE-RESUME-CAPTURE-V1 capture=unavailable "
                b"absence_is_not_callback_proof=1\n"
            )
        except OSError:
            pass


if __name__ == "__main__":
    main()
