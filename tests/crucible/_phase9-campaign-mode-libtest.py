"""Validates libtest selection and execution before campaign-mode evidence."""

import re
import shlex


_SUCCESS_SUMMARY = re.compile(
    r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"\d+ measured; \d+ filtered out; finished in [0-9.]+s"
)
_SUCCESSFUL_TEST = re.compile(r"test (.+?)(?: - should panic)? \.\.\. ok")


def run_campaign_mode_test(
    executable, arguments, evidence, expected_count, run_command
):
    """Returns a transcript and PASS evidence only after all selected tests pass.

    ``run_command`` must reject unsuccessful exits and accept ``timeout``.
    A whole-binary command may use ``None`` for its expected count; its positive
    listing then supplies the count that execution must satisfy.
    """
    command_prefix = [shlex.quote(executable)] + [
        shlex.quote(argument) for argument in arguments
    ]
    list_command = " ".join(command_prefix + ["--list", "--format", "terse"])
    listed = run_command(list_command, timeout=900)
    listed_names = [
        line.removesuffix(": test")
        for line in listed.splitlines()
        if line.endswith(": test")
    ]
    listed_count = len(listed_names)

    if listed_count <= 0:
        raise ValueError(f"{evidence}: no tests selected\n{listed}")
    if any(not name for name in listed_names) or len(set(listed_names)) != listed_count:
        raise ValueError(f"{evidence}: invalid or duplicate listed test names\n{listed}")
    if expected_count is None:
        expected_count = listed_count
    if expected_count <= 0 or listed_count != expected_count:
        raise ValueError(
            f"{evidence}: listed {listed_count} tests, expected {expected_count}\n"
            f"{listed}"
        )

    command = " ".join(command_prefix + ["--test-threads=1"])
    transcript = run_command(command, timeout=900)
    summaries = [
        match
        for line in transcript.splitlines()
        if (match := _SUCCESS_SUMMARY.fullmatch(line)) is not None
    ]
    if len(summaries) != 1:
        raise ValueError(
            f"{evidence}: expected one libtest success summary, "
            f"found {len(summaries)}\n{transcript}"
        )

    passed, failed, ignored = map(int, summaries[0].groups())
    if (passed, failed, ignored) != (expected_count, 0, 0):
        raise ValueError(
            f"{evidence}: executed counts "
            f"passed={passed}, failed={failed}, ignored={ignored}; "
            f"expected passed={expected_count}, failed=0, ignored=0\n{transcript}"
        )

    # Equal aggregate counts cannot prove that the original selection ran.
    completed_names = [
        match[1]
        for line in transcript.splitlines()
        if (match := _SUCCESSFUL_TEST.fullmatch(line)) is not None
    ]
    if (
        len(completed_names) != expected_count
        or len(set(completed_names)) != len(completed_names)
        or set(completed_names) != set(listed_names)
    ):
        raise ValueError(
            f"{evidence}: completed test names differ from original selection\n"
            f"listing:\n{listed}\nexecution:\n{transcript}"
        )

    return command, transcript, f"{evidence}=PASS"
