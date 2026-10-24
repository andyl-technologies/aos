"""Interprets the pinned rules_rust process wrapper's indirect compiler inputs.

Callers supply already verified input text and explicit execution-root identities.
This model reconstructs arguments and environment; it does not infer rustc defaults
or claim that two compiler configurations are semantically equivalent.
"""


SINGLE_FLAGS = {
    "--stable-status-file", "--volatile-status-file", "--out-dir", "--touch-file",
    "--stdout-file", "--stderr-file", "--output-file", "--rustc-quit-on-rmeta",
    "--rustc-output-format", "--require-explicit-unstable-features",
}
REPEATED_FLAGS = {"--subst", "--env-file", "--arg-file", "--copy-output"}


def wrapper_options(command):
    """Parses separate flag/value groups, preserving repeated values in order."""
    if command.count("--") != 1:
        raise ValueError("unsupported Rust wrapper compiler boundary")
    boundary = command.index("--")
    prefix = command[1:boundary]
    options = {}
    index = 0
    while index < len(prefix):
        flag = prefix[index]
        index += 1
        if flag not in SINGLE_FLAGS | REPEATED_FLAGS:
            raise ValueError("unsupported Rust wrapper flag: " + flag)
        values = []
        while index < len(prefix) and not prefix[index].startswith("--"):
            values.append(prefix[index])
            index += 1
        if not values or (flag in SINGLE_FLAGS and (len(values) != 1 or flag in options)):
            raise ValueError("missing or repeated scalar Rust wrapper value: " + flag)
        options.setdefault(flag, []).extend(values)
    child = command[boundary + 1:]
    if not child:
        raise ValueError("missing Rust wrapper child command")
    return options, child


def logical_lines(text):
    """Matches BufRead::lines and the wrapper's trailing-backslash continuation."""
    result = []
    continued = ""
    lines = text.split("\n")
    for index, line in enumerate(lines):
        # Rust strips CR only when it precedes a consumed LF. Other Unicode
        # line separators, whitespace, and a final bare CR remain literal.
        if index < len(lines) - 1 and line.endswith("\r"):
            line = line[:-1]
        if not line:
            continue
        stripped = line.rstrip("\\")
        count = len(line) - len(stripped)
        continued += stripped + "\\" * (count // 2)
        if count % 2:
            continued += "\n"
        else:
            result.append(continued)
            continued = ""
    # The pinned wrapper discards an unterminated continuation at EOF.
    return result


def expand_wrapper(command, environment, files, roots):
    """Reconstructs compiler inputs from verified text and explicit path roots.

    Response files in the supplied command must already be expanded and bound
    to execution digests. Nested response files introduced by indirect inputs
    are rejected because their contents have not been retained here.
    """
    options, child = wrapper_options(command)

    def lines(path):
        if path not in files:
            raise ValueError("missing retained Rust wrapper input: " + path)
        return logical_lines(files[path])

    substitutions = []
    for declaration in options.get("--subst", []):
        key, separator, value = declaration.partition("=")
        if not separator:
            raise ValueError("invalid Rust wrapper substitution")
        if value in {"${pwd}", "${output_base}", "${exec_root}"}:
            root = value[2:-1]
            if root not in roots:
                raise ValueError("missing explicit Rust wrapper path root: " + root)
            value = roots[root]
        substitutions.append((key, value))
    out_dir = options.get("--out-dir", [None])[0]
    if out_dir is not None:
        substitutions.append(("out_dir", out_dir))

    child_environment = dict(environment)
    for path in options.get("--env-file", []):
        for line in lines(path):
            key, separator, value = line.partition("=")
            if not separator:
                raise ValueError("invalid Rust wrapper environment line")
            child_environment[key] = value
    if out_dir is not None:
        child_environment["OUT_DIR"] = "${pwd}/" + out_dir

    for flag in ["--stable-status-file", "--volatile-status-file"]:
        for path in options.get(flag, []):
            for line in lines(path):
                key, separator, value = line.partition(" ")
                if not separator:
                    raise ValueError("invalid Rust wrapper status line")
                child_environment = {
                    name: contents.replace("{" + key + "}", value)
                    for name, contents in child_environment.items()
                }

    arguments = list(child)
    for path in options.get("--arg-file", []):
        arguments.extend(lines(path))

    for key, replacement in substitutions:
        token = "${" + key + "}"
        arguments = [argument.replace(token, replacement) for argument in arguments]
        child_environment = {
            name: value.replace(token, replacement) for name, value in child_environment.items()
        }
    if any(argument.startswith("@") for argument in arguments):
        raise ValueError("indirect nested response file requires its own retained evidence")
    if options.get("--require-explicit-unstable-features") == ["true"]:
        if not any(argument.startswith(("-Zallow-features=", "allow-features=")) for argument in arguments):
            arguments.append("-Zallow-features=")

    return {"arguments": arguments, "environment": child_environment}
