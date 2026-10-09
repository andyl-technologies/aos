"""Checks an actual SELinux binary-policy decode against a kernel class map."""

from __future__ import annotations

import re
import sys
from pathlib import Path


TOKEN_PATTERN = re.compile(r'\s+|;[^\n]*|[()]|"(?:\\.|[^"\\])*"|[^\s();]+')


class CoverageError(Exception):
    """Reports malformed evidence or a failed policy-coverage requirement."""


def tokenize(source: str) -> list[str]:
    """Returns the meaningful tokens from one CIL source document."""
    tokens = []

    for match in TOKEN_PATTERN.finditer(source):
        token = match.group(0)
        if token.isspace() or token.startswith(";"):
            continue
        tokens.append(token)

    return tokens


def parse_cil(source: str) -> list[object]:
    """Parses the parenthesized subset used by a checkpolicy CIL decode."""
    tokens = tokenize(source)
    expressions = []
    position = 0

    def parse_expression() -> object:
        nonlocal position

        if position >= len(tokens):
            raise CoverageError("unexpected end of CIL input")

        token = tokens[position]
        position += 1

        if token == ")":
            raise CoverageError("unexpected ')' in CIL input")
        if token != "(":
            return token

        items = []
        while position < len(tokens) and tokens[position] != ")":
            items.append(parse_expression())

        if position >= len(tokens):
            raise CoverageError("unterminated CIL expression")

        position += 1
        return items

    while position < len(tokens):
        expressions.append(parse_expression())

    return expressions


def walk(expressions: list[object]):
    """Yields every list expression recursively in source order."""
    for expression in expressions:
        if not isinstance(expression, list):
            continue

        yield expression
        yield from walk(expression)


def atom_list(value: object, description: str) -> list[str]:
    """Returns a list whose members must all be atoms."""
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CoverageError(f"{description} is not an atom list")

    return value


def add_unique(mapping: dict[str, object], name: str, value: object, kind: str) -> None:
    """Adds one uniquely named declaration to a parsed mapping."""
    if name in mapping:
        raise CoverageError(f"duplicate {kind} declaration: {name}")

    mapping[name] = value


def policy_classes(expressions: list[object]) -> tuple[dict[str, list[str]], list[str]]:
    """Returns effective ordered class permissions and handleunknown values."""
    commons: dict[str, list[str]] = {}
    classes: dict[str, list[str]] = {}
    class_commons: dict[str, str] = {}
    handle_unknown = []

    for expression in walk(expressions):
        if not expression or not isinstance(expression[0], str):
            continue

        form = expression[0]
        if form in {"common", "class"} and len(expression) == 3:
            name = expression[1]
            if not isinstance(name, str):
                raise CoverageError(f"non-atom {form} name")

            permissions = atom_list(expression[2], f"{form} {name} permissions")
            target = commons if form == "common" else classes
            add_unique(target, name, permissions, form)
        elif form == "classcommon" and len(expression) == 3:
            class_name, common_name = expression[1:]
            if not isinstance(class_name, str) or not isinstance(common_name, str):
                raise CoverageError("non-atom classcommon name")
            add_unique(class_commons, class_name, common_name, "classcommon")
        elif form == "handleunknown" and len(expression) == 2:
            value = expression[1]
            if not isinstance(value, str):
                raise CoverageError("non-atom handleunknown value")
            handle_unknown.append(value)

    effective = {}
    for class_name, direct_permissions in classes.items():
        common_name = class_commons.get(class_name)
        common_permissions = []
        if common_name is not None:
            if common_name not in commons:
                raise CoverageError(
                    f"class {class_name} refers to missing common {common_name}"
                )
            common_permissions = commons[common_name]

        effective[class_name] = common_permissions + direct_permissions

    return effective, handle_unknown


def read_expected(path: Path) -> dict[str, list[str]]:
    """Reads ordered class and permission rows emitted from the kernel source."""
    expected = {}

    for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
        fields = raw_line.split("\t")
        if len(fields) < 2 or not all(fields):
            raise CoverageError(f"malformed kernel class-map row {line_number}")

        class_name, *permissions = fields
        if len(permissions) != len(set(permissions)):
            raise CoverageError(f"duplicate kernel permission in class {class_name}")
        add_unique(expected, class_name, permissions, "kernel class")

    if not expected:
        raise CoverageError("kernel class map is empty")

    return expected


def write_observed(path: Path, observed: dict[str, list[str]]) -> None:
    """Writes all effective policy class permissions as ordered TSV evidence."""
    rows = ["\t".join([class_name, *permissions]) for class_name, permissions in observed.items()]
    path.write_text("\n".join(rows) + "\n")


def check_policy(expected_path: Path, cil_path: Path, observed_path: Path) -> None:
    """Checks ordered kernel sequences and reject-unknown in a binary decode."""
    expected = read_expected(expected_path)
    expressions = parse_cil(cil_path.read_text())
    observed, handle_unknown = policy_classes(expressions)

    write_observed(observed_path, observed)

    if handle_unknown != ["reject"]:
        raise CoverageError(
            f"expected exactly '(handleunknown reject)', observed {handle_unknown!r}"
        )

    for class_name, expected_permissions in expected.items():
        if class_name not in observed:
            raise CoverageError(f"missing kernel class: {class_name}")

        observed_permissions = observed[class_name]
        observed_prefix = observed_permissions[: len(expected_permissions)]
        if observed_prefix != expected_permissions:
            raise CoverageError(
                f"ordered permissions differ for {class_name}: "
                f"expected {expected_permissions!r}, observed {observed_permissions!r}"
            )


def render(expression: object) -> str:
    """Renders parsed CIL without changing atoms or expression order."""
    if isinstance(expression, str):
        return expression
    if isinstance(expression, list):
        return "(" + " ".join(render(item) for item in expression) + ")"

    raise CoverageError("cannot render an unknown CIL node")


def remove_permission(
    input_path: Path,
    output_path: Path,
    class_name: str,
    permission_name: str,
) -> None:
    """Creates one deliberately deficient CIL document for a negative gate."""
    expressions = parse_cil(input_path.read_text())
    removals = 0

    for expression in walk(expressions):
        if len(expression) != 3 or expression[:2] != ["class", class_name]:
            continue

        permissions = atom_list(expression[2], f"class {class_name} permissions")
        if permission_name in permissions:
            permissions.remove(permission_name)
            removals += 1

    if removals != 1:
        raise CoverageError(
            f"expected one {class_name}.{permission_name} declaration, removed {removals}"
        )

    output_path.write_text("\n".join(render(expression) for expression in expressions) + "\n")


def main(arguments: list[str]) -> int:
    """Runs the selected coverage or fixture command."""
    try:
        if len(arguments) == 5 and arguments[1] == "check":
            check_policy(Path(arguments[2]), Path(arguments[3]), Path(arguments[4]))
        elif len(arguments) == 6 and arguments[1] == "remove":
            remove_permission(
                Path(arguments[2]),
                Path(arguments[3]),
                arguments[4],
                arguments[5],
            )
        else:
            raise CoverageError(
                "usage: coverage.py check EXPECTED CIL OBSERVED | "
                "coverage.py remove INPUT OUTPUT CLASS PERMISSION"
            )
    except (CoverageError, OSError) as error:
        print(f"SELinux policy coverage: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
