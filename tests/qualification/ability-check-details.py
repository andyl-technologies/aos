"""Checks that every native-ability qualification check has report metadata."""

import ast
import json
import pathlib
import sys


def check_details(path):
    module = ast.parse(pathlib.Path(path).read_text())
    def assignment(name):
        matches = [
            statement
            for statement in module.body
            if isinstance(statement, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == name
                for target in statement.targets
            )
        ]
        assert len(matches) == 1, (name, matches)
        values = ast.literal_eval(matches[0].value)
        assert isinstance(values, dict), (name, type(values))
        assert all(
            isinstance(check, str)
            and check
            and isinstance(detail, str)
            and detail
            for check, detail in values.items()
        ), (name, values)
        return values

    details = assignment("CHECK_DETAILS")
    generated = assignment("GENERATED_CHECK_DETAILS")
    prefixes = assignment("GENERATED_CHECK_PREFIX_DETAILS")
    assert not details.keys() & generated.keys()
    return details | generated, prefixes


contract = json.loads(pathlib.Path(sys.argv[1]).read_text())
details, detail_prefixes = check_details(sys.argv[2])
required = {
    check
    for requirement in contract["requirements"]
    if requirement["id"].startswith("ability-native-")
    for check in requirement["checks"]
}
missing = sorted(
    check
    for check in required - details.keys()
    if not any(check.startswith(prefix) for prefix in detail_prefixes)
)
assert not missing, f"native ability checks lack qualification report details: {missing}"
