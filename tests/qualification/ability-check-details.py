"""Checks that every native-ability qualification check has report metadata."""

import ast
import json
import pathlib
import sys


def check_details(path):
    module = ast.parse(pathlib.Path(path).read_text())
    assignments = [
        statement
        for statement in module.body
        if isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "CHECK_DETAILS"
            for target in statement.targets
        )
    ]
    assert len(assignments) == 1, assignments
    details = ast.literal_eval(assignments[0].value)
    assert isinstance(details, dict), type(details)
    assert all(
        isinstance(check, str)
        and check
        and isinstance(detail, str)
        and detail
        for check, detail in details.items()
    ), details
    return details


contract = json.loads(pathlib.Path(sys.argv[1]).read_text())
details = check_details(sys.argv[2])
required = {
    check
    for requirement in contract["requirements"]
    if requirement["id"].startswith("ability-native-")
    for check in requirement["checks"]
}
missing = sorted(required - details.keys())
assert not missing, f"native ability checks lack qualification report details: {missing}"
