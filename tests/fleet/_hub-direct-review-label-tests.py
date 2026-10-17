"""Exercise actual called review labels through the unchanged private channel."""

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest


SOURCE_ROOT = Path(__file__).parent
RUN = "a" * 32


def called_labels():
    selections = (
        ("_hub-external-oci-window.py", "run_external_oci_pair_window",
            "-reviewer", "external-mirror-" + RUN + "-initial-reviewer"),
        ("_hub-external-oci-window.py", "run_external_oci_business_lane",
            "-destination-inputs", "external-oci-" + RUN + "-destination-provider-inputs"),
        ("_hub-external-oci-direct.py", "_qualify_paired_external_oci_direct",
            "-copy-authorization", "external-oci-" + RUN + "-copy-preflight-authorization"),
    )
    result = []
    for filename, function, suffix, original in selections:
        tree = ast.parse((SOURCE_ROOT / filename).read_bytes())
        definitions = [node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == function]
        if len(definitions) != 1:
            raise AssertionError("selected actual caller definition differs")
        calls = [node for node in ast.walk(definitions[0]) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "await_direct_review"
            and isinstance(node.args[0], ast.BinOp)
            and isinstance(node.args[0].right, ast.Constant)
            and node.args[0].right.value == suffix]
        if len(calls) != 1:
            raise AssertionError("selected actual caller suffix differs")
        expression = ast.Expression(calls[0].args[0])
        label = eval(compile(expression, filename, "eval"), {"__builtins__": {}},
            {"run": RUN, "label": "external-oci-" + RUN})
        result.append((label, original))
    return result


class ReviewLabelTests(unittest.TestCase):
    def test_actual_called_labels_write_request_then_remain_pending(self):
        spec = importlib.util.spec_from_file_location("selected_review", SOURCE_ROOT / "_hub-direct-review.py")
        review = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(review)
        previous = Path.cwd()

        with tempfile.TemporaryDirectory(prefix="aos-review-label-controlled-") as directory:
            os.chmod(directory, 0o700)
            os.chdir(directory)
            try:
                for label, original in called_labels():
                    self.assertIn(RUN, label)
                    self.assertLessEqual(len(label), 64)
                    with self.assertRaisesRegex(ValueError, "invalid independent review checkpoint label"):
                        review.await_direct_review(original, {"actualControlledObservation": "b" * 64},
                            {"controlledSelectedInput"}, timeout=0)
                    self.assertFalse((Path("independent-direct-review") / (original + ".request.json")).exists())

                    with self.assertRaisesRegex(RuntimeError, "review remains pending"):
                        review.await_direct_review(label, {"actualControlledObservation": "b" * 64},
                            {"controlledSelectedInput"}, timeout=0)
                    request = Path("independent-direct-review") / (label + ".request.json")
                    metadata = request.stat()
                    self.assertEqual(metadata.st_uid, os.geteuid())
                    self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                    raw = request.read_bytes()
                    self.assertEqual(json.loads(raw), {"version": 1, "checkpoint": label,
                        "observationHashes": {"actualControlledObservation": "b" * 64},
                        "selectionFields": ["controlledSelectedInput"],
                        "scope": "independent operator selection only; no automatic runtime acceptance"})
                    self.assertEqual(len(hashlib.sha256(raw).hexdigest()), 64)
                    self.assertFalse(request.with_name(label + ".selected.json").exists())
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
