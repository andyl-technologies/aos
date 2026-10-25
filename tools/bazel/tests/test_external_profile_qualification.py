"""Registers external compiler-unit rejection tests in the policy suite."""

from pathlib import Path
import sys
from unittest.mock import patch


qualification = Path(__file__).resolve().parents[1] / "qualification"
with patch.object(sys, "path", [str(qualification), *sys.path]):
    from test_rust_external_profiles import RustExternalProfileTests
