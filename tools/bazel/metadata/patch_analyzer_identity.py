"""Preserves configured external compilation units in the pinned analyzer aspect."""

import argparse
from pathlib import Path


def patch(source):
    """Keeps first-party libtest merging and distinguishes external outputs."""
    original = '    return "ID-" + crate_info.root.path\n'
    replacement = '''    # An external source can compile in target and execution configurations,
    # with different features, generated files, or compiler environment. The
    # output identifies that configured unit on both ends of dependency edges.
    if crate_info.root.path.startswith("external/"):
        return "ID-" + crate_info.root.path + "#" + crate_info.output.path
    return "ID-" + crate_info.root.path
'''
    if source.count(original) != 1:
        raise ValueError("rules_rust analyzer compilation identity patch no longer applies")
    return source.replace(original, replacement)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    options = parser.parse_args()
    options.source.write_text(patch(options.source.read_text()))
