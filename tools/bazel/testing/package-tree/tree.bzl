"""Generates a nested tree to exercise the complete package export boundary."""

def _tree_impl(ctx):
    tree = ctx.actions.declare_directory(ctx.label.name)
    script = """from pathlib import Path
import sys
root = Path(sys.argv[1])
(root / 'nested').mkdir(parents=True)
(root / 'nested/payload.txt').write_bytes(b'generated asset\\n')
(root / 'version').write_bytes(b'1\\n')
"""
    ctx.actions.run(
        executable = ctx.file._python,
        arguments = ["-c", script, tree.path],
        inputs = [ctx.file._closure],
        outputs = [tree],
        env = {"LANG": "C", "LC_ALL": "C"},
        mnemonic = "AosPackageFixtureTree",
    )
    return [DefaultInfo(files = depset([tree]))]

fixture_tree = rule(
    implementation = _tree_impl,
    attrs = {
        "_python": attr.label(default = "@aos_tools//:python", allow_single_file = True, cfg = "exec"),
        "_closure": attr.label(default = "@aos_tools//:closure.json", allow_single_file = True, cfg = "exec"),
    },
)
