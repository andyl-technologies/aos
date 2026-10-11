"""Exercise the selected publisher environments without publication effects."""

import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


HERE = Path(__file__).parent
GIT = "/nix/store/lbn32cswqbj9byj71m0ww09gq5lz3p80-git-minimal-2.55.0/bin/git"


def source_module(leaf):
    specification = importlib.util.spec_from_file_location("publisher_environment", HERE / leaf)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def retained_guest(leaf, function, variable=None):
    tree = ast.parse((HERE / leaf).read_text())
    selected = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function)
    for node in ast.walk(selected):
        if variable is None and isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "direct_guest_python":
            return textwrap.dedent(node.args[2].value)
        if variable is not None and isinstance(node, ast.Assign) \
                and any(isinstance(target, ast.Name) and target.id == variable for target in node.targets):
            return textwrap.dedent(node.value.args[0].value)
    raise AssertionError("Selected guest source is absent")


def actual_environment(program, root):
    compile(program, "publisher-guest", "exec")
    nodes = ast.parse(program).body
    start = next(index for index, node in enumerate(nodes) if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "environment" for target in node.targets))
    context = {"os": os, "home": root,
               "selected": {"home": str(root), "publisherHome": str(root)}}
    # Execute the actual copied-environment and update statements, before any
    # subprocess or filesystem effect in the guest program.
    exec(compile(ast.Module(body=nodes[start:start + 2], type_ignores=[]), "publisher-environment", "exec"), context)
    return context["environment"]


class PublisherEnvironmentTests(unittest.TestCase):
    def prepared_program(self):
        module = source_module("_hub-direct-publisher.py")
        commands = []
        def capture(client, command, **unused):
            commands.append(command)
            return json.dumps({"trustKey": "external-direct:Ed25519:controlled"})
        module.private_guest_command = capture
        module.prepare_direct_signed_surface(object(), "selected-python", "selected-apr", GIT,
            "selected-ssh", "selected-nix", "selected-helper", "https://localhost/registry",
            publication_project="selected-project")
        return commands[0].split("<<'DIRECT_SIGNED_SURFACE'\n", 1)[1].rsplit("DIRECT_SIGNED_SURFACE", 1)[0]

    def test_apr_initial_identity_is_command_scoped_and_home_is_inherited(self):
        with tempfile.TemporaryDirectory(prefix="aos-publisher-environment-") as temporary:
            root = Path(temporary)
            program = self.prepared_program()
            environment = actual_environment(program, root)
            result = subprocess.run([GIT, "var", "GIT_AUTHOR_IDENT"], env=environment,
                stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=10)

            self.assertTrue(result.stdout.startswith(b"Hybrid Fleet Publisher <fleet-publisher@example.test> "))
            self.assertEqual(environment.get("HOME"), os.environ.get("HOME"))
            self.assertEqual(environment["XDG_CONFIG_HOME"], str(root / ".config"))
            self.assertEqual(environment["XDG_DATA_HOME"], str(root / ".local/share"))
            self.assertNotIn("'--global'", program)
            self.assertIn("'--local'", program)

    def test_fifo_and_supervisor_select_the_same_private_state_without_home_override(self):
        programs = [retained_guest("_hub-direct-publisher.py", "assert_direct_fifo_checkpoint"),
                    retained_guest("_hub-direct-concurrent-publications.py", "start_direct_publication", "supervisor")]
        with tempfile.TemporaryDirectory(prefix="aos-publisher-environment-") as temporary:
            root = Path(temporary)
            environments = [actual_environment(program, root) for program in programs]

            for environment in environments:
                self.assertEqual(environment.get("HOME"), os.environ.get("HOME"))
                self.assertEqual(environment["XDG_CONFIG_HOME"], str(root / ".config"))
                self.assertEqual(environment["XDG_DATA_HOME"], str(root / ".local/share"))
                self.assertEqual(environment["XDG_CACHE_HOME"], str(root / ".cache"))
            self.assertEqual(environments[0], environments[1])

    def test_publication_scoped_roots_cannot_leak_between_invocations(self):
        program = retained_guest("_hub-direct-concurrent-publications.py", "start_direct_publication", "supervisor")
        original = dict(os.environ)
        first = actual_environment(program, Path("/var/lib/hybrid-client/publisher-a"))
        second = actual_environment(program, Path("/var/lib/hybrid-client/publisher-b"))

        self.assertEqual(dict(os.environ), original)
        for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"):
            self.assertNotEqual(first[key], second[key])
        self.assertEqual(first.get("HOME"), second.get("HOME"))


if __name__ == "__main__":
    unittest.main()
