"""Exercises role/config syntax and fail-closed T0 dispatch through the binary."""

import pathlib
import subprocess
import sys
import tempfile


def invoke(binary, *arguments):
    return subprocess.run([binary, *arguments], capture_output=True, text=True, check=False)


def main():
    binary = sys.argv[1]
    help_result = invoke(binary, "--help")
    assert help_result.returncode == 0, help_result.stderr
    assert "--check-config" in help_result.stdout
    assert "--role" in help_result.stdout

    with tempfile.TemporaryDirectory() as directory:
        config = pathlib.Path(directory) / "config.toml"
        for role in ["serve", "realize", "fuse-worker", "publish", "gc", "job"]:
            config.write_text(f'role = "{role}"\nstore = "bucket(file:///tmp/store)"\n')
            result = invoke(binary, "--config", str(config), "--check-config")
            assert result.returncode == 0, (role, result.stderr)
            assert role in result.stdout and "syntax" in result.stdout
            result = invoke(binary, "--role", role, "--config", str(config), "--check-config")
            assert result.returncode == 0, (role, result.stderr)
            other_role = "gc" if role == "serve" else "serve"
            result = invoke(binary, "--role", other_role, "--config", str(config), "--check-config")
            assert result.returncode != 0 and "differs" in result.stderr

            result = invoke(binary, "--config", str(config))
            assert result.returncode != 0, f"unimplemented role falsely succeeded: {role}"
            assert role in result.stderr and "unavailable" in result.stderr

        for text in [
            'role = "unknown"\nstore = "disk(/tmp)"',
            'role = "serve"\nstore = "unknown(/tmp)"',
            'role = "serve"\nstore = "disk(/tmp)"\nunknown = true',
            'role = "serve"\nstore = "disk(/tmp)"\n[[expose]]\nid = "test"\nview = "refs/heads/main"\nsurface = "fuse"\nat = "/tmp/view"\ntoken = "file:/tmp/token"',
            'role = "serve"\nstore = "disk(/tmp)"\n[[expose]]\nsurface = "browse"',
        ]:
            config.write_text(text)
            result = invoke(binary, "--config", str(config), "--check-config")
            assert result.returncode != 0, f"invalid configuration accepted: {text}"
        config.write_text('role = "realize"\nstore = "disk(/tmp)"\n[[expose]]\nid = "test"\nview = "refs/heads/main"\nsurface = "fuse"\nat = "/tmp/view"\ntoken = "file:/tmp/token"')
        result = invoke(binary, "--config", str(config), "--check-config")
        assert "fuse" in result.stderr and "unavailable" in result.stderr

    print("role-selection: configuration and unavailable runtime behavior passes")


if __name__ == "__main__":
    main()
