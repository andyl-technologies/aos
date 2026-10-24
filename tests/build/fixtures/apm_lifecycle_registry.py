"""Creates signed native package registries for CLI lifecycle integration tests."""

import argparse
import base64
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess


def run(binary, environment, *arguments):
    result = subprocess.run(
        [str(binary), *map(str, arguments)],
        env=environment,
        text=True,
        capture_output=True,
    )
    if result.returncode:
        raise RuntimeError(
            f"{Path(binary).name} {' '.join(map(str, arguments))} failed:\n"
            + result.stdout
            + result.stderr
        )
    return result.stdout + result.stderr


def home_environment(environment, home):
    return environment | {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "APM_SYSTEM_CONFIG_DIR": str(home / "etc-apm"),
    }


def package_metadata(name, packages, platform="x86_64-linux"):
    text = (
        f'[package]\nname = "{name}"\ndescription = "{name} lifecycle fixture"\n'
        'license = "MIT"\nmaintainer = "registry@example.com"\n'
    )
    for package in packages:
        text += (
            "\n[[versions]]\nversion = "
            + json.dumps(package["version"])
            + f"\n[versions.platforms.{platform}]\n"
        )
        for field in ["store_path", "nar_hash", "nar_size", "version_requirement"]:
            text += field + " = " + json.dumps(package[field]) + "\n"
        text += (
            'requires-features = ["native-package-modules-v1"]\n'
            "references = { hashes = "
            + json.dumps(package["references"])
            + ', requires-features = ["native-package-modules-v1"] }\n'
            'closure_size = 1\nsource_drv = ""\nsource_nar_hash = ""\n'
            f"[versions.platforms.{platform}.deployment]\n"
        )
        for field, value in package["deployment"].items():
            text += field + " = " + json.dumps(value) + "\n"
    return text


def publish(root, fixture, environment, apr, *, upgrade):
    maintainer = root / "maintainer"
    producer = home_environment(environment, maintainer)
    key = maintainer / ".config/apm/keys/lifecycle-initial.key"
    registry = maintainer / ".local/share/apm/registries/lifecycle"
    packages = fixture["packages"]

    if not upgrade:
        key_output = run(apr, producer, "keys", "generate", "initial", "--registry", "lifecycle")
        public = next(
            line.split()[-1]
            for line in key_output.splitlines()
            if line.split() and line.split()[-1].startswith("lifecycle:Ed25519:")
        )
        (root / "public-key").write_text(public)
        run(apr, producer, "create", "lifecycle", "--trust-key", public, "--key", key)

    groups = {
        "alpha": [packages["alpha_v1"]] + ([packages["alpha_v2"]] if upgrade else []),
        "beta": [packages["beta" if (root / "with-dependencies").exists() else "beta_without_helper"]],
        "beta-helper": [packages["beta_helper"]],
    }
    for name, versions in groups.items():
        directory = registry / "packages" / name[0]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / (name + ".toml")).write_text(package_metadata(name, versions, fixture["platform"]))

    for entry in fixture["store_graph"]:
        digest = Path(entry["path"]).name.split("-", 1)[0]
        directory = registry / "store" / digest[:2]
        directory.mkdir(parents=True, exist_ok=True)
        nar = entry["narHash"]
        if nar.startswith("sha256-"):
            nar = "sha256:" + base64.b64decode(nar[7:]).hex()
        text = f"nar:{nar}:{entry['narSize']}\n"
        for reference in entry["references"]:
            text += "\tia:sha256:" + Path(reference).name.split("-", 1)[0] + "\n"
        (directory / digest).write_text(text)

    run(
        apr, producer, "commit", "packages", "store", "--registry", "lifecycle",
        "--key", key, "--message", "publish lifecycle fixtures",
    )
    # Admission validates published NAR metadata even for already imported paths.
    # One compression worker also makes this small fixture cheap to repeat.
    cache = maintainer / "cache"
    run(
        apr, producer, "cache", "generate", "--registry", "lifecycle",
        "--registry-key", key, "--output", cache, "--cache-url", cache.as_uri(),
        "--jobs", "1",
    )
    run(
        apr, producer, "release", "2.0.0" if upgrade else "1.0.0",
        "--registry", "lifecycle", "--key", key,
    )
    return registry


def initialize(arguments, fixture):
    root = arguments.root.resolve()
    private_nix = root / "private-nix"
    store = private_nix / "nix/store"
    store.mkdir(parents=True)
    if arguments.with_dependencies:
        (root / "with-dependencies").touch()
    for entry in fixture["store_graph"]:
        source = Path(entry["path"])
        destination = store / source.name
        if source.is_dir():
            shutil.copytree(source, destination, symlinks=True)
        else:
            shutil.copy2(source, destination)

    environment = home_environment(dict(os.environ), root / "consumer") | {
        "USER": "apmtest",
        "LOGNAME": "apmtest",
        "GIT_AUTHOR_NAME": "Lifecycle Test",
        "GIT_AUTHOR_EMAIL": "registry@example.com",
        "GIT_COMMITTER_NAME": "Lifecycle Test",
        "GIT_COMMITTER_EMAIL": "registry@example.com",
        "AOS_PROFILE_ROOT": str(root / "profiles"),
        "AOS_NIX_EVAL_STORE": f"local?root={private_nix}",
        "NIX_REMOTE": f"local?root={private_nix}",
        "NIX_STORE_DIR": "/nix/store",
        "NIX_STATE_DIR": str(private_nix / "nix/var/nix"),
        "NIX_LOG_DIR": str(private_nix / "nix/var/log/nix"),
        "NIX_CONFIG": "experimental-features = nix-command flakes\n",
        "AOS_PACKAGE_MODULE_LIBRARY": fixture["module_library"],
        "AOS_PACKAGE_RUNTIME": str(arguments.runtime.resolve()),
    }
    for suffix in ["REMOTE", "STORE_DIR", "STATE_DIR", "LOG_DIR"]:
        environment["AOS_TEST_ABILITY_NIX_" + suffix] = environment["NIX_" + suffix]
    with (arguments.fixtures.parent / "registration").open("rb") as registration:
        subprocess.run(
            [environment["AOS_NIX_STORE"], "--load-db"],
            env=environment, stdin=registration, check=True,
        )

    # Forward every operation to real Nix, including its temporary-root protocol.
    # The log lets the upgrade test assert that validity was actually checked.
    tools = root / "tools"
    tools.mkdir()
    shell = shutil.which("bash", path=environment["PATH"])
    if shell is None:
        raise ValueError("AOS-built bash is required")
    wrapper = tools / "nix-store"
    log = root / "nix-store-calls.log"
    wrapper.write_text(
        f"#!{shell}\n"
        + "printf '%s\\n' \"$*\" >> " + shlex.quote(str(log)) + "\n"
        + "exec " + shlex.quote(environment["AOS_NIX_STORE"]) + ' "$@"\n'
    )
    wrapper.chmod(0o755)
    environment["PATH"] = str(tools) + os.pathsep + environment["PATH"]
    (root / "environment.json").write_text(json.dumps(environment, indent=2))

    registry = publish(root, fixture, environment, arguments.apr, upgrade=False)
    run(
        arguments.apm, environment, "--json", "registry", "add", registry.as_uri(),
        "--trust-key", (root / "public-key").read_text(), "--version", "*",
        "--name", "lifecycle",
    )



def initialize_cache(arguments, fixture):
    """Loads genuine producer paths and leaves package payloads absent in the consumer."""
    root = arguments.root.resolve()
    packages = fixture["packages"]
    excluded = {package[field] for package in packages.values() for field in ["store_path", "envelope"]}
    entries = {entry["path"]: entry for entry in fixture["store_graph"]}
    key = root / "cache-signing-key"
    public = root / "cache-public-key"
    subprocess.run(
        [os.environ["AOS_NIX_STORE"], "--generate-binary-cache-key", "native-cli-cache", str(key), str(public)],
        check=True,
    )

    def closure(roots):
        result = set()
        pending = list(roots)
        while pending:
            path = pending.pop()
            if path not in result:
                result.add(path)
                pending.extend(entries[path]["references"])
        return result

    for role in ["producer", "consumer"]:
        directory = root / (role + "-aos-root")
        private = directory / "private-nix"
        store = private / "nix/store"
        store.mkdir(parents=True)
        selected = set(entries) if role == "producer" else set(entries) - excluded
        for path in sorted(selected):
            source = Path(path)
            destination = store / source.name
            if source.is_dir():
                shutil.copytree(source, destination, symlinks=True)
            else:
                shutil.copy2(source, destination)
        environment = {
            "NIX_REMOTE": f"local?root={private}",
            "NIX_STORE_DIR": "/nix/store",
            "NIX_STATE_DIR": str(private / "nix/var/nix"),
            "NIX_LOG_DIR": str(private / "nix/var/log/nix"),
            "NIX_CONFIG": "experimental-features = nix-command flakes\nrequire-sigs = true\ntrusted-public-keys = " + public.read_text().strip() + "\n",
            "AOS_NIX_EVAL_STORE": f"local?root={private}",
            "AOS_NIX_STORE_DIR": "/nix/store",
            "AOS_PACKAGE_MODULE_LIBRARY": fixture["module_library"],
            "AOS_PACKAGE_RUNTIME": str(arguments.runtime.resolve()),
        }
        for suffix in ["REMOTE", "STORE_DIR", "STATE_DIR", "LOG_DIR"]:
            environment["AOS_TEST_ABILITY_NIX_" + suffix] = environment["NIX_" + suffix]
        registration = ""
        for path in sorted(selected):
            entry = entries[path]
            references = entry["references"]
            registration += f"{path}\n{entry['narHash']}\n{entry['narSize']}\n\n{len(references)}\n" + "".join(reference + "\n" for reference in references)
        subprocess.run(
            [os.environ["AOS_NIX_STORE"], "--load-db"],
            input=registration, text=True, env=dict(os.environ) | environment, check=True,
        )
        (directory / "native-environment.json").write_text(json.dumps(environment))

    first = packages["tool_v1"]
    second = packages["tool_v2"]
    first_closure = closure([first["store_path"], first["envelope"], packages["helper_v1"]["envelope"]])
    second_closure = closure([second["store_path"], second["envelope"], packages["helper_v2"]["envelope"]])
    for version, selected in [("v1", first_closure), ("v2", first_closure | second_closure)]:
        for path in sorted(selected):
            entry = entries[path]
            digest = Path(path).name.split("-", 1)[0]
            directory = root / ("store-" + version) / digest[:2]
            directory.mkdir(parents=True, exist_ok=True)
            nar = entry["narHash"]
            if nar.startswith("sha256-"):
                nar = "sha256:" + base64.b64decode(nar[7:]).hex()
            text = f"nar:{nar}:{entry['narSize']}\n"
            for reference in entry["references"]:
                text += "\tia:sha256:" + Path(reference).name.split("-", 1)[0] + "\n"
            (directory / digest).write_text(text)

    (root / "native-cache.json").write_text(json.dumps({
        "packages": packages,
        "initial_downloads": len(first_closure & excluded),
        "upgrade_downloads": len((second_closure - first_closure) & excluded),
        "cache_entries_v1": len(first_closure),
        "cache_entries_payload_v1": len(closure([first["store_path"]])),
    }))
    (root / "helper-v1.toml").write_text(package_metadata("fixture-helper", [packages["helper_v1"]], fixture["platform"]))
    (root / "helper-v2.toml").write_text(package_metadata("fixture-helper", [packages["helper_v1"], packages["helper_v2"]], fixture["platform"]))
    (root / "package-v1.toml").write_text(package_metadata("fixture-tool", [first], fixture["platform"]))
    (root / "package-v2.toml").write_text(package_metadata("fixture-tool", [first, second], fixture["platform"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["initialize", "publish-upgrade", "initialize-cache"])
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--apr", type=Path, required=True)
    parser.add_argument("--apm", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--with-dependencies", action="store_true")
    arguments = parser.parse_args()
    fixture = json.loads(arguments.fixtures.read_text())
    if arguments.operation == "initialize-cache":
        initialize_cache(arguments, fixture)
    elif arguments.operation == "initialize":
        initialize(arguments, fixture)
    else:
        environment = json.loads((arguments.root / "environment.json").read_text())
        publish(arguments.root, fixture, environment, arguments.apr, upgrade=True)
        run(arguments.apm, environment, "--json", "update", "--registry", "lifecycle")


if __name__ == "__main__":
    main()
