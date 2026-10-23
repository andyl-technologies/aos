"""Resolves crate specifications explicitly and retains source-only build inputs.

Ordinary Bazel builds never execute this tool. Cargo is used only to resolve
and inspect third-party sources; the generated compilation rules invoke rustc.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
from urllib.parse import urlparse


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def crate_repository(repository, name, version):
    """Matches the pinned crate_universe renderer's repository-name spelling."""
    return f"{repository}__{name}-{version}".replace("+", "-")


def run(command, environment):
    subprocess.run([str(argument) for argument in command], env=environment, check=True)


def resolve(specification, tools, scratch, seed_lock):
    """Uses a private Cargo home and the source-built crate_universe generator."""
    repository = "aos_" + specification["family"].replace("-", "_") + "_crates"
    config = {
        "generate_binaries": False,
        "generate_build_scripts": True,
        "annotations": specification["annotations"],
        "supported_platform_triples": specification["platforms"],
        "rendering": {
            "repository_name": repository,
            "regen_command": "aos-dev bazel update-deps " + specification["family"],
            "generate_cargo_toml_env_vars": True,
            "generate_rules_license_metadata": False,
            "generate_target_compatible_with": True,
            "incompatible_no_root_alias_targets": False,
        },
    }
    write_json(scratch / "config.json", config)
    write_json(scratch / "splicing.json", {
        "cargo_config": None,
        "direct_packages": specification["packages"],
        "manifests": {},
        "resolver_version": "2",
    })
    for name in ["cargo-home", "tmp"]:
        (scratch / name).mkdir()
    environment = {
        "PATH": tools["path"],
        "HOME": str(scratch),
        "CARGO_HOME": str(scratch / "cargo-home"),
        "TMPDIR": str(scratch / "tmp"),
        "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
    }
    for name in ["SSL_CERT_FILE", "SSL_CERT_DIR", "CARGO_HTTP_CAINFO", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"]:
        if name in os.environ:
            environment[name] = os.environ[name]
    common = [
        "--config", scratch / "config.json",
        "--splicing-manifest", scratch / "splicing.json",
        "--cargo", tools["cargo"], "--rustc", tools["rustc"],
        "--nonhermetic-root-bazel-workspace-dir", scratch / "workspace",
    ]
    splice = [tools["generator"], "splice", *common,
              "--workspace-dir", scratch / "workspace", "--output-dir", scratch / "spliced",
              "--repository-name", repository]
    if seed_lock:
        shutil.copyfile(seed_lock, scratch / "seed.lock")
        splice.extend(["--cargo-lockfile", scratch / "seed.lock"])
    run(splice, environment)
    run([tools["generator"], "generate", *common, "--repin",
         "--metadata", scratch / "spliced/metadata.json",
         "--cargo-lockfile", scratch / "spliced/Cargo.lock",
         "--lockfile", scratch / "context.json", "--repository-dir", scratch / "rendered",
         "--paths-to-track", scratch / "paths.json",
         "--warnings-output-path", scratch / "warnings.json",
         "--hub-packages-output-path", scratch / "hub-packages.json"], environment)
    return repository


def validate_license(specification, crate):
    """Requires an explicit license review before admitting shared boundary inputs."""
    if crate["license"] in specification.get("host_only_licenses", []):
        return "apache-host"
    identity = f"{crate['name']}@{crate['version']}"
    domain = ("permissive-protocol" if identity in specification.get("permissive_crates", [])
              else specification["license_domain"])
    if (domain == "permissive-protocol"
            and crate["license"] not in specification.get("approved_licenses", [])):
        raise ValueError(
            f"unreviewed protocol dependency license: {crate['name']}-{crate['version']}: "
            + crate["license"]
        )
    return domain


def rendered_features(node):
    """Reads the pinned renderer's literal or platform-selected feature form."""
    if isinstance(node, ast.List):
        return {"common": ast.literal_eval(node), "selects": {}}
    if (not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add)
            or not isinstance(node.left, ast.List) or not isinstance(node.right, ast.Call)
            or not isinstance(node.right.func, ast.Name) or node.right.func.id != "select"
            or len(node.right.args) != 1 or node.right.keywords):
        raise ValueError("unsupported reviewed feature expression")
    selections = ast.literal_eval(node.right.args[0])
    if selections.pop("//conditions:default", None) != []:
        raise ValueError("reviewed feature select requires an empty default")
    prefix = "@rules_rust//rust/platform:"
    if any(not label.startswith(prefix) for label in selections):
        raise ValueError("reviewed feature select contains an unknown platform")
    return {
        "common": ast.literal_eval(node.left),
        "selects": {label.removeprefix(prefix): features for label, features in selections.items()},
    }


def rewrite_features(rendered, expected, features, suffix="", repository=""):
    """Specializes literal generated rules without changing their source inputs.

    Build-script binaries must get constant features: an exec-configured select
    would otherwise give a target crate's script the build dependency's features.
    Variants therefore copy the library, script, and script alias together.
    """
    lines = rendered.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def span(node):
        return offsets[node.lineno - 1] + node.col_offset, offsets[node.end_lineno - 1] + node.end_col_offset

    calls = [node.value for node in ast.parse(rendered).body
             if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
             and isinstance(node.value.func, ast.Name)
             and node.value.func.id in {"rust_library", "rust_proc_macro", "cargo_build_script", "alias"}]
    names = {ast.literal_eval(keyword.value) for call in calls for keyword in call.keywords if keyword.arg == "name"}
    replacements = []
    variants = []
    feature_rules = 0
    for call in calls:
        start, end = span(call)
        edits = []
        keywords = {keyword.arg: keyword.value for keyword in call.keywords}
        if "crate_features" in keywords:
            value = keywords["crate_features"]
            resolution = expected if isinstance(expected, dict) else {"common": expected, "selects": {}}
            if rendered_features(value) != resolution:
                raise ValueError("rendered crate features disagree with reviewed resolution")
            edits.append((*span(value), json.dumps(features)))
            feature_rules += 1
        if suffix:
            value = keywords["name"]
            name = ast.literal_eval(value)
            edits.append((*span(value), json.dumps(name + suffix)))
            for node in ast.walk(call):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                for prefix in [":", "@" + repository + "//:"]:
                    if node.value.startswith(prefix) and node.value[len(prefix):] in names:
                        edits.append((*span(node), json.dumps(node.value + suffix)))
            if call.func.id in {"rust_library", "rust_proc_macro"} and "crate_name" not in keywords:
                # The rule name changes, but rustc's crate identity must not.
                edits.append((end - 1, end - 1, "    crate_name = " + json.dumps(name) + ",\n"))
        block = rendered[start:end]
        for left, right, value in sorted(edits, reverse=True):
            block = block[:left - start] + value + block[right - start:]
        if suffix:
            variants.append(block)
        else:
            replacements.append((start, end, block))
    if not feature_rules:
        raise ValueError("reviewed crate has no literal feature declarations")
    if suffix:
        return "\n\n".join(variants) + "\n"
    for start, end, block in reversed(replacements):
        rendered = rendered[:start] + block + rendered[end:]
    return rendered


def execution_feature_graph(rendered, expected, target_features, exec_features, repository):
    """Selects complete feature units while keeping each build script constant.

    Selecting features on a build-script executable would observe its exec
    configuration instead of the library configuration it describes. Select
    the complete library/script unit first, then compile its script normally.
    """
    lines = rendered.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    calls = [node.value for node in ast.parse(rendered).body
             if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
             and isinstance(node.value.func, ast.Name)
             and node.value.func.id in {"rust_library", "rust_proc_macro", "cargo_build_script", "alias"}]
    names = [ast.literal_eval(keyword.value) for call in calls
             for keyword in call.keywords if keyword.arg == "name"]
    if len(names) != len(calls) or len(set(names)) != len(names):
        raise ValueError("execution feature units require unique literal rule names")

    prelude = rendered
    for call in reversed(calls):
        start = offsets[call.lineno - 1] + call.col_offset
        end = offsets[call.end_lineno - 1] + call.end_col_offset
        prelude = prelude[:start] + prelude[end:]
    variants = [rewrite_features(rendered, expected, features, "__aos_" + role, repository)
                for role, features in [("target", target_features), ("exec", exec_features)]]
    aliases = [
        "alias(\n    name = " + json.dumps(name) + ",\n    actual = select({\n"
        '        "@//tools/bazel/rules:exec_compilation": ' + json.dumps(":" + name + "__aos_exec") + ",\n"
        '        "//conditions:default": ' + json.dumps(":" + name + "__aos_target") + ",\n"
        "    }),\n)\n"
        for name in names
    ]
    return prelude.rstrip() + "\n\n" + "\n".join(variants + aliases)


def specialize_feature_graph(specification, context, builds, repository):
    """Applies version-checked feature units and redirects explicit consumer edges."""
    for name, policy in specification.get("feature_variants", {}).items():
        identifier = (name, policy["version"])
        crates = [crate for crate in context["crates"].values()
                  if (crate["name"], crate["version"]) == identifier]
        if len(crates) != 1 or identifier not in builds:
            raise ValueError(f"reviewed feature crate version is absent: {identifier}")
        crate = crates[0]
        expected = {"common": policy["resolved_features"], "selects": policy.get("resolved_selects", {})}
        if crate["common_attrs"]["crate_features"] != expected:
            raise ValueError(f"reviewed feature resolution changed: {identifier}")
        original = builds[identifier]
        own_repository = crate_repository(repository, *identifier)
        if "exec_features" in policy:
            if policy.get("variants"):
                raise ValueError("execution feature units cannot also redirect explicit consumers")
            builds[identifier] = execution_feature_graph(
                original, expected, policy["features"], policy["exec_features"], own_repository)
            continue
        builds[identifier] = rewrite_features(original, expected, policy["features"])
        for variant, settings in policy.get("variants", {}).items():
            if not re.fullmatch(r"[a-z][a-z0-9_]*", variant) or not settings["dependents"]:
                raise ValueError("feature variant requires a safe name and explicit dependents")
            suffix = "__aos_" + variant
            builds[identifier] += "\n# Reviewed Cargo feature unit: " + variant + "\n" + rewrite_features(
                original, expected, settings["features"], suffix, own_repository)
            label = f"@{own_repository}//:{crate['library_target_name']}"
            for consumer, version in settings["dependents"].items():
                key = (consumer, version)
                if key not in builds or json.dumps(label) not in builds[key]:
                    raise ValueError(f"reviewed feature dependency edge is absent: {key} -> {identifier}")
                builds[key] = builds[key].replace(json.dumps(label), json.dumps(label + suffix))
    return builds


def prepare_sources(specification, scratch, repository, staged):
    """Checks registry archive hashes and annotates rendered integration scope."""
    context = json.loads((scratch / "context.json").read_text())
    available = {f"{crate['name']}@{crate['version']}" for crate in context["crates"].values()}
    requested = specification.get("permissive_crates", [])
    if len(requested) != len(set(requested)) or set(requested) - available:
        raise ValueError("permissive crate identities must be unique and present in the resolved graph")
    lock = tomllib.loads((scratch / "spliced/Cargo.lock").read_text())
    checksums = {(package["name"], package["version"]): package["checksum"]
                 for package in lock["package"] if "source" in package}
    sources = {}
    declarations = [
        '# Generated by the explicit Rust dependency update. Nix supplies every source repository.',
        'aos_crate = use_repo_rule("//tools/bazel/toolchains:repositories.bzl", "aos_tools_repository")',
        "",
    ]
    builds = {}
    for crate in context["crates"].values():
        if crate["repository"] is None:
            continue
        source = crate["repository"]
        if set(source) != {"Http"}:
            raise ValueError("Rust source updater currently accepts hashed registry archives only")
        source = source["Http"]
        url = urlparse(source["url"])
        if url.scheme != "https" or url.username or url.password or url.query:
            raise ValueError("Rust source URL must be an HTTPS URL without credentials or query parameters")
        name, version = crate["name"], crate["version"]
        archives = list((scratch / "cargo-home").glob(f"registry/cache/*/{name}-{version}.crate"))
        if len(archives) != 1:
            raise ValueError(f"missing unique downloaded source archive: {name}-{version}")
        checksum = digest(archives[0])
        if checksum != checksums[name, version] or checksum != source["sha256"]:
            raise ValueError(f"source checksum disagrees with resolved locks: {name}-{version}")
        license_domain = validate_license(specification, crate)
        filename = f"BUILD.{name}-{version}.bazel"
        rendered = (scratch / "rendered" / filename).read_text()
        marker = "    tags = [\n"
        if marker not in rendered:
            raise ValueError(f"rendered crate lacks expected tag declarations: {filename}")
        # Scope is checked independently of the original SPDX expression, which
        # remains in the source inventory and upstream source files.
        rendered = rendered.replace(marker, marker + '        "aos-license:' + license_domain + '",\n')
        rendered = "\n".join(line.rstrip() for line in rendered.splitlines()) + "\n"
        builds[name, version] = rendered
        label = crate_repository(repository, name, version)
        if label in sources:
            raise ValueError(f"crate repository name collision: {label}")
        sources[label] = {
            "name": name, "version": version, "url": source["url"], "sha256": checksum,
            "strip_prefix": f"{name}-{version}", "build_file": filename,
            "license": crate["license"], "license_domain": license_domain,
        }
        declarations.append(f'aos_crate(name = "{label}")')
    builds = specialize_feature_graph(specification, context, builds, repository)
    for (name, version), rendered in builds.items():
        (staged / f"BUILD.{name}-{version}.bazel").write_text(rendered)
    (staged / "repositories.MODULE.bazel").write_text("\n".join(declarations) + "\n")
    aliases = {}
    for identifier in context["direct_deps"]:
        crate = context["crates"][identifier]
        name, version = crate["name"], crate["version"]
        aliases[name] = f"@{crate_repository(repository, name, version)}//:{crate['library_target_name']}"
    (staged / "aliases.bzl").write_text(
        '"""Generated direct dependency labels for this resolved family."""\n\n'
        + "CRATES = " + json.dumps(aliases, indent=4, sort_keys=True) + "\n"
    )
    shutil.copyfile(scratch / "spliced/Cargo.lock", staged / "Cargo.lock")
    shutil.copyfile(scratch / "context.json", staged / "cargo-bazel.json")
    shutil.copyfile(scratch / "config.json", staged / "generator-config.json")
    return sources


def publish(staged, output):
    """Replaces only files owned by this updater, preserving unrelated files."""
    previous = output / "sources.json"
    owned = set()
    if previous.exists():
        value = json.loads(previous.read_text())
        if value["schema_version"] != 1:
            raise ValueError("unsupported previous Rust source inventory")
        owned = set(value["generated_files"]) | {"sources.json"}
    for name in owned:
        if Path(name).name != name or name in {"", ".", ".."}:
            raise ValueError("unsafe obsolete generated filename")
    output.mkdir(parents=True, exist_ok=True)
    for file in staged.iterdir():
        target = output / file.name
        if target.exists() and file.name not in owned:
            raise ValueError(f"refusing to replace unmanaged Rust dependency file: {target}")
    for file in staged.iterdir():
        # Scratch space and the checkout can reside on different filesystems.
        # Stage replacements beside their destination before atomic rename.
        with tempfile.NamedTemporaryFile(dir=output, prefix=".update-", delete=False) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(file.read_bytes())
        try:
            temporary_path.chmod(0o644)
            os.replace(temporary_path, output / file.name)
        finally:
            temporary_path.unlink(missing_ok=True)
        owned.discard(file.name)
    for name in owned:
        # Inventory paths are basenames produced here, never arbitrary paths.
        (output / name).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--specifications", required=True, type=Path)
    parser.add_argument("--tool-config", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--scratch-parent", type=Path)
    parser.add_argument("--seed-lock", type=Path)
    options = parser.parse_args()
    specification = json.loads(options.specifications.read_text())
    if specification["schema_version"] != 1 or not re.fullmatch(r"[a-z][a-z0-9-]*", specification["family"]):
        parser.error("unsupported Rust family specification")
    tools = json.loads(options.tool_config.read_text())
    if digest(Path(__file__)) != digest(options.root / "tools/bazel/metadata/update_rust.py"):
        parser.error("installed Rust updater is stale; rebuild its package")
    for name, expected in specification["contracts"].items():
        if digest(options.root / name) != expected:
            parser.error("stale Rust specifications; rebuild their Bazel package: " + name)
    with tempfile.TemporaryDirectory(prefix="aos-rust-update-", dir=options.scratch_parent) as directory:
        scratch = Path(directory)
        seed_lock = options.seed_lock
        if seed_lock is None and (options.output / "Cargo.lock").exists():
            seed_lock = options.output / "Cargo.lock"
        repository = resolve(specification, tools, scratch, seed_lock)
        staged = scratch / "staged"
        staged.mkdir()
        sources = prepare_sources(specification, scratch, repository, staged)
        contracts = {**specification["contracts"],
                     "tools/bazel/metadata/update_rust.py": digest(options.root / "tools/bazel/metadata/update_rust.py")}
        inventory = {
            "schema_version": 1, "family": specification["family"],
            "specifications": specification, "sources": sources,
            "contracts": contracts,
            "tool_identity": tools,
            "generated_files": {file.name: digest(file) for file in sorted(staged.iterdir())},
        }
        write_json(staged / "sources.json", inventory)
        publish(staged, options.output)


if __name__ == "__main__":
    main()
