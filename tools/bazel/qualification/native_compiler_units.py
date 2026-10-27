"""Classifies native compiler roles through declared artifact dependency edges.

Cargo can place target and execution libraries in the same directory when both
platforms are native. Artifact names, compiler sources, and explicit --extern
edges distinguish the units without inferring roles from optimization flags.
This model accepts the Linux Rust artifact forms retained by the native oracle;
other formats fail instead of being guessed.
"""

from collections import defaultdict
import posixpath

from verify_compiler_options import compiler_options


def option_values(arguments, name):
    """Reads nonempty paired or equals-form option values."""
    result = []
    for index, argument in enumerate(arguments):
        if argument == name:
            if index + 1 == len(arguments) or arguments[index + 1].startswith("-"):
                raise ValueError("missing compiler option value: " + name)
            result.append(arguments[index + 1])
        elif argument.startswith(name + "="):
            result.append(argument[len(name) + 1:])
    if any(not value for value in result):
        raise ValueError("empty compiler option value: " + name)
    return result


def unique_option(arguments, name):
    """Requires one unambiguous compiler option value."""
    values = option_values(arguments, name)
    if len(values) != 1:
        raise ValueError("missing or ambiguous compiler option: " + name)
    return values[0]


def linux_outputs(arguments):
    """Indexes ordinary Linux Rust artifact names from explicit compiler inputs."""
    if option_values(arguments, "-o") or option_values(arguments, "--output"):
        raise ValueError("explicit native output paths require a separate artifact model")
    directory = unique_option(arguments, "--out-dir")
    name = unique_option(arguments, "--crate-name")
    scalar = compiler_options(arguments)["effective_scalar_codegen"]
    suffix = scalar.get("extra-filename")
    if not isinstance(suffix, str) or not suffix.startswith("-") or "/" in name + suffix:
        raise ValueError("native compiler unit omitted its artifact identity")
    kinds = {kind for value in option_values(arguments, "--crate-type") for kind in value.split(",")}
    if not kinds and "--test" in arguments:
        kinds = {"bin"}
    if not kinds:
        raise ValueError("native compiler unit omitted its crate type")

    stem = name + suffix
    filenames = set()
    for kind in kinds:
        if kind in {"lib", "rlib"}:
            filenames.update("lib" + stem + extension for extension in [".rlib", ".rmeta"])
        elif kind in {"proc-macro", "dylib", "cdylib"}:
            filenames.add("lib" + stem + ".so")
        elif kind == "staticlib":
            filenames.add("lib" + stem + ".a")
        elif kind == "bin":
            filenames.add(stem)
        else:
            raise ValueError("unsupported native Rust crate type: " + kind)
    return sorted(posixpath.normpath(posixpath.join(directory, filename)) for filename in filenames), kinds


def classify(invocations, messages, target_sources):
    """Requires complete, unambiguous target/execution roles for native units.

    The caller supplies exact native source paths for target roots. Declared
    Cargo custom-build and proc-macro artifacts seed execution roots. Only
    compiler requests whose source appears in successful Cargo artifact records
    enter the graph. Compiler capability queries and build-script probes remain
    explicitly excluded. Every non-sysroot extern must resolve to one compiler
    unit, and every selected unit must be reachable from an explicit root.
    """
    artifacts = defaultdict(list)
    for message in messages:
        if message.get("reason") == "compiler-artifact":
            artifacts[posixpath.normpath(message["target"]["src_path"])].append(message)
    target_sources = {posixpath.normpath(source) for source in target_sources}
    if not artifacts or not target_sources:
        raise ValueError("native artifact or target-root inventory is empty")

    units = []
    excluded = []
    matched_target_sources = set()
    for index, invocation in enumerate(invocations):
        if invocation.get("schema_version") != 1:
            raise ValueError("unsupported native compiler trace schema")
        arguments = invocation["arguments"]
        if any(argument == "--print" or argument.startswith("--print=") for argument in arguments):
            excluded.append({"invocation": index, "reason": "compiler query"})
            continue
        sources = {
            posixpath.normpath(argument if argument.startswith("/") else posixpath.join(invocation["directory"], argument))
            for argument in arguments if not argument.startswith("-") and argument.endswith(".rs")
        }
        matched = sources & artifacts.keys()
        if not matched:
            excluded.append({"invocation": index, "reason": "source has no Cargo compiler artifact"})
            continue
        if len(matched) != 1:
            raise ValueError("ambiguous native compiler artifact source")
        source = matched.pop()
        outputs, kinds = linux_outputs(arguments)
        custom_build = any("custom-build" in message["target"]["kind"] for message in artifacts[source])
        execution = custom_build or "proc-macro" in kinds
        if execution and source in target_sources:
            raise ValueError("native execution root was also declared as a target root")
        role = "execution" if execution else ("target" if source in target_sources else None)
        if role == "target":
            matched_target_sources.add(source)
        units.append({"invocation": index, "source": source, "outputs": outputs, "root_role": role})
    if matched_target_sources != target_sources:
        raise ValueError("native target roots omitted a declared compiler source")

    owners = {}
    for index, unit in enumerate(units):
        for output in unit["outputs"]:
            if output in owners:
                raise ValueError("ambiguous native compiler artifact owner: " + output)
            owners[output] = index
    edges = defaultdict(set)
    sysroot_externs = []
    for index, unit in enumerate(units):
        for declaration in option_values(invocations[unit["invocation"]]["arguments"], "--extern"):
            alias, separator, filename = declaration.partition("=")
            if not separator and alias == "proc_macro":
                sysroot_externs.append({"unit": index, "name": alias})
                continue
            if not separator or not alias or not filename:
                raise ValueError("native extern omitted its artifact path: " + declaration)
            filename = posixpath.normpath(filename)
            if filename not in owners:
                raise ValueError("native extern has no compiler artifact owner: " + filename)
            edges[index].add(owners[filename])

    roles = defaultdict(set)
    pending = [(index, unit["root_role"]) for index, unit in enumerate(units) if unit["root_role"]]
    while pending:
        index, role = pending.pop()
        if role in roles[index]:
            continue
        roles[index].add(role)
        for dependency in edges[index]:
            child_role = "execution" if units[dependency]["root_role"] == "execution" else role
            pending.append((dependency, child_role))
    if set(roles) != set(range(len(units))):
        raise ValueError("native compiler unit is unreachable from a declared root")
    if any(len(selected) != 1 for selected in roles.values()):
        raise ValueError("native compiler artifact is shared by target and execution roles")
    for index, unit in enumerate(units):
        unit["role"] = next(iter(roles[index]))
        unit["dependencies"] = sorted(edges[index])
    return {"units": units, "excluded_invocations": excluded, "sysroot_externs": sysroot_externs}
