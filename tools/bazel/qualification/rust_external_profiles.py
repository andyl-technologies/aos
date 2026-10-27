"""Pairs external Rust units using artifact-derived native execution roles.

This ordinary-test audit compares features, cfgs, editions, selected profile
settings, and optionally stripping. Raw compiler-option differences remain
visible; a matching library unit does not qualify its native or linker ABI.
"""

import posixpath

from build_script_profiles import compiler_role
from native_compiler_units import classify, option_values, unique_option
from rust_profiles import profile, require_matching_strip
from verify_compiler_options import cargo_compilation_source, compiler_options


# These pinned rules_rust tools implement the build system itself. Cargo's
# application trace has no counterpart for them; retain their executions apart
# from dependency units rather than treating placeholder package versions as SDKs.
BUILD_SUPPORT_LABELS = {
    "@@rules_rust++i+rules_rust_tinyjson//:tinyjson",
    "@@rules_rust+//util/process_wrapper:process_wrapper",
    "@@rules_rust+//cargo/private/cargo_build_script_runner:cargo_build_script_runner",
    "@@rules_rust+//cargo/private/cargo_build_script_runner:runner",
}


def describe(arguments, environment, role):
    """Retains package/version, crate kind, role, and exact feature identity."""
    if role not in {"target", "execution"}:
        raise ValueError("unsupported external compiler role")
    package = environment.get("CARGO_PKG_NAME")
    version = environment.get("CARGO_PKG_VERSION")
    if not package or not version:
        raise ValueError("external compiler omitted its package identity")

    declared_types = [kind for value in option_values(arguments, "--crate-type")
                      for kind in value.split(",")]
    kinds = set(declared_types)
    library_types = {"lib", "rlib", "cdylib", "staticlib", "dylib"}
    if kinds & {"lib", "rlib"} and kinds <= library_types:
        # Cargo can additionally emit C-facing artifacts in the same request.
        # Preserve those types without treating them as qualified Bazel outputs.
        kind = "rlib"
    elif len(kinds) == 1 and kinds <= library_types | {"bin", "proc-macro"}:
        kind = next(iter(kinds))
    else:
        raise ValueError("unsupported external crate-type combination: " + str(declared_types))

    options = compiler_options(arguments)
    options["explicit_edition"] = options["edition"]
    options["edition"] = options["edition"] or "2015"
    options["declared_crate_types"] = declared_types
    features = tuple(cfg for cfg in options["cfg"] if cfg.startswith("feature="))
    key = package, version, unique_option(arguments, "--crate-name"), kind, role, features
    return key, options


def add_unit(index, key, value):
    """Rejects duplicate executions rather than hiding them in a set."""
    if key in index:
        raise ValueError("duplicate external compiler unit: " + str(key))
    index[key] = value


def match_units(bazel, native, compare_strip):
    """Requires complete units and matches their selected compiler settings."""
    if not bazel or not native or bazel.keys() != native.keys():
        raise ValueError("external compiler inventories differ: " + str({
            "only_bazel": sorted(bazel.keys() - native.keys()),
            "only_native": sorted(native.keys() - bazel.keys()),
        }))

    pairs = []
    for key in sorted(bazel):
        actual = bazel[key]
        expected = native[key]
        differences = {
            field: {"bazel": actual["options"][field], "native": expected["options"][field]}
            for field in ["cfg", "edition"]
            if actual["options"][field] != expected["options"][field]
        }
        if differences:
            raise ValueError("external compiler cfg/edition differs: " + str((key, differences)))

        optimization = "0" if key[4] == "execution" else "s"
        bazel_scalar = profile(actual["arguments"], optimization, True)
        native_scalar = profile(expected["arguments"], optimization, False)
        if compare_strip:
            require_matching_strip(bazel_scalar, native_scalar)
        pairs.append({
            "package": key[0], "version": key[1], "crate_name": key[2],
            "kind": key[3], "role": key[4], "features": list(key[5]),
            "label": actual["label"], "native_invocation": expected["invocation"],
            "bazel_options": actual["options"], "native_options": expected["options"],
            "bazel_scalar": bazel_scalar, "native_scalar": native_scalar,
        })
    return pairs


def source_paths(invocation):
    """Resolves the positional Rust sources recorded by the native wrapper."""
    return {
        posixpath.normpath(argument if argument.startswith("/") else
                           posixpath.join(invocation["directory"], argument))
        for argument in invocation["arguments"]
        if not argument.startswith("-") and argument.endswith(".rs")
    }


def native_target_roots(invocations, messages):
    """Selects declared first-party roots independently of optimization flags."""
    artifacts = {posixpath.normpath(row["target"]["src_path"])
                 for row in messages if row.get("reason") == "compiler-artifact"}
    execution = {posixpath.normpath(row["target"]["src_path"])
                 for row in messages if row.get("reason") == "compiler-artifact"
                 and {"custom-build", "proc-macro"} & set(row["target"]["kind"])}
    return set().union(*[
        source_paths(row) & (artifacts - execution)
        for row in invocations if cargo_compilation_source(row) is not None
    ])


def verify_external(actions, configurations, invocations, messages, repository_prefix, compare_strip):
    """Matches every external request, rejecting unknown Bazel repositories."""
    if not repository_prefix.startswith("@@") or not repository_prefix.endswith("_"):
        raise ValueError("external audit requires an explicit canonical repository prefix")
    roles = classify(invocations, messages, native_target_roots(invocations, messages))

    bazel = {}
    support = {}
    for action in actions:
        label = action["target_label"]
        if not label.startswith(repository_prefix):
            if label in BUILD_SUPPORT_LABELS:
                if label in support or compiler_role(action["arguments"], configurations) != "execution":
                    raise ValueError("build-system helper is duplicated or uses a target configuration: " + label)
                support[label] = action
            elif not label.startswith("//crates/"):
                raise ValueError("external compiler uses an unenrolled repository: " + label)
            continue
        role = compiler_role(action["arguments"], configurations)
        key, options = describe(action["arguments"], action["environment"], role)
        add_unit(bazel, key, {"label": label, "arguments": action["arguments"], "options": options})

    native = {}
    for unit in roles["units"]:
        index = unit["invocation"]
        invocation = invocations[index]
        if cargo_compilation_source(invocation) is not None:
            continue
        key, options = describe(invocation["arguments"], invocation["environment"], unit["role"])
        add_unit(native, key, {"invocation": index, "arguments": invocation["arguments"], "options": options})

    return {
        "status": "PASS", "repository_prefix": repository_prefix,
        "native_role_inference_uses_optimization": False,
        "native_role_graph": roles,
        "build_system_helpers": [support[label] for label in sorted(support)],
        "units": match_units(bazel, native, compare_strip),
        "strip_compared": compare_strip,
        "limits": [
            "Matches exact ordinary-test package/version/crate/feature/role units and selected cfg/edition/profile settings.",
            "Additional native C-facing crate types remain explicit; their artifacts and ABI are not qualified here.",
            "Exact pinned rules_rust build-system helpers are retained separately and must use execution configurations; they have no Cargo application-unit counterpart.",
            "Other compiler defaults, native C/linker options, ABI/runtime, editor/release/foreign profiles, caches and performance remain separate.",
            "The native artifact model accepts Linux output forms and rejects artifacts shared between target and execution roles.",
        ],
    }
