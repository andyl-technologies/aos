"""Keeps the combined Apache controller tests in one Rust dependency graph.

Selecting all controller packages enables dependency features through every
selected package's development edges. In particular, control client/server
tests enable session test support while CLI tests also enable its test double.
These libraries are separate from each package's independently selected tests
and from the installed controller executables.
"""

load(":compile.bzl", "rust_library")
load(":license.bzl", "aos_license_check")
load(":test.bzl", "aos_rust_test")

_PACKAGES = {
    "engine": "crucible-engine",
    "session": "crucible-session",
    "api": "crucible-control-api",
    "client": "crucible-control-client",
    "server": "crucible-control-server",
    "qemu": "crucible-qemu-host",
    "daemon": "crucible-daemon",
    "s3": "crucible-store-s3",
    "campaign": "crucible-campaign",
    "store": "crucible-store",
}

_FEATURES = {
    "crucible-engine": ["default", "test-double", "test-support"],
    "crucible-session": ["default", "test-double", "test-support"],
    "crucible-control-api": [],
    "crucible-control-client": [],
    "crucible-control-server": ["default", "test-support"],
    "crucible-qemu-host": ["default", "test-support"],
    "crucible-daemon": ["default", "test-support"],
    "crucible-cli": ["default", "test-double"],
    "crucible-campaign": [],
    "crucible-store-s3": [],
}

def controller_features(package):
    """Returns features for the combined controller test selection only."""
    if package.name not in _FEATURES:
        fail("package has no controller-specific feature graph: " + package.name)
    return _FEATURES[package.name]

def controller_dependencies(names):
    """Selects the same Rust library identity along direct and indirect edges."""
    result = []
    for name in names:
        package = _PACKAGES[name]
        target = "lib_test_support" if name == "store" else "lib_controller" if package in _FEATURES else "lib"
        result.append("//crates/crucible/" + package + ":" + target)
    return result

def controller_dependency(dependency):
    """Remaps package-owned direct dependencies that gain combined features."""
    for name, package in _PACKAGES.items():
        if dependency == "//crates/crucible/" + package + ":lib":
            return controller_dependencies([name])[0]
    return dependency

def controller_library(package, sources, common_deps, library_names = [], compile_data = []):
    """Declares one package-owned library with the combined test features."""
    dependencies = common_deps + controller_dependencies(library_names)
    if package.name == "crucible-engine":
        dependencies = dependencies + ["//crates/crucible/crucible-qemu-shmem:lib"]
    rust_library(
        name = "lib_controller",
        testonly = True,
        package = package,
        lint_config = "//tools/bazel/rules:workspace_lints",
        crate_name = package.name.replace("-", "_"),
        crate_root = "src/lib.rs",
        srcs = sources,
        compile_data = compile_data,
        crate_features = controller_features(package),
        deps = dependencies,
    )

def controller_tests(package, integrations, dependencies, development_deps = [], unit_compile_data = [], unit_data = [], compile_inputs = {}, source_inputs = {}, runtime_inputs = {}, environments = {}, runfile_environments = {}, ignored_only = []):
    """Preserves package-owned fixtures while using the combined library graph."""
    features = controller_features(package)
    # rules_rust's default includes the compile action's temporary sandbox.
    # Runtime source discovery uses workspace-relative runfiles instead.
    compiler_environment = {"CARGO_MANIFEST_DIR": native.package_name()}
    aos_rust_test(
        name = "unit_controller",
        package = package,
        lint_config = "//tools/bazel/rules:workspace_lints",
        crate = ":lib_controller",
        crate_features = features,
        rustc_env = compiler_environment,
        compile_data = unit_compile_data,
        data = unit_data,
        deps = development_deps,
    )
    binaries = [":unit_controller_binary"]
    tests = [":unit_controller"]
    for source in integrations:
        name = source.removeprefix("tests/").removesuffix(".rs") + "_controller"
        aos_rust_test(
            name = name,
            package = package,
            lint_config = "//tools/bazel/rules:workspace_lints",
            crate_root = source,
            srcs = [source] + native.glob([source.removesuffix(".rs") + "/**/*.rs"], allow_empty = True) + source_inputs.get(source, []),
            compile_data = compile_inputs.get(source, []),
            data = runtime_inputs.get(source, []),
            env = environments.get(source, {}),
            runfile_env = runfile_environments.get(source, {}),
            allow_ignored_only = source in ignored_only,
            crate_features = features,
            rustc_env = compiler_environment,
            deps = [":lib_controller"] + dependencies + development_deps,
        )
        binaries.append(":" + name + "_binary")
        tests.append(":" + name)
    native.test_suite(name = "controller_tests", tests = tests)
    aos_license_check(
        name = "controller_test_license_closure",
        testonly = True,
        roots = [":lib_controller"] + binaries,
        license_domain = package.license_domain,
    )
