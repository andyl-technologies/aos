"""Selects coherent daemon library identities for CLI feature configurations."""

load(":daemon_graph.bzl", "daemon_dependencies")

CRUCIBLE_CLI_VARIANTS = {
    "": [],
    "_test_double": ["test-double"],
    "_recovery_faults": ["destructive-recovery-faults"],
    "_recovery_test_double": ["destructive-recovery-faults", "test-double"],
    "_packaged_midpoint_flight": ["packaged-midpoint-flight"],
    "_packaged_recovery": ["destructive-recovery-faults", "packaged-midpoint-flight"],
    "_packaged_test_double": ["packaged-midpoint-flight", "test-double"],
    "_all_features": ["destructive-recovery-faults", "packaged-midpoint-flight", "test-double"],
}

def cli_dependencies(names, features, development = False):
    """Preserves one library graph across direct and indirect CLI dependencies."""
    recovery = "destructive-recovery-faults" in features
    session_test_double = "test-double" in features
    if development:
        suffix = "_all_features" if recovery else "_test_support"
    else:
        suffix = "_recovery_faults" if recovery else ""
    result = daemon_dependencies(
        [name for name in names if name != "daemon"],
        suffix,
        development,
        session_test_double,
    )
    if "daemon" in names:
        target = "lib_for_tests" if development else "lib"
        target += ("_session_test_double" if session_test_double else "") + suffix
        result.append("//crates/crucible/crucible-daemon:" + target)
    return result

def cli_integration_sources(source):
    """Includes each integration root and its actual shared module directories."""
    sources = [source]
    patterns = [source.removesuffix(".rs") + "/**/*.rs"]
    if source == "tests/gate_campaign_store_composition.rs":
        sources.append("tests/campaign_store_process.rs")
        patterns.append("tests/campaign_store_process/**/*.rs")
    if source in ["tests/campaign_store_process.rs", "tests/gate_campaign_store_composition.rs"]:
        patterns.append("tests/support/campaign_packaged_process*.rs")
        patterns.append("tests/support/campaign_packaged_process/**/*.rs")
    if source == "tests/machine_readable.rs":
        sources.append("tests/support/machine.rs")
    return sources + native.glob(patterns, allow_empty = True)
