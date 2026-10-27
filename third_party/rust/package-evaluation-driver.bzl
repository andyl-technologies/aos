"""Preserves the installed Cargo example's execution and target feature roles."""

load(":package-manager.bzl", "PACKAGE_MANAGER_TESTS_FEATURE_VARIANTS")

PACKAGE_EVALUATION_DRIVER_FEATURE_VARIANTS = dict(
    PACKAGE_MANAGER_TESTS_FEATURE_VARIANTS,
    # The production builder selects an explicit target triple. Its execution
    # generators retain minimal dependencies independently of target features.
    getrandom = json.encode({
        "version": "0.4.2",
        "resolved_features": ["sys_rng"],
        "features": ["sys_rng"],
        "exec_features": [],
    }),
    hashbrown = json.encode({
        "version": "0.17.1",
        "resolved_features": ["default-hasher", "inline-more"],
        "features": ["default-hasher", "inline-more"],
        "exec_features": [],
    }),
)
