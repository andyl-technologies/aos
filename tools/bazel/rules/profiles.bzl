"""Selects a coherent third-party feature graph for a Rust compilation family."""

def _dependency_profile_impl(ctx):
    if ctx.build_setting_value not in ["core", "device", "store", "guest", "engine", "quota"]:
        fail("unknown Rust dependency profile: " + ctx.build_setting_value)
    return []

dependency_profile = rule(
    implementation = _dependency_profile_impl,
    build_setting = config.string(flag = True),
)

def _device_profile_required_impl(_ctx):
    fail("this dependency requires --//tools/bazel/rules:dependency_profile=device")

device_profile_required = rule(implementation = _device_profile_required_impl)

def _store_profile_required_impl(_ctx):
    fail("this dependency requires --//tools/bazel/rules:dependency_profile=store")

store_profile_required = rule(implementation = _store_profile_required_impl)

def _guest_profile_required_impl(_ctx):
    fail("dependency is unavailable in the selected family; guest dependencies require --//tools/bazel/rules:dependency_profile=guest")

guest_profile_required = rule(implementation = _guest_profile_required_impl)

def _engine_profile_required_impl(_ctx):
    fail("dependency is unavailable in the selected family; engine dependencies require --//tools/bazel/rules:dependency_profile=engine")

engine_profile_required = rule(implementation = _engine_profile_required_impl)

def _quota_profile_required_impl(_ctx):
    fail("dependency is unavailable in the selected family; quota dependencies require --//tools/bazel/rules:dependency_profile=quota")

quota_profile_required = rule(implementation = _quota_profile_required_impl)
