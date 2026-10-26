"""Selects a coherent third-party feature graph for a Rust compilation family."""

def _dependency_profile_impl(ctx):
    if ctx.build_setting_value not in [
        "aos-cli-tests",
        "aos-cli-fleet-tests",
        "aos-cli-production",
        "hub-worker-tests",
        "hub-worker-all-features-tests",
        "hub-worker-wasm",
        "hub-worker-wasm-do-e2e",
        "hub-worker-wasm-all-features",
        "hub-native-postgres",
        "hub-native-tests",
        "hub-service",
        "hub-service-tests",
        "hub-service-all-features",
        "hub-service-all-features-tests",
        "accache",
        "registry-web",
        "registry-web-wasm",
        "hub-console",
        "hub-console-wasm",
        "hub-db",
        "hub-db-tests",
        "hub-db-all-features",
        "hub-db-all-features-tests",
        "package-manager",
        "package-manager-tests",
        "package-evaluation-driver",
        "deployment-check",
        "configuration-image",
        "configuration-image-tests",
        "preparation-provider",
        "preparation-provider-tests",
        "nix-store-provider",
        "systemd-provider",
        "configuration-files",
        "configuration-files-tests",
        "kernel-tunable",
        "kernel-tunable-tests",
        "boot-preparation",
        "boot-preparation-minimal",
        "release-coordination",
        "registry-native",
        "registry-native-tests",
        "release-preparation",
        "release-signer",
        "hub-client",
        "hub-model",
        "hub-model-tests",
        "hub-portable",
        "deployment",
        "build-services",
        "cli-support",
        "activation-crucible",
        "activation-crucible-tests",
        "activation-systemd",
        "activation-storage",
        "activation-core",
        "activation-core-tests",
        "core",
        "device",
        "store",
        "guest",
        "engine",
        "quota",
        "session",
        "control",
        "qemu-host",
        "qemu-gpl-production",
        "qemu-test-oracle-host",
        "qemu-gpl-tests",
        "qemu-gpl-plugin-tests",
        "store-s3",
        "daemon",
        "crucible-cli",
        "native-foundation",
        "native-bindings",
        "native-foundation-tests",
        "native-foundation-minimal",
        "formats",
    ]:
        fail("unknown Rust dependency profile: " + ctx.build_setting_value)
    return []

dependency_profile = rule(
    implementation = _dependency_profile_impl,
    build_setting = config.string(flag = True),
)

def _compilation_role_impl(ctx):
    return [config_common.FeatureFlagInfo(
        value = "exec" if ctx.configuration.is_tool_configuration() else "target",
    )]

compilation_role = rule(implementation = _compilation_role_impl)

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

def _session_profile_required_impl(_ctx):
    fail("dependency is unavailable in the selected family; session dependencies require --//tools/bazel/rules:dependency_profile=session")

session_profile_required = rule(implementation = _session_profile_required_impl)

def _control_profile_required_impl(_ctx):
    fail("dependency is unavailable in the selected family; transport dependencies require --//tools/bazel/rules:dependency_profile=control")

control_profile_required = rule(implementation = _control_profile_required_impl)

def _qemu_host_profile_required_impl(_ctx):
    fail("QEMU host dependencies require --//tools/bazel/rules:dependency_profile=qemu-host")

qemu_host_profile_required = rule(implementation = _qemu_host_profile_required_impl)

def _store_s3_profile_required_impl(_ctx):
    fail("S3 adapter dependencies require --//tools/bazel/rules:dependency_profile=store-s3")

store_s3_profile_required = rule(implementation = _store_s3_profile_required_impl)

def _daemon_profile_required_impl(_ctx):
    fail("daemon dependencies require --//tools/bazel/rules:dependency_profile=daemon")

daemon_profile_required = rule(implementation = _daemon_profile_required_impl)

def _crucible_cli_profile_required_impl(_ctx):
    fail("Crucible CLI dependencies require --//tools/bazel/rules:dependency_profile=crucible-cli")

crucible_cli_profile_required = rule(implementation = _crucible_cli_profile_required_impl)


def _formats_profile_required_impl(_ctx):
    fail("Format dependencies require --//tools/bazel/rules:dependency_profile=formats")

formats_profile_required = rule(implementation = _formats_profile_required_impl)
