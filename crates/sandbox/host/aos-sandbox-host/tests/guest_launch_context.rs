//! Checks the emitted Systemd guest-owner argument against Linux confinement.

#![cfg(target_os = "linux")]

use aos_sandbox_linux::guest_confinement::{GUEST_OWNER_CONTEXT, GUEST_TENANT_CONTEXT};
use aos_systemd_client::{
    SandboxDescriptorPath, SandboxNspawnCommand, SandboxResolvedPaths, SandboxResources,
    SandboxUnitName, SandboxUnitSpec,
};
use std::os::fd::AsFd as _;
use std::time::Duration;

fn descriptor_path(path: &str) -> SandboxDescriptorPath {
    let file = std::fs::File::open(path).unwrap();
    SandboxDescriptorPath::for_current_process(file.as_fd()).unwrap()
}

#[test]
fn guest_owner_launch_context_matches_linux_confinement() {
    let incarnation = [0xab; 16];
    let command = SandboxNspawnCommand::private_user_descriptor_v1(
        descriptor_path("/proc/self/exe"),
        incarnation,
        65_536,
        65_536,
    )
    .unwrap();
    let paths = SandboxResolvedPaths::from_descriptors(
        descriptor_path("/"),
        descriptor_path("/proc/self/ns/net"),
    );
    let resources = SandboxResources::new(512, 1024, 128, 100)
        .and_then(|value| value.with_cpu_quota(Duration::from_millis(500)))
        .and_then(|value| value.with_io_weight(200))
        .and_then(|value| value.with_open_file_limit(1024))
        .unwrap();
    let spec = SandboxUnitSpec::new_nspawn(
        SandboxUnitName::from_incarnation(incarnation),
        command,
        paths,
        resources,
        Duration::from_secs(30),
        Duration::from_secs(10),
    )
    .unwrap();

    let contexts = spec
        .arguments()
        .iter()
        .filter_map(|argument| argument.strip_prefix("--selinux-context="))
        .collect::<Vec<_>>();

    assert_eq!(contexts, [GUEST_OWNER_CONTEXT]);
    assert_ne!(contexts, [GUEST_TENANT_CONTEXT]);
}
