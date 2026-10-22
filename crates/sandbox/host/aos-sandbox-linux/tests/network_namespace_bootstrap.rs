//! Proves native worker network isolation preserves the host mount namespace.
//!
//! This harness-free executable runs as root in the AOS qualification VM.
//! Namespace originals stay open across bootstrap so inode reuse cannot make
//! a different namespace appear identical to an original.

use std::fs::File;

use aos_sandbox_linux::pidfd::{NamespaceFd, NamespaceKind, SingleThreadedProcess};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let process = SingleThreadedProcess::verify()?;
    let original_network = NamespaceFd::current_network()?;
    let original_mount = NamespaceFd::from_owned(
        File::open("/proc/self/ns/mnt")?.into(),
        NamespaceKind::Mount,
    )?;

    process.create_network_namespace()?;

    let private_network = NamespaceFd::current_network()?;
    let current_mount = NamespaceFd::from_owned(
        File::open("/proc/self/ns/mnt")?.into(),
        NamespaceKind::Mount,
    )?;
    assert_ne!(private_network.identity(), original_network.identity());
    assert_eq!(current_mount.identity(), original_mount.identity());
    println!("private network namespace retains the original mount namespace");
    Ok(())
}
