//! Checks original mount attributes after a private mount namespace is created.
//!
//! The dedicated QEMU fixture opens descriptors 3 and 4 before unshare. Procfs
//! reopens only recover those test descriptors without raw-FD adoption; the
//! production observation itself accepts their borrowed descriptors directly.

use std::fs::File;
use std::os::fd::AsFd;

use aos_linux_descriptors::Error;
use aos_sandbox_linux::inventory::{DescriptorMountObservation, MountId, MountNamespace};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths: Vec<_> = std::env::args_os().skip(1).collect();
    assert_eq!(
        paths.len(),
        2,
        "requires the read-only and writable fixture paths"
    );

    for (slot, path, read_only) in [(3, &paths[0], true), (4, &paths[1], false)] {
        let inherited = File::open(format!("/proc/self/fd/{slot}"))?;
        let inherited_id = MountId::from_fd(inherited.as_fd())?;
        let namespace = MountNamespace::current();

        // The old namespace-based guard cannot observe the inherited mount.
        match namespace.observe(inherited_id) {
            Err(Error::Syscall { source, .. }) if source.raw_os_error() == Some(libc::ENOENT) => {}
            result => panic!("expected a foreign inherited mount, got {result:?}"),
        }

        let observed = DescriptorMountObservation::capture(inherited.as_fd())?;
        assert_eq!(observed.mount_id, inherited_id);
        assert_eq!(observed.is_read_only(), read_only);
        assert_eq!(
            DescriptorMountObservation::capture(inherited.as_fd())?,
            observed
        );

        let reopened = File::open(path)?;
        let reopened_id = MountId::from_fd(reopened.as_fd())?;
        assert_ne!(reopened_id, inherited_id);
        assert_eq!(namespace.observe(reopened_id)?.is_read_only(), read_only);
        assert_eq!(
            DescriptorMountObservation::capture(reopened.as_fd())?.is_read_only(),
            read_only,
        );
    }

    println!("inherited mount basics preserve read-only and writable rejection: PASS");
    Ok(())
}
