//! Independently checks a genuine publisher-peer probe against retained roots.
//!
//! The peer receipt is privately minted by the authenticated concrete client.
//! This adapter measures its actual descriptor again and retains that receipt,
//! its native domain root and provisioning guard for the capability's lifetime.
//! Seal support alone never qualifies quota, admission or canonical serving.

use super::{NativeHostLayout, open_directory_chain};
use crate::publisher_local::client::PeerSealProbe;
use rustix::fs::{FileType, OFlags, fcntl_getfl, fstat, fstatfs};
use std::{io, sync::Arc};
use terrane::host::cache::{DomainHostLayout, HostInspection, HostReadLocation, SealInspection};

/// Retains independently measured seal support on one genuine native layout.
///
/// A caller cannot construct this from an arbitrary file, digest or boolean.
/// The complete authenticated peer receipt keeps its actual root guard alive.
/// This type grants neither a serving handle nor writable admission authority.
pub struct NativeSealCapability<L: HostReadLocation = DomainHostLayout> {
    probe: PeerSealProbe<L>,
    inspection: HostInspection,
}

impl<L: HostReadLocation> NativeSealCapability<L> {
    /// Borrows the real unlinked probe for native owner allocation observation.
    #[cfg(feature = "tokio")]
    pub(super) fn probe_handle(&self) -> &std::fs::File {
        self.probe.handle()
    }

    /// Remeasures an actual authenticated peer probe and its root filesystem.
    ///
    /// The source must be the private receipt returned by the concrete native
    /// publisher client. Its descriptor remains empty, unlinked and read-only;
    /// canonical content can never be substituted for this capability probe.
    ///
    /// # Errors
    /// Refuses stale roots, another device, nonregular/writable/named/nonempty
    /// probes, mismatched kernel measurements, inconsistent mount observations
    /// and unsupported native filesystem or seal facts.
    pub fn from_probe(probe: PeerSealProbe<L>) -> io::Result<Self> {
        let inspection = inspect(&probe)?;
        Ok(Self { probe, inspection })
    }

    /// Borrows the actual retained root and its live provisioning guard.
    pub fn layout(&self) -> &Arc<NativeHostLayout<L>> {
        self.probe.layout()
    }

    /// Borrows the measured filesystem snapshot without creating new authority.
    ///
    /// Consumers needing live facts call `recheck` before their own native
    /// boundary. This snapshot is not quota, admission or object-identity proof.
    pub fn inspection(&self) -> &HostInspection {
        &self.inspection
    }

    /// Rechecks the actual probe, root incarnation and current mount facts.
    ///
    /// # Errors
    /// Returns native inspection errors or rejects a changed device, root inode,
    /// filesystem type or independently measured kernel seal.
    pub fn recheck(&self) -> io::Result<()> {
        let current = inspect(&self.probe)?;
        if current.device != self.inspection.device
            || current.root_inode != self.inspection.root_inode
            || current.filesystem_type != self.inspection.filesystem_type
            || current.seal.algorithm != self.inspection.seal.algorithm
            || current.seal.digest != self.inspection.seal.digest
        {
            return Err(invalid("native seal capability incarnation changed"));
        }
        Ok(())
    }
}

fn inspect<L: HostReadLocation>(probe: &PeerSealProbe<L>) -> io::Result<HostInspection> {
    let layout = probe.layout();
    layout.recheck()?;
    let root = fstat(&layout.root)?;
    let filesystem = fstatfs(&layout.root)?;
    check_canonical_mount(layout, &filesystem)?;

    let before = fstat(probe.handle())?;
    let flags = fcntl_getfl(probe.handle())?;
    if flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
        || FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_nlink != 0
        || before.st_size != 0
        || before.st_dev != root.st_dev
    {
        return Err(invalid(
            "seal probe has unsuitable access, type, link, size or device",
        ));
    }
    let binding = crate::verity::measure(probe.handle())?;
    if &binding != probe.binding() {
        return Err(invalid(
            "seal probe differs from authenticated peer measurement",
        ));
    }
    let after = fstat(probe.handle())?;
    if before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_uid != after.st_uid
        || before.st_mode != after.st_mode
        || before.st_nlink != after.st_nlink
        || before.st_size != after.st_size
    {
        return Err(invalid("seal probe changed during native measurement"));
    }
    let inspection = HostInspection {
        device: root.st_dev,
        root_inode: root.st_ino,
        filesystem_type: filesystem.f_type as u64,
        mount_flags: filesystem.f_flags as u64,
        seal: SealInspection {
            device: after.st_dev,
            algorithm: binding.algorithm,
            digest: binding.digest,
        },
    };
    inspection.validate()?;
    layout.recheck()?;
    check_canonical_mount(layout, &filesystem)?;
    Ok(inspection)
}

fn check_canonical_mount<L: HostReadLocation>(
    layout: &NativeHostLayout<L>,
    expected: &rustix::fs::StatFs,
) -> io::Result<()> {
    // Matching device/inode alone does not detect a replacement bind mount of
    // that same directory with different mount flags. Observe the current path
    // as well as the retained directory description without following symlinks.
    let current = open_directory_chain(layout.layout().root())?;
    let metadata = fstat(&current)?;
    let retained = fstat(&layout.root)?;
    let filesystem = fstatfs(&current)?;
    if metadata.st_dev != retained.st_dev
        || metadata.st_ino != retained.st_ino
        || filesystem.f_type != expected.f_type
        || filesystem.f_flags != expected.f_flags
    {
        return Err(invalid(
            "canonical host root mount differs from retained inspection",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
