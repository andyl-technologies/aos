//! Retains the complete anchor inventory's real descriptor and native results.

use super::*;
use aos_sandbox_linux::path::BeneathRootResolveOriginalV2;

/// Retains one complete physical anchor census and its first native refusal.
///
/// Empty construction performs no observations. The selected service funds the
/// full census before entering it and retains this owner through signed send.
#[derive(Default)]
pub struct MountAttachmentAnchorInventoryOriginalV4 {
    entered: bool,
    reads: Vec<AnchorReadOriginalV4>,
    output: Option<Vec<AttachmentAnchorInventoryV1>>,
    result: Option<Result<()>>,
    closed: Option<MountError>,
}

#[derive(Default)]
pub(super) struct AnchorReadOriginalV4 {
    resolved: BeneathRootResolveOriginalV2,
    absent_expected: bool,
    resolution: Option<std::result::Result<(), aos_linux_descriptors::Error>>,
    pin: Option<ResolvedPath>,
    metadata: Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>,
    mount: Option<std::result::Result<MountId, aos_linux_descriptors::Error>>,
    comparison: Option<Result<()>>,
    physical_mount: Option<std::result::Result<MountId, aos_linux_descriptors::Error>>,
}

impl AnchorReadOriginalV4 {
    fn verify_pin_v4(&mut self, store: &DestinationSlotStoreV1, pin: &ResolvedPath,
        mode: u32, expected: Option<(u64, u64, u64)>) -> Result<(FileIdentity, MountId)> {
        verify_native_pin_v4(store, pin, mode, expected,
            &mut self.metadata, &mut self.mount, &mut self.comparison,
            &mut self.physical_mount)
    }

    pub(super) fn resolve_v4(&mut self, store: &DestinationSlotStoreV1, path: &Path,
        expected: Option<(u64, u64, u64)>) -> Result<(FileIdentity, MountId)> {
        self.resolve_optional_v4(store, path, ANCHOR_DIRECTORY_MODE, expected)?
            .ok_or_else(|| corrupt("Ready anchor path is absent"))
    }

    pub(super) fn resolve_optional_v4(
        &mut self, store: &DestinationSlotStoreV1, path: &Path,
        mode: u32, expected: Option<(u64, u64, u64)>,
    ) -> Result<Option<(FileIdentity, MountId)>> {
        if !self.resolve_path_optional_v4(store, path)? { return Ok(None); }
        self.verify_resolved_v4(store, mode, expected).map(Some)
    }

    pub(super) fn resolve_path_optional_v4(
        &mut self, store: &DestinationSlotStoreV1, path: &Path,
    ) -> Result<bool> {
        self.resolution = Some(self.resolved.resolve_once(&store.root, path, ResolveOptions::directory()));
        if !matches!(self.resolution, Some(Ok(()))) {
            if matches!(self.resolved.failure(), Some(aos_linux_descriptors::Error::Syscall { source, .. })
                if source.raw_os_error() == Some(libc::ENOENT))
            {
                self.absent_expected = true;
                return Ok(false);
            }
            return Err(conflict("anchor inventory retained resolution refusal"));
        }
        self.pin = self.resolved.take_completed_once();
        if self.pin.is_none() { return Err(corrupt("anchor inventory lost descriptor")); }
        Ok(true)
    }

    pub(super) fn verify_resolved_v4(
        &mut self, store: &DestinationSlotStoreV1, mode: u32,
        expected: Option<(u64, u64, u64)>,
    ) -> Result<(FileIdentity, MountId)> {
        let pin = self.pin.as_ref().ok_or_else(|| corrupt("anchor inventory lost descriptor"))?;
        verify_native_pin_v4(store, pin, mode, expected,
            &mut self.metadata, &mut self.mount, &mut self.comparison,
            &mut self.physical_mount)
    }

    pub(super) fn take_pin_once_v4(&mut self) -> Option<ResolvedPath> {
        if self.failure_v4().is_some() || !matches!(self.comparison, Some(Ok(()))) { return None; }
        self.pin.take()
    }

    pub(super) fn borrowed_pin_v4(&self) -> Option<&ResolvedPath> {
        if self.failure_v4().is_some() || !matches!(self.comparison, Some(Ok(()))) { return None; }
        self.pin.as_ref()
    }

    pub(super) fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.resolved.failure().filter(|_| !self.absent_expected).map(|cause| cause as _)
            .or_else(|| self.metadata.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.mount.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.physical_mount.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.comparison.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

impl MountAttachmentAnchorInventoryOriginalV4 {
    /// Borrows the actual first native cause before its coarse census marker.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.reads.iter().find_map(|read| read.failure_v4())
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn collect_once_v4(&mut self, store: &DestinationSlotStoreV1) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(|| conflict("anchor inventory already entered"));
            return Err(conflict("anchor inventory remains closed"));
        }
        self.entered = true;
        self.result = Some((|| {
            let reads = store.records.len().checked_mul(2)
                .and_then(|count| count.checked_add(store.namespace_anchors.records.len()))
                .ok_or_else(|| invalid("anchor inventory read count overflow"))?;
            self.reads = Vec::with_capacity(reads);
            let mut anchors = BTreeMap::new();
            for (slot_key, record) in &store.records {
                if record.phase != DestinationSlotResourcePhaseV1::Ready
                    || record.kernel_boot_id != store.kernel_boot_id { continue; }
                let pin = store.pins.get(slot_key).ok_or_else(|| corrupt("Ready slot is not pinned"))?;
                self.reads.push(AnchorReadOriginalV4::default());
                self.reads.last_mut().ok_or_else(|| corrupt("slot read original absent"))?
                    .verify_pin_v4(store, pin, SLOT_DIRECTORY_MODE,
                        Some((record.slot_device, record.slot_inode, record.anchor_mount_id)))?;
                let key = (record.binding.sandbox_id, record.binding.incarnation_id,
                    record.binding.namespace_generation);
                if let Some(anchor) = anchors.get(&key) {
                    let anchor: &AttachmentAnchorInventoryV1 = anchor;
                    if anchor.identity.device != record.slot_device || anchor.mount_id.get() != record.anchor_mount_id {
                        return Err(corrupt("Ready slots disagree about their physical anchor"));
                    }
                    continue;
                }
                self.reads.push(AnchorReadOriginalV4::default());
                let (identity, mount) = self.reads.last_mut().ok_or_else(|| corrupt("anchor read original absent"))?
                    .resolve_v4(store, &record.binding.anchor_relative_path(), None)?;
                if identity.device != record.slot_device || mount.get() != record.anchor_mount_id {
                    return Err(corrupt("anchor does not reproduce Ready slot identity"));
                }
                anchors.insert(key, AttachmentAnchorInventoryV1 { sandbox_id: key.0,
                    incarnation_id: key.1, namespace_generation: key.2,
                    kernel_boot_id: store.kernel_boot_id, identity, mount_id: mount });
            }
            for (key, record) in &store.namespace_anchors.records {
                if record.lifecycle() != Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY
                    || record.resource_kernel_boot_id() != &store.kernel_boot_id { continue; }
                let pin = store.namespace_anchors.pins.get(key)
                    .ok_or_else(|| corrupt("Ready namespace anchor is not pinned"))?;
                if record.physical_identity_v1() != Some((pin.identity().device, pin.identity().inode, store.anchor_mount_id.get())) {
                    return Err(corrupt("namespace inventory pin changed"));
                }
                self.reads.push(AnchorReadOriginalV4::default());
                let (identity, mount) = self.reads.last_mut().ok_or_else(|| corrupt("namespace read original absent"))?
                    .resolve_v4(store, &namespace_path_v1(record), record.physical_identity_v1())?;
                let fence = record.fence();
                let key = (*fence.sandbox_id(), *fence.incarnation_id(), record.namespace_generation());
                if anchors.insert(key, AttachmentAnchorInventoryV1 { sandbox_id: key.0,
                    incarnation_id: key.1, namespace_generation: key.2,
                    kernel_boot_id: store.kernel_boot_id, identity, mount_id: mount }).is_some() {
                    return Err(corrupt("namespace inventory aliases slot anchor"));
                }
            }
            self.output = Some(anchors.into_values().collect());
            Ok(())
        })());
        if matches!(self.result, Some(Ok(()))) { Ok(()) }
        else { Err(conflict("anchor inventory retained a refusal")) }
    }

    pub(crate) fn take_completed_once_v4(&mut self) -> Option<Vec<AttachmentAnchorInventoryV1>> {
        if self.failure().is_some() || !matches!(self.result, Some(Ok(()))) { return None; }
        self.output.take()
    }
}

fn verify_native_pin_v4(
    store: &DestinationSlotStoreV1,
    pin: &ResolvedPath,
    mode: u32,
    expected: Option<(u64, u64, u64)>,
    metadata: &mut Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>,
    mount_result: &mut Option<std::result::Result<MountId, aos_linux_descriptors::Error>>,
    comparison: &mut Option<Result<()>>,
    physical_mount: &mut Option<std::result::Result<MountId, aos_linux_descriptors::Error>>,
) -> Result<(FileIdentity, MountId)> {
    *metadata = Some(rustix::fs::fstat(pin.as_fd()));
    *comparison = Some((|| {
        let stat = metadata.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or_else(|| conflict("anchor inventory retained metadata refusal"))?;
        let identity = pin.identity();
        if identity.file_type != FileType::Directory || stat.st_uid != store.root_owner
            || stat.st_mode & 0o7777 != mode
        {
            return Err(corrupt("anchor inventory directory ownership or mode changed"));
        }
        // Preserve the ordinary directory short circuit: no mount probe occurs
        // after a failed fstat/owner/mode check.
        *mount_result = Some(MountId::from_fd(pin.as_fd()));
        let mount = mount_result.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or_else(|| conflict("anchor inventory retained mount refusal"))?;
        if mount != store.anchor_mount_id {
            return Err(corrupt("anchor inventory is outside the original Mount anchor"));
        }
        let observed = if mode == SLOT_DIRECTORY_MODE && expected.is_some() {
            // The existing Ready/Reaping slot chain independently observed its
            // physical record after verify_new_directory's first MountId.
            *physical_mount = Some(MountId::from_fd(pin.as_fd()));
            physical_mount.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or_else(|| conflict("slot inventory retained physical mount refusal"))?
        } else { mount };
        if expected.is_some_and(|value| value != (identity.device, identity.inode, observed.get())) {
            return Err(corrupt("anchor inventory physical identity changed"));
        }
        Ok(())
    })());
    if !matches!(comparison, Some(Ok(()))) {
        return Err(conflict("anchor inventory retained comparison refusal"));
    }
    Ok((pin.identity(), mount_result.as_ref().and_then(|result| result.as_ref().ok())
        .copied().ok_or_else(|| corrupt("anchor inventory lost mount result"))?))
}

/// Carries passive complete native/model/response geometry for a held census.
pub struct MountAttachmentAnchorInventoryShapeDataV4 {
    complete: aos_sandbox_model::ResourceVector,
}

impl MountAttachmentAnchorInventoryShapeDataV4 {
    /// Prices all current rows and retained physical read destinations.
    ///
    /// # Errors
    /// Refuses an invalid table population or checked geometry overflow.
    pub fn for_current_v4(store: &DestinationSlotStoreV1) -> Result<Self> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let overflow = || invalid("anchor inventory representation overflow");
        let slots = store.records.len();
        let namespaces = store.namespace_anchors.records.len();
        let anchors = slots.checked_add(namespaces).ok_or_else(overflow)?;
        let reads = slots.checked_add(anchors).ok_or_else(overflow)?;
        let encoded = aos_sandbox_protocol::mount_destination_slot::destination_slot_inventory_encoded_bound_v4(
            slots, namespaces, anchors,
        )?;
        let resolution = BeneathRootResolveOriginalV2::receiving_obligations_v2(88)
            .ok_or_else(overflow)?;
        let native = std::mem::size_of::<AnchorReadOriginalV4>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(resolution.0)).ok_or_else(overflow)?;
        let tree = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<
            ([u8; 16], [u8; 16], u64), AttachmentAnchorInventoryV1>(anchors).ok_or_else(overflow)?;
        let bytes = std::mem::size_of::<MountAttachmentAnchorInventoryOriginalV4>().checked_mul(2)
            .and_then(|bytes| reads.checked_mul(native).and_then(|other| bytes.checked_add(other)))
            .and_then(|bytes| bytes.checked_add(tree))
            .and_then(|bytes| anchors.checked_mul(2 * std::mem::size_of::<AttachmentAnchorInventoryV1>())
                .and_then(|other| bytes.checked_add(other)))
            // Retained wire model, encoder growth, validation graph and output.
            .and_then(|bytes| encoded.checked_mul(4).and_then(|other| bytes.checked_add(other)))
            .ok_or_else(overflow)?;
        let complete = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow())?)
            .with(D::OpenFiles, u64::try_from(anchors.checked_mul(resolution.1).ok_or_else(overflow)?).map_err(|_| overflow())?)
            .with(D::MetadataEntries, u64::try_from(anchors.checked_mul(resolution.2).and_then(|names| names.checked_add(anchors)).ok_or_else(overflow)?).map_err(|_| overflow())?)
            .with(D::OutputBytes, u64::try_from(encoded).map_err(|_| overflow())?);
        Ok(Self { complete })
    }

    /// Returns this already checked complete recipe without admitting it.
    ///
    /// # Errors
    /// The immutable checked recipe has no additional failure path.
    pub fn receiving_demand_v4(&self) -> Result<aos_sandbox_model::ResourceVector> { Ok(self.complete) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_mount_native::JournalLimits;

    #[test]
    fn ordinary_slot_owner_refusal_short_circuits_before_any_mount_probe() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(PARENT_DIRECTORY_MODE)).unwrap();
        let (journal, _) = Journal::open(directory.path().join("journal"), JournalLimits::default()).unwrap();
        let store = DestinationSlotStoreV1::recover(directory.path(), rustix::process::getuid().as_raw(), &journal).unwrap();
        let pin = store.root.resolve(Path::new("."), ResolveOptions::directory()).unwrap();
        let mut read = AnchorReadOriginalV4::default();

        assert!(read.verify_pin_v4(&store, &pin, SLOT_DIRECTORY_MODE, None).is_err());
        assert!(matches!(read.metadata, Some(Ok(_))));
        assert!(read.mount.is_none());
        assert!(read.physical_mount.is_none());
        assert!(read.failure_v4().is_some());
    }

    #[test]
    fn ordinary_slot_physical_comparison_retains_both_original_mount_samples() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(PARENT_DIRECTORY_MODE)).unwrap();
        let (journal, _) = Journal::open(directory.path().join("journal"), JournalLimits::default()).unwrap();
        let store = DestinationSlotStoreV1::recover(directory.path(), rustix::process::getuid().as_raw(), &journal).unwrap();
        std::fs::create_dir(directory.path().join("slot")).unwrap();
        std::fs::set_permissions(directory.path().join("slot"), std::fs::Permissions::from_mode(SLOT_DIRECTORY_MODE)).unwrap();
        let pin = store.root.resolve(Path::new("slot"), ResolveOptions::directory()).unwrap();
        let identity = pin.identity();
        let mut read = AnchorReadOriginalV4::default();

        read.verify_pin_v4(&store, &pin, SLOT_DIRECTORY_MODE,
            Some((identity.device, identity.inode, store.anchor_mount_id.get()))).unwrap();
        assert!(matches!(read.mount, Some(Ok(_))));
        assert!(matches!(read.physical_mount, Some(Ok(_))));
        assert!(read.failure_v4().is_none());
    }
}
