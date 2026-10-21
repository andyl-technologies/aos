//! Retains the sole destination-store opening, replay and native recovery.
//!
//! The selected image-enrolled Mount facade funds these destinations before
//! opening the fixed catalog path. Ordinary recovery delegates the same recipe.

use super::*;
use aos_sandbox_linux::path::BeneathRootOwnedOriginalV2;
use aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1;

/// Retains the complete fixed Store opening and every failed native prefix.
///
/// Empty construction performs no IO and adopts no supplied directory.
pub struct DestinationSlotStartupOriginalV4 {
    entered: bool,
    metadata: Option<std::io::Result<std::fs::Metadata>>,
    open: Option<std::result::Result<(), rustix::io::Errno>>,
    pending: Option<OwnedFd>,
    descriptor_metadata: Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>,
    root_original: BeneathRootOwnedOriginalV2,
    root_result: Option<std::result::Result<(), aos_linux_descriptors::Error>>,
    root: Option<BeneathRoot>,
    mount: Option<std::result::Result<MountId, aos_linux_descriptors::Error>>,
    boot: RootOriginalKernelBootIdAttemptV1,
    replay: DestinationResourceReplayOriginalV4,
    reads: Vec<inventory::AnchorReadOriginalV4>,
    store: Option<DestinationSlotStoreV1>,
    result: Option<Result<()>>,
    closed: Option<MountError>,
}

impl Default for DestinationSlotStartupOriginalV4 {
    fn default() -> Self {
        Self { entered: false, metadata: None, open: None, pending: None,
            descriptor_metadata: None, root_original: Default::default(), root_result: None,
            root: None, mount: None, boot: RootOriginalKernelBootIdAttemptV1::new(),
            replay: Default::default(), reads: Vec::new(), store: None, result: None, closed: None }
    }
}

impl DestinationSlotStartupOriginalV4 {
    /// Prices the real first root/boot prefix before any native opening.
    ///
    /// # Errors
    /// Refuses checked layout overflow; no observation is performed.
    pub fn fixed_receiving_demand_v4() -> Result<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        let bytes = std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()?))
            .ok_or_else(|| invalid("Mount store startup representation overflow"))?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes)
            .map_err(|_| invalid("Mount store startup representation overflow"))?)
            .with(D::OpenFiles, 1 + RootOriginalKernelBootIdAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64)
            .with(D::MetadataEntries, 1))
    }

    /// Prices complete current table recovery before parsing or native pin opens.
    ///
    /// # Errors
    /// Preserves the same writer's native geometry or checked layout refusal.
    pub fn reached_receiving_demand_v4(journal: &Journal) -> Result<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
        use aos_sandbox_journal::geometry::{RecordShape, conservative_btree_node_bytes_v1};
        let overflow = || invalid("Mount store replay representation overflow");
        let count = journal.records(RecordNamespace::MountDestinationSlot).count();
        let slot_rows = journal.records(RecordNamespace::MountDestinationSlot)
            .filter(|(key, _)| key.len() == 56).count();
        let namespace_rows = journal.records(RecordNamespace::MountDestinationSlot)
            .filter(|(key, _)| key.len() == 40).count();
        if count > MAXIMUM_SLOT_RESOURCES { return Err(overflow()); }
        let native = aos_sandbox_linux::path::BeneathRootResolveOriginalV2::receiving_obligations_v2(121)
            .ok_or_else(overflow)?;
        let read = std::mem::size_of::<inventory::AnchorReadOriginalV4>().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(native.0)).ok_or_else(overflow)?;
        let slots = conservative_btree_node_bytes_v1::<SlotKey, Record>(count).ok_or_else(overflow)?;
        let namespaces = conservative_btree_node_bytes_v1::<[u8; 40], ValidatedAttachmentAnchorResourceV1>(count)
            .ok_or_else(overflow)?;
        let pins = conservative_btree_node_bytes_v1::<SlotKey, ResolvedPath>(count).ok_or_else(overflow)?;
        let namespace_pins = conservative_btree_node_bytes_v1::<[u8; 40], Arc<BeneathRoot>>(count)
            .ok_or_else(overflow)?;
        let operations = conservative_btree_node_bytes_v1::<OperationId, ()>(count.checked_mul(3).ok_or_else(overflow)?)
            .ok_or_else(overflow)?;
        let arc = std::mem::size_of::<BeneathRoot>().checked_add(2 * std::mem::size_of::<usize>())
            .and_then(|bytes| bytes.checked_add(std::mem::align_of::<BeneathRoot>()))
            .and_then(|bytes| bytes.checked_mul(count)).ok_or_else(overflow)?;
        let row_decode = aos_sandbox_protocol::mount_attachment_anchor::attachment_anchor_resource_decoding_memory_v4(
            aos_sandbox_protocol::mount_attachment_anchor::MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1)?;
        let bytes = slots.checked_add(namespaces).and_then(|bytes| bytes.checked_add(pins))
            .and_then(|bytes| bytes.checked_add(namespace_pins))
            .and_then(|bytes| bytes.checked_add(operations))
            .and_then(|bytes| bytes.checked_add(arc))
            .and_then(|bytes| bytes.checked_add(row_decode))
            .and_then(|bytes| count.checked_mul(read).and_then(|other| bytes.checked_add(other)))
            // Each actual row's finite payload also dominates its descriptor
            // backing, constructor and prospective indexed representation.
            .and_then(|bytes| count.checked_mul(2 * aos_sandbox_protocol::mount_destination_slot::MAXIMUM_DESTINATION_RESOURCE_RECORD_BYTES_V4)
                .and_then(|other| bytes.checked_add(other))).ok_or_else(overflow)?;
        // The compiled resolver's one owning descriptor is moved into the
        // Store; taking its output does not create a second native file.
        let files = count.checked_mul(native.1).ok_or_else(overflow)?;
        // These are real logical namespace indices, distinct from durable
        // journal indices and filesystem names: record+pin per resource and
        // the replay's retained operation-ID set (up to three/slot, two/anchor).
        let index_names = slot_rows.checked_mul(5)
            .and_then(|names| namespace_rows.checked_mul(4).and_then(|other| names.checked_add(other)))
            .ok_or_else(overflow)?;
        let names = count.checked_mul(native.2).and_then(|names| names.checked_add(index_names))
            .ok_or_else(overflow)?;
        let models = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| overflow())?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| overflow())?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| overflow())?);
        let journal = journal.append_receiving_demand_v1(std::iter::empty::<RecordShape>())
            .map_err(MountError::AnchorGeometry)?;
        Self::fixed_receiving_demand_v4()?.checked_add(models)
            .and_then(|complete| complete.checked_add(journal)).map_err(|_| overflow())
    }

    pub(crate) fn open_once_v4(&mut self, path: &Path, owner: u32, journal: &Journal) -> Result<()> {
        if self.entered {
            self.closed.get_or_insert_with(|| conflict("Mount store startup already entered"));
            return Err(conflict("Mount store startup remains closed"));
        }
        self.entered = true;
        self.result = Some((|| {
            self.metadata = Some(std::fs::symlink_metadata(path));
            let metadata = self.metadata.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| conflict("Mount root metadata retained a refusal"))?;
            if !metadata.file_type().is_dir() || metadata.uid() != owner
                || metadata.permissions().mode() & 0o077 != 0
            { return Err(corrupt("destination-slot root is not an exact private directory")); }
            match rustix::fs::open(path, rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC, rustix::fs::Mode::empty()) {
                Ok(fd) => { self.pending = Some(fd); self.open = Some(Ok(())); }
                Err(cause) => { self.open = Some(Err(cause)); return Err(conflict("Mount root open retained a refusal")); }
            }
            let candidate = self.pending.as_ref().ok_or_else(|| corrupt("Mount root descriptor absent"))?;
            self.descriptor_metadata = Some(rustix::fs::fstat(candidate));
            let stat = self.descriptor_metadata.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| conflict("Mount root descriptor metadata retained a refusal"))?;
            if stat.st_uid != owner || stat.st_mode & 0o7777 != PARENT_DIRECTORY_MODE
                || stat.st_dev != metadata.dev() || stat.st_ino != metadata.ino()
            { return Err(corrupt("destination-slot root changed while opened")); }
            let candidate = self.pending.take().ok_or_else(|| corrupt("Mount root candidate absent"))?;
            self.root_result = Some(self.root_original.from_owned_once(candidate));
            if !matches!(self.root_result, Some(Ok(()))) {
                return Err(conflict("Mount root validation retained a refusal"));
            }
            self.root = self.root_original.take_completed_once();
            let root = self.root.as_ref().ok_or_else(|| corrupt("Mount original root absent"))?;
            self.mount = Some(MountId::from_fd(root.as_fd()));
            let mount = self.mount.as_ref().and_then(|result| result.as_ref().ok()).copied()
                .ok_or_else(|| conflict("Mount root identity retained a refusal"))?;
            let boot = self.boot.observe_once().ok().copied()
                .ok_or_else(|| conflict("Mount boot original retained a refusal"))?.into_bytes();
            self.replay.load_once_v4(journal)?;
            let (records, namespaces) = self.replay.take_completed_once_v4()
                .ok_or_else(|| corrupt("Mount replay lost its complete original"))?;
            let root = self.root.take().ok_or_else(|| corrupt("Mount root lost before Store transfer"))?;
            self.store = Some(DestinationSlotStoreV1 { root, root_owner: owner, anchor_mount_id: mount,
                kernel_boot_id: boot, records, pins: BTreeMap::new(),
                namespace_anchors: NamespaceAnchorTableV1::new(namespaces), git_coverage_census: None });
            let store = self.store.as_mut().ok_or_else(|| corrupt("Mount pending Store absent"))?;
            let count = store.records.len().checked_add(store.namespace_anchors.records.len())
                .ok_or_else(|| invalid("Mount recovery read count overflow"))?;
            // Exact preallocation avoids Vec::push's minimum-four carrier
            // allocation. Every subsequent row fits this already paid buffer.
            self.reads = Vec::with_capacity(count);
            recover_pins_v4(store, &mut self.reads)?;
            Ok(())
        })());
        if matches!(self.result, Some(Ok(()))) { Ok(()) }
        else { Err(conflict("Mount store startup retained a refusal")) }
    }

    /// Borrows the first actual native, parser or model refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.metadata.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.open.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.descriptor_metadata.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.root_original.failure().map(|cause| cause as _))
            .or_else(|| self.mount.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.boot.failure())
            .or_else(|| self.replay.failure_v4().map(|cause| cause as _))
            .or_else(|| self.reads.iter().find_map(|read| read.failure_v4()))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn take_completed_once_v4(&mut self) -> Option<DestinationSlotStoreV1> {
        if self.failure().is_some() || !matches!(self.result, Some(Ok(()))) { return None; }
        self.store.take()
    }
}

fn recover_pins_v4(store: &mut DestinationSlotStoreV1, reads: &mut Vec<inventory::AnchorReadOriginalV4>) -> Result<()> {
    for (key, record) in &store.records {
        reads.push(inventory::AnchorReadOriginalV4::default());
        let read = reads.last_mut().ok_or_else(|| corrupt("slot recovery original absent"))?;
        let physical = if matches!(record.phase, DestinationSlotResourcePhaseV1::Ready | DestinationSlotResourcePhaseV1::Reaping) {
            Some((record.slot_device, record.slot_inode, record.anchor_mount_id))
        } else { None };
        let present = read.resolve_path_optional_v4(store, &record.binding.catalog_relative_path())?;
        if record.kernel_boot_id != store.kernel_boot_id {
            if present { return Err(corrupt("stale-boot destination-slot path unexpectedly exists")); }
            continue;
        }
        if record.phase == DestinationSlotResourcePhaseV1::Released {
            if present { return Err(corrupt("Released slot still exists")); }
            continue;
        }
        let observed = if present { Some(read.verify_resolved_v4(store, SLOT_DIRECTORY_MODE, physical)?) }
            else { None };
        match (record.phase, observed) {
            (DestinationSlotResourcePhaseV1::Ready | DestinationSlotResourcePhaseV1::Reaping, Some(_)) => {
                let pin = read.take_pin_once_v4().ok_or_else(|| corrupt("slot recovery lost its original pin"))?;
                store.pins.insert(*key, pin);
            }
            (DestinationSlotResourcePhaseV1::Ready, None) => return Err(corrupt("same-boot Ready slot is absent")),
            (DestinationSlotResourcePhaseV1::Released, Some(_)) => return Err(corrupt("Released slot still exists")),
            _ => {}
        }
    }
    for (key, record) in &store.namespace_anchors.records {
        reads.push(inventory::AnchorReadOriginalV4::default());
        let read = reads.last_mut().ok_or_else(|| corrupt("namespace recovery original absent"))?;
        let present = read.resolve_path_optional_v4(store, &namespace_path_v1(record))?;
        if record.resource_kernel_boot_id() != &store.kernel_boot_id {
            if present { return Err(corrupt("stale namespace anchor path unexpectedly exists")); }
            continue;
        }
        if record.lifecycle() == Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED {
            if present { return Err(corrupt("Released namespace still exists")); }
            continue;
        }
        let observed = if present { Some(read.verify_resolved_v4(store, ANCHOR_DIRECTORY_MODE,
            record.physical_identity_v1())?) } else { None };
        match (record.lifecycle(), observed) {
            (Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY | Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_REAPING, Some(_)) => {
                let pin = read.take_pin_once_v4().ok_or_else(|| corrupt("namespace recovery lost original pin"))?;
                let root = BeneathRoot::from_resolved(pin).map_err(linux_error)?;
                store.namespace_anchors.pins.insert(*key, Arc::new(root));
            }
            (Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY, None) => return Err(corrupt("same-boot Ready namespace is absent")),
            (Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED, Some(_)) => return Err(corrupt("Released namespace still exists")),
            _ => {}
        }
    }
    Ok(())
}
