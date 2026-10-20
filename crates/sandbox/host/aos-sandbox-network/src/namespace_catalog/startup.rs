//! Owns first-local namespace catalog replay, fixed pin root and boot census.
//!
//! Saved-descriptor restart and historical BSA inventory checkpoint recovery
//! remain closed in this selected first-local entrance. Ordinary recovery keeps
//! its existing recipe. No empty activation object is reconstructed from DATA.

use super::*;
use crate::journal::NetworkNamespaceCapturedJournalOpenV4;
use aos_sandbox_broker::receiving::{FixedServiceOperationClosedV4 as Closed,
    FixedServiceReceivingCaptureV1 as Common};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::boot::RootOriginalKernelBootIdAttemptV1;
use crate::service_original::journal::{NetworkJournalOriginalV4,
    NetworkJournalStartupErrorV4, reached_rows_v4};

type Models = (u64, BTreeMap<[u8; 32], NamespaceRecordV1>, Option<checkpoint::InventoryBsaCheckpointHeadV2>);

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error(transparent)]
    Native(#[from] NetworkJournalStartupErrorV4),
    #[error(transparent)]
    Catalog(#[from] NetworkNamespaceCatalogError),
    #[error(transparent)]
    Accounting(#[from] aos_sandbox_model::AccountingError),
    #[error(transparent)]
    Encoding(#[from] canonical_map::CanonicalMapReceivingErrorV1),
    #[error(transparent)]
    Append(#[from] crate::journal::JournalAppendReceivingDemandErrorV1),
    #[error("the actual first-local namespace startup remains closed")]
    Closed,
}

pub(crate) struct NetworkNamespaceCatalogOpeningOriginalV4 {
    native: NetworkJournalOriginalV4<NetworkNamespaceCapturedJournalOpenV4>,
    boot: RootOriginalKernelBootIdAttemptV1,
    pin_root: NetworkPinRootOpeningOriginalV4,
    root: Option<PinRoot>,
    boot_id: Option<[u8; 16]>,
    invocation: Option<Result<[u8; 16], Closed>>,
    model: Option<Result<Models, NetworkNamespaceCatalogError>>,
    census: Vec<NetworkPinObservationOriginalV4>,
    returned: Option<Result<(), StartupError>>,
    funding: [Option<Result<(), Closed>>; 2],
    original_selected: bool,
    boot_failed: bool,
    entered: bool,
}

impl NetworkNamespaceCatalogOpeningOriginalV4 {
    pub(crate) fn new() -> Self {
        Self { native: NetworkJournalOriginalV4::new(), boot: RootOriginalKernelBootIdAttemptV1::new(),
            pin_root: NetworkPinRootOpeningOriginalV4::new(), root: None, boot_id: None,
            invocation: None, model: None, census: Vec::new(), returned: None,
            funding: std::array::from_fn(|_| None), original_selected: false, boot_failed: false, entered: false }
    }

    pub(crate) fn capture_once_v4(&mut self, common: &mut Common<Closed>) -> Result<(), Closed> {
        if self.entered { return Err(Closed); }
        self.entered = true;
        self.returned = Some(self.capture_inner(common));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(Closed) }
    }

    fn capture_inner(&mut self, common: &mut Common<Closed>) -> Result<(), StartupError> {
        self.native.open_once_v4(common, namespace_journal_limits(), model_demand_v4)?;
        let boot = RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(StartupError::Closed)?;
        let fixed = NetworkPinRootOpeningOriginalV4::receiving_demand_v4().ok_or(StartupError::Closed)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, boot).with(D::OpenFiles, 1))?;
        self.admit_v4(common, fixed, 0)?;
        self.invocation = Some(common.network_startup_invocation_data_v4());
        if !matches!(self.invocation, Some(Ok(_))) {
            self.original_selected = true;
            return Err(StartupError::Closed);
        }
        match self.boot.observe_once() {
            Ok(boot) => self.boot_id = Some(boot.into_bytes()),
            Err(_) => { self.boot_failed = true; return Err(StartupError::Closed); }
        }
        self.pin_root.open_once_v4()?;
        self.root = self.pin_root.take_completed_once_v4();
        let journal = self.native.journal_v4().ok_or(StartupError::Closed)?;
        // This private entrance has no saved namespace-tail owner. Refuse
        // historical BSA checkpoint graphs before their semantic decoder.
        if journal.records(RecordNamespace::NetworkResourceInventory)
            .any(|(key, _)| checkpoint::is_key(key)) {
            return Err(StartupError::Closed);
        }
        let head = CatalogHeadV1 { generation: 1 };
        let encoding = canonical_map::head_encoding_demand_v1(&head, HEAD_FORMAT_VERSION)?;
        let payload = usize::try_from(encoding.get(D::MemoryBytes)).map_err(|_| StartupError::Closed)?;
        let append = journal.append_receiving_demand_v1(std::iter::once(
            aos_sandbox_journal::geometry::RecordShape { key_bytes: HEAD_KEY.len(), value_bytes: Some(payload) }))?;
        self.admit_v4(common, encoding.checked_add(append)?, 1)?;
        let journal = self.native.journal_mut_v4().ok_or(StartupError::Closed)?;
        self.model = Some(recover_models_v4(journal));
        let (_, records, _) = self.model.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(StartupError::Closed)?;
        let root = self.root.as_ref().ok_or(StartupError::Closed)?;
        let boot = self.boot_id.ok_or(StartupError::Closed)?;
        for record in records.values() {
            // The actual Common proves no inherited saved-descriptor tail;
            // the selected Store separately proves fresh manager inventory
            // empty. A durable current live row needs restart custody instead.
            if record.kernel_boot_id == boot && !matches!(record.lifecycle, NamespaceLifecycleV1::Retired) {
                return Err(StartupError::Closed);
            }
            if matches!(record.lifecycle, NamespaceLifecycleV1::Retired) {
                self.census.push(NetworkPinObservationOriginalV4::new());
                let original = self.census.last_mut().ok_or(StartupError::Closed)?;
                root.ensure_absent_retaining_v4(&record.network_handle, original)?;
            }
        }
        Ok(())
    }

    fn admit_v4(&mut self, common: &mut Common<Closed>, demand: ResourceVector, slot: usize)
        -> Result<(), StartupError> {
        self.funding[slot] = Some(common.require_additional_startup_representation_v4(demand));
        if !matches!(self.funding[slot], Some(Ok(()))) {
            self.original_selected = true;
            return Err(StartupError::Closed);
        }
        Ok(())
    }

    pub(crate) fn take_completed_once_v4(&mut self) -> Option<NetworkNamespaceCatalogV1> {
        if !matches!(self.returned, Some(Ok(()))) || !matches!(self.model, Some(Ok(_))) { return None; }
        let journal = self.native.take_journal_v4()?;
        let pin_root = self.root.take()?;
        let kernel_boot_id = self.boot_id?;
        let broker_instance_id = self.invocation.as_ref()?.as_ref().ok().copied()?;
        let Some(Ok((generation, records, checkpoint_head))) = self.model.take() else { std::process::abort() };
        Some(NetworkNamespaceCatalogV1 { journal, pin_root, kernel_boot_id, broker_instance_id,
            generation, records, checkpoint_head })
    }

    pub(crate) fn original_failure_selected_v4(&self) -> bool {
        self.original_selected || self.native.original_failure_selected_v4()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.failure()
            .or_else(|| self.boot_failed.then(|| self.boot.failure()).flatten())
            .or_else(|| self.pin_root.failure())
            .or_else(|| self.model.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.census.iter().find_map(NetworkPinObservationOriginalV4::failure))
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

fn model_demand_v4(extent: &crate::journal::ProtectedJournalPreopenReplayExtentV1)
    -> Result<ResourceVector, NetworkJournalStartupErrorV4> {
    let closed = || NetworkJournalStartupErrorV4::Closed;
    let rows = reached_rows_v4(extent)?;
    let node = size_of::<NamespaceRecordV1>().checked_add(size_of::<AssignmentWire>())
        .and_then(|bytes| bytes.checked_add(size_of::<CatalogBindingWire>()))
        .and_then(|bytes| bytes.checked_add(8 * size_of::<Vec<u8>>())).ok_or_else(closed)?;
    let raw = usize::try_from(extent.native_bytes).ok()
        .and_then(|bytes| bytes.checked_mul(node.checked_mul(4)?))
        .and_then(|bytes| bytes.checked_add(MAXIMUM_RECORD_BYTES * 8)).ok_or_else(closed)?;
    // Catalog plus request/assignment/physical uniqueness maps. The complete
    // retained pin census is a separately owned native/model contribution.
    let maps = aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1::<[u8; 32], NamespaceRecordV1>(rows)
        .and_then(|bytes| bytes.checked_mul(4)).ok_or_else(closed)?;
    let demand = ResourceVector::ZERO.with(D::MemoryBytes,
        u64::try_from(raw.checked_add(maps).ok_or_else(closed)?).map_err(|_| closed())?)
        .with(D::MetadataEntries, u64::try_from(rows.checked_mul(4).ok_or_else(closed)?)
            .map_err(|_| closed())?);
    demand.checked_add(NetworkPinObservationOriginalV4::receiving_demand_v4(rows).ok_or_else(closed)?)
        .map_err(Into::into)
}

impl NetworkNamespaceCatalogOpeningOriginalV4 {
    pub(crate) fn inventory_currentness_demand_v2(&self)
        -> std::result::Result<ResourceVector, crate::journal::JournalError>
    {
        self.native.inventory_currentness_demand_v2()
    }

    pub(crate) fn inventory_currentness_before_v2(&self, journal: &Journal,
        original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> std::result::Result<(), crate::journal::JournalError> {
        self.native.inventory_currentness_before_v2(journal, original)
    }

    pub(crate) fn inventory_currentness_after_owed_v2(&self, journal: &Journal,
        original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> std::result::Result<(), crate::journal::JournalError> {
        self.native.inventory_currentness_after_owed_v2(journal, original)
    }
}
