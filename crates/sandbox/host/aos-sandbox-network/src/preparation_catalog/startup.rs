//! Retains preparation policy, canonical replay and protected head append.

use super::*;
use crate::journal::NetworkPreparationCapturedJournalOpenV4;
use aos_sandbox_broker::receiving::{FixedServiceOperationClosedV4 as Closed,
    FixedServiceReceivingCaptureV1 as Common};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use crate::service_original::journal::{NetworkJournalOriginalV4,
    NetworkJournalStartupErrorV4, reached_rows_v4};

type Models = (BTreeMap<[u8; 32], PreparationRecordV1>, BTreeMap<[u8; 32], NetworkNamespacePlanV1>);

#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error(transparent)]
    Journal(#[from] NetworkJournalStartupErrorV4),
    #[error(transparent)]
    Catalog(#[from] NetworkPreparationCatalogError),
    #[error(transparent)]
    Encoding(#[from] canonical_map::CanonicalMapReceivingErrorV1),
    #[error(transparent)]
    Append(#[from] crate::journal::JournalAppendReceivingDemandErrorV1),
    #[error(transparent)]
    Geometry(#[from] aos_sandbox_model::AccountingError),
    #[error("the actual preparation startup remains closed")]
    Closed,
}

pub(crate) struct NetworkPreparationOpeningOriginalV4 {
    native: NetworkJournalOriginalV4<NetworkPreparationCapturedJournalOpenV4>,
    policy: Option<NetworkPolicyCatalogV1>,
    model: Option<Result<Models, NetworkPreparationCatalogError>>,
    returned: Option<Result<(), StartupError>>,
    head_funding: Option<Result<(), Closed>>,
    original_selected: bool,
    entered: bool,
}

impl NetworkPreparationOpeningOriginalV4 {
    pub(crate) fn new() -> Self {
        Self { native: NetworkJournalOriginalV4::new(), policy: None, model: None,
            returned: None, head_funding: None, original_selected: false, entered: false }
    }

    pub(crate) fn capture_once_v4(&mut self, common: &mut Common<Closed>,
        policy: NetworkPolicyCatalogV1, minimum_generation: u64) -> Result<(), Closed> {
        if self.entered { return Err(Closed); }
        self.entered = true;
        self.policy = Some(policy);
        self.returned = Some(self.capture_inner(common, minimum_generation));
        if matches!(self.returned, Some(Ok(()))) { Ok(()) } else { Err(Closed) }
    }

    fn capture_inner(&mut self, common: &mut Common<Closed>, minimum_generation: u64)
        -> Result<(), StartupError> {
        self.native.open_once_v4(common, preparation_journal_limits(), model_demand_v4)?;
        let policy = self.policy.as_ref().ok_or(StartupError::Closed)?;
        let journal = self.native.journal_v4().ok_or(StartupError::Closed)?;
        let head = CatalogHeadV1 { node: *policy.node().as_bytes(),
            generation: policy.generation(), digest: *policy.digest().as_bytes() };
        let encoding = canonical_map::head_encoding_demand_v1(&head, RECORD_FORMAT_VERSION)?;
        // The same allocation-free serializer's Memory bound dominates the
        // exact head payload. Forecast the real captured append before the
        // ordinary recovery engine may initialize or advance that head.
        let payload_bound = usize::try_from(encoding.get(D::MemoryBytes)).map_err(|_| StartupError::Closed)?;
        let append = journal.append_receiving_demand_v1(std::iter::once(
            aos_sandbox_journal::geometry::RecordShape { key_bytes: HEAD_KEY.len(), value_bytes: Some(payload_bound) }))?;
        self.head_funding = Some(common.require_additional_startup_representation_v4(encoding.checked_add(append)?));
        if !matches!(self.head_funding, Some(Ok(()))) {
            self.original_selected = true;
            return Err(StartupError::Closed);
        }
        let policy = self.policy.as_ref().ok_or(StartupError::Closed)?;
        let journal = self.native.journal_mut_v4().ok_or(StartupError::Closed)?;
        self.model = Some(recover_models_v4(journal, policy, minimum_generation));
        if matches!(self.model, Some(Ok(_))) { Ok(()) } else { Err(StartupError::Closed) }
    }

    pub(crate) fn take_completed_once_v4(&mut self) -> Option<NetworkPreparationCatalogV1> {
        if !matches!(self.returned, Some(Ok(()))) || !matches!(self.model, Some(Ok(_))) { return None; }
        let journal = self.native.take_journal_v4()?;
        let policy = self.policy.take()?;
        let Some(Ok((records, plans))) = self.model.take() else { std::process::abort() };
        Some(NetworkPreparationCatalogV1 { journal, policy, records, plans })
    }

    pub(crate) fn original_failure_selected_v4(&self) -> bool {
        self.original_selected || self.native.original_failure_selected_v4()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.failure()
            .or_else(|| self.model.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.returned.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

fn model_demand_v4(extent: &crate::journal::ProtectedJournalPreopenReplayExtentV1)
    -> Result<ResourceVector, NetworkJournalStartupErrorV4> {
    let closed = || NetworkJournalStartupErrorV4::Closed;
    let rows = reached_rows_v4(extent)?;
    let node = std::mem::size_of::<PreparationRecordV1>()
        .checked_add(std::mem::size_of::<AllocationRecordV1>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<AllocationPolicyWireV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<IpPrefixWireV1>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<EndpointWire>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<NetworkNamespacePlanV1>()))
        .and_then(|bytes| bytes.checked_add(16 * std::mem::size_of::<Vec<u8>>())).ok_or_else(closed)?;
    let operand = usize::try_from(extent.native_bytes).map_err(|_| closed())?.min(MAXIMUM_RECORD_BYTES);
    let (core, core_names) = aos_sandbox_protocol::semantics::network::preparation_content::
        network_preparation_models_receiving_obligations_v2(operand, operand).ok_or_else(closed)?;
    let typed = usize::try_from(extent.native_bytes).ok()
        .and_then(|bytes| bytes.checked_mul(node.checked_mul(4)?))
        .and_then(|bytes| bytes.checked_add(core.checked_mul(rows)?))
        .and_then(|bytes| bytes.checked_add(MAXIMUM_RECORD_BYTES.checked_mul(8)?)).ok_or_else(closed)?;
    // Two owning maps plus assignment, generation, two interface, two MAC and
    // four IP uniqueness entries per allocation. Core's operand supplier adds
    // the actual source/feature/profile names reached by the nested models.
    let names = rows.checked_mul(12).and_then(|names| names.checked_add(core_names.checked_mul(rows)?))
        .ok_or_else(closed)?;
    use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
    let maps = nodes::<[u8; 32], (PreparationRecordV1, NetworkNamespacePlanV1)>(rows)
        .and_then(|bytes| bytes.checked_mul(12)).ok_or_else(closed)?;
    let memory = typed.checked_add(maps).and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(closed)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
        .with(D::MetadataEntries, u64::try_from(names).map_err(|_| closed())?))
}

impl NetworkPreparationOpeningOriginalV4 {
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
