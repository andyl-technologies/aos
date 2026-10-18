//! Retains the actual fixed-three cold graphs beyond archive validation.
//!
//! The cache owns the same archive and Source allocations. Staging borrows the
//! original data only while the existing grouped constructor runs; its Drop
//! moves every initialized or partial owning field into this cache. No borrowed
//! ArchivedOwnerData, construction-demand scalar or reconstructed alias label
//! substitutes for actual retained backing.

use super::*;
use crate::node_contract::RuntimeError;
use crate::node_state::CompleteOriginalRestorationSource;
use std::{
    cell::{Cell, OnceCell, Ref, RefCell},
    rc::Rc,
};

/// Retains actual grouped cold outputs beneath one genuine restoration action.
///
/// This is private construction custody, not an archive or target capability.
/// The installed window must precharge the complete inline Option/root, static
/// counters and actual prospective construction before staging starts. Source3
/// allocation rows are counted independently by that same window.
pub(crate) struct OriginalRestorationColdGroup {
    process: u32,
    thread: ThreadId,
    archive: CompleteOriginalRestorationSource,
    sources: [Rc<PacketCompleteSemanticSource>; 3],
    owners: [Option<RetainedColdOwner>; 3],
    staging_started: bool,
    staging_finished: bool,
    import_release: Cell<ImportReleaseStage>,
}

/// Lends exact decoder-produced owners without a live authority conversion.
pub(crate) struct OriginalRestorationColdOwnerView<'a> {
    pub(crate) source: &'a PacketCompleteSemanticSource,
    pub(crate) owner: &'a NativeOwnerState,
    pub(crate) journal: &'a PacketCompleteSettledJournal,
    pub(crate) host: &'a SealedHistoricalControllerState,
    pub(crate) native_before: Ref<'a, SealedHistoricalNativeState>,
    pub(crate) native_after: Ref<'a, SealedHistoricalNativeState>,
    pub(crate) registry: Ref<'a, SealedHistoricalHostExtensionRegistry>,
}

struct RetainedColdOwner {
    association_valid: bool,
    owner_index: Option<usize>,
    journal_index: Option<usize>,
    snapshot_class: CompleteNativeSnapshotClass,
    journal: Option<PacketCompleteSettledJournal>,
    host_limits: OwnedProtocol11DataLimits,
    native_limits: OwnedProtocol11DataLimits,
    before_limits: OwnedProtocol11DataLimits,
    registry_limits: OwnedProtocol11DataLimits,
    maximum: usize,
    journal_storage: usize,
    host_aliases: Vec<HistoricalAliasSummary>,
    native_aliases: Vec<HistoricalAliasSummary>,
    before_aliases: Vec<HistoricalAliasSummary>,
    registry_aliases: Vec<HistoricalAliasSummary>,
    before_reference: Option<ContentRef>,
    before_raw: Vec<u8>,
    before_encoded: Option<Vec<u8>>,

    host_encoded: Option<Vec<u8>>,
    native_encoded: Option<Vec<u8>>,
    registry_encoded: Option<Vec<u8>>,

    host: Option<SealedHistoricalControllerState>,

    known_requested: Option<usize>,
    native_restoration_demand: Option<crucible_node_provider::protocol_snapshot::owned11::native::outer::NativeOwnedProtocol11AllocationDemand>,
    attempted: bool,
    failed: bool,
    decoded: RefCell<DecodedImportOwners>,
    installed_boundary: OnceCell<InstalledImportBoundary>,
}

struct ColdSigningView<'a> {
    source: &'a PacketCompleteSemanticSource,
    owner: &'a NativeOwnerState,
    journal: &'a PacketCompleteSettledJournal,
    host: &'a SealedHistoricalControllerState,
}

/// Moves all actual cold results into their preinstalled root during unwinding.
///
/// Its destructor performs only fixed field moves. Partial decoders and failed
/// output banks remain owned even when the grouped constructor returns early.
pub(crate) struct ColdGroupStaging<'cache, 'input> {
    cache: &'cache mut OriginalRestorationColdGroup,
    slots: [Option<PacketCompleteArchivedOwnerData<'input>>; 3],
    finished: bool,
}

impl OriginalRestorationColdGroup {
    pub(crate) fn retain_originals_into(
        archive: &CompleteOriginalRestorationSource,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        output: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        archive.inner.authenticate_birth()?;
        if output.is_some()
            || (0..3)
                .any(|index| (0..index).any(|prior| Rc::ptr_eq(&sources[index], &sources[prior])))
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        // These clones add fixed strong handles to the same allocations. They
        // allocate no replacement archive, Source, content bank or protocol graph.
        *output = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            archive: CompleteOriginalRestorationSource {
                inner: Rc::clone(&archive.inner),
            },
            sources: std::array::from_fn(|index| Rc::clone(&sources[index])),
            owners: std::array::from_fn(|_| None),
            staging_started: false,
            staging_finished: false,
            import_release: Cell::new(ImportReleaseStage::Retained),
        });
        Ok(())
    }

    pub(crate) fn begin_staging<'cache, 'input>(
        &'cache mut self,
    ) -> Result<ColdGroupStaging<'cache, 'input>, RuntimeError> {
        self.origin()?;
        if self.staging_started || self.owners.iter().any(Option::is_some) {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.staging_started = true;
        Ok(ColdGroupStaging {
            cache: self,
            slots: std::array::from_fn(|_| None),
            finished: false,
        })
    }

    /// Runs the existing fixed-three constructor under the enclosing window.
    ///
    /// All originals and this root must already be retained and fully admitted.
    /// This private method consumes no replacement ticket and performs no target,
    /// MAC, protocol publication or final-context issuance. Every partial output
    /// transfers into this cache before an error or unwind reaches its caller.
    pub(crate) fn construct_original_group<'input>(
        &mut self,
        inputs: &'input crate::node_admission::OriginalRestorationConstructionInputs<'input>,
        additional_retained_bytes: usize,
    ) -> Result<(), RuntimeError> {
        self.origin()?;
        inputs.authenticate_original_group_data()?;
        if !Rc::ptr_eq(&self.archive.inner, &inputs.archive.inner)
            || (0..3).any(|index| !Rc::ptr_eq(&self.sources[index], &inputs.sources[index]))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let runtime = inputs.archive.original_runtime_record_data()?;
        let limits = inputs.archive.original_archive_limits_data()?;
        let mut staging = self.begin_staging()?;
        let mut prepared = additional_retained_bytes;
        for index in 0..3 {
            let ticket = inputs.tickets[index];
            let owner = ticket.owner()?;
            let journal = inputs.journals[index];
            if !owner.evidence.contains(journal) {
                return Err(RuntimeError::InvalidReceipt);
            }
            inputs.sources[index]
                .prepare_complete_archived_owner_data_into(
                    owner,
                    runtime,
                    inputs.archive.runtime_object(),
                    inputs.archive.content(),
                    journal,
                    limits,
                    prepared,
                    &mut staging.slots()[index],
                )
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            let bytes = staging.slots()[index]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?
                .retained_data_bank_bytes()
                .map_err(|_| RuntimeError::ResourceLimit)?;
            prepared = prepared
                .checked_add(bytes)
                .ok_or(RuntimeError::ResourceLimit)?;
        }
        PacketCompleteArchivedOwnerData::reconstruct_group(
            staging.slots(),
            additional_retained_bytes,
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        staging.finish()
    }

    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.archive.inner.authenticate_birth()
    }

    /// Lends one same-ticket complete original after successful grouped reconstruction.
    ///
    /// This inert loan does not authenticate a live peer or permit a signer.
    /// The action independently checks its actual source/member/currentness.
    fn original_signing_owner_data(
        &self,
        index: usize,
        source: &Rc<PacketCompleteSemanticSource>,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
    ) -> Result<ColdSigningView<'_>, RuntimeError> {
        self.origin()?;
        ticket.authenticate_source(&self.archive)?;
        let original_source = self
            .sources
            .get(index)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let retained = self
            .owners
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !self.staging_finished
            || !retained.association_valid
            || !retained.attempted
            || retained.failed
            || !Rc::ptr_eq(source, original_source)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let owner = self
            .archive
            .archive()
            .owners()
            .get(retained.owner_index.ok_or(RuntimeError::ForeignAuthority)?)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !std::ptr::eq(owner, ticket.owner()?) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let journal = retained
            .journal
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let journal_reference = owner
            .evidence
            .get(
                retained
                    .journal_index
                    .ok_or(RuntimeError::ForeignAuthority)?,
            )
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if self.archive.content().get(journal_reference).is_none() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        let view = ColdSigningView {
            source: original_source,
            owner,
            journal,
            host: retained
                .host
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
        };
        view.host
            .historical()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        self.origin()?;
        Ok(view)
    }

    pub(crate) fn original_owner_data(
        &self,
        index: usize,
        source: &Rc<PacketCompleteSemanticSource>,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
    ) -> Result<OriginalRestorationColdOwnerView<'_>, RuntimeError> {
        let stable = self.original_signing_owner_data(index, source, ticket)?;
        let retained = self.owners[index]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let decoded = retained
            .decoded
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let before = Ref::filter_map(Ref::clone(&decoded), |owners| owners.before.as_ref())
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        let native = Ref::filter_map(Ref::clone(&decoded), |owners| owners.native.as_ref())
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        let registry = Ref::filter_map(decoded, |owners| owners.registry.as_ref())
            .map_err(|_| RuntimeError::OwnerUnavailable)?;
        before
            .historical()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        native
            .historical()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        registry
            .historical()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(OriginalRestorationColdOwnerView {
            source: stable.source,
            owner: stable.owner,
            journal: stable.journal,
            host: stable.host,
            native_before: before,
            native_after: native,
            registry,
        })
    }

    /// Borrows the same completed cold originals for a Source construction quote.
    ///
    /// This DATA loan issues no transaction claim. The caller separately funds
    /// cold reconstruction before this call and the complete installed window
    /// before a Source effect. The actual index constructor retains its own
    /// archive cap; its all-other-retained term cannot be replaced by zero.
    pub(crate) fn original_signing_construction_inputs_data<'a>(
        &'a self,
        inputs: &'a crate::node_admission::OriginalRestorationConstructionInputs<'a>,
        plan: &'a crate::node_admission::InstalledConformancePlan,
        native: &'a crate::node_admission::OriginalRestorationNodeConstructionData,
        controller: &'a crucible_node_provider::client::CnpController,
        query: &'a crucible_node_provider::client::OriginalFreshRestoreQuery,
        maximum_mapping_bytes: usize,
        maximum_record_bytes: usize,
        observed_other_retained_bytes: usize,
    ) -> Result<crate::node_admission::OriginalRestorationSigningConstructionInputs<'a>, RuntimeError>
    {
        inputs.authenticate_original_group_data()?;
        if !Rc::ptr_eq(&self.archive.inner, &inputs.archive.inner)
            || maximum_mapping_bytes == 0
            || maximum_record_bytes == 0
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        native.authenticate_original_source_data(inputs.source)?;
        let cold =
            self.original_signing_owner_data(inputs.selected, inputs.source, inputs.ticket)?;
        let host = cold
            .host
            .historical()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        // The completed grouped constructor already authenticated this exact
        // immutable journal/Host/native transcript. This raw loan neither
        // reparses frames nor repeats its allocating validation phases.
        let terminal = host
            .custody
            .controller
            .get(&cold.journal.confirmation.capture.capture_request_id)
            .and_then(|pair| pair.response.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let retained = self.owners[inputs.selected]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let journal_reference = cold
            .owner
            .evidence
            .get(
                retained
                    .journal_index
                    .ok_or(RuntimeError::ForeignAuthority)?,
            )
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if journal_reference != inputs.journal {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.origin()?;
        Ok(
            crate::node_admission::OriginalRestorationSigningConstructionInputs {
                source: inputs.source,
                archive: inputs.archive,
                ticket: inputs.ticket,
                controller,
                query,
                binding_quote: &native.prepare_binding,
                plan,
                activation: inputs.activation,
                launch: inputs.launch,
                journal: cold.journal,
                journal_reference,
                capture_terminal: terminal,
                native_allocation: &native.native_allocation,
                prepare_id: inputs.prepare_id,
                commit_id: inputs.commit_id,
                maximum_mapping_bytes,
                maximum_record_bytes,
                observed_other_retained_bytes,
            },
        )
    }

    pub(crate) fn original_restoration_references_data<'a>(
        &'a self,
        index: usize,
        source: &Rc<PacketCompleteSemanticSource>,
        ticket: &crate::node_state::CompleteOriginalNativeTicket,
    ) -> Result<[&'a ContentRef; 5], RuntimeError> {
        let cold = self.original_signing_owner_data(index, source, ticket)?;
        let retained = self.owners[index]
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let journal_reference = cold
            .owner
            .evidence
            .get(
                retained
                    .journal_index
                    .ok_or(RuntimeError::ForeignAuthority)?,
            )
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let references = [
            &cold.journal.native_after_protocol,
            &cold.journal.native_control,
            &cold.journal.native_anchor,
            &cold.owner.state,
            journal_reference,
        ];
        ticket
            .native_restoration_construction_data()?
            .authenticate_original_references_data(references)?;
        Ok(references)
    }

    pub(crate) fn original_signing_inputs_data<'a>(
        &'a self,
        index: usize,
        source: &'a Rc<PacketCompleteSemanticSource>,
        ticket: &'a crate::node_state::CompleteOriginalNativeTicket,
        plan: &'a crate::node_admission::InstalledConformancePlan,
        activation: &'a crate::node_contract::ActivationRecord,
        mapping: &'a crucible_node_provider::protocol_snapshot::PreparedArchivedProtocolMapping,
        native: &'a crate::node_admission::OriginalRestorationNodeConstructionData,
        prepare_id: &'a Id,
        commit_id: &'a Id,
        maximum_record_bytes: usize,
        observed_other_retained_bytes: usize,
    ) -> Result<crate::node_admission::OriginalRestorationSigningInputs<'a>, RuntimeError> {
        native.authenticate_original_source_data(source)?;
        let cold = self.original_signing_owner_data(index, source, ticket)?;
        let references = self.original_restoration_references_data(index, source, ticket)?;
        let host = cold
            .host
            .historical()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let capture_terminal = host
            .custody
            .controller
            .get(&cold.journal.confirmation.capture.capture_request_id)
            .and_then(|pair| pair.response.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        Ok(crate::node_admission::OriginalRestorationSigningInputs {
            source,
            archive: &self.archive,
            ticket,
            plan,
            activation,
            journal: cold.journal,
            journal_reference: references[4],
            capture_terminal,
            mapping,
            native_allocation: &native.native_allocation,
            prepare_id,
            commit_id,
            maximum_record_bytes,
            observed_other_retained_bytes,
        })
    }

    /// Counts actual nested backing, including failed/partially decoded owners.
    ///
    /// The containing Option/root is a separate term. Source3 backing must be
    /// counted by the same installed conjunction; this method retains those
    /// same strong handles and counts the exact archive backing conservatively.
    pub(crate) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        self.origin()?;
        let mut total = self.archive.inner.capture_owned_storage()?;
        for owner in self.owners.iter().flatten() {
            add(&mut total, owner.retained_storage_data(maximum)?, maximum)?;
        }
        self.origin()?;
        if total > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(total)
    }

    /// Reports the actual inline root required in the containing window's census.
    pub(crate) fn inline_root_storage_data() -> usize {
        size_of::<Option<Self>>()
    }

    /// Names fixed raw-view/counter work before walking the first sealed graph.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<[usize; 8]>()
            .saturating_add(Self::installed_import_counter_scratch_data())
            .saturating_add(size_of::<OriginalRestorationColdOwnerView<'static>>())
            .saturating_add(size_of::<crate::node_admission::OriginalRestorationSigningInputs<'static>>())
            .saturating_add(size_of::<Result<crate::node_admission::OriginalRestorationSigningInputs<'static>, RuntimeError>>())
            .saturating_add(size_of::<[&ContentRef; 5]>())
            .saturating_add(size_of::<Result<[&ContentRef; 5], RuntimeError>>())
            .saturating_add(size_of::<crate::node_admission::OriginalRestorationSigningConstructionInputs<'static>>())
            .saturating_add(size_of::<Result<crate::node_admission::OriginalRestorationSigningConstructionInputs<'static>, RuntimeError>>())
            .saturating_add(size_of::<&HistoricalControllerState>())
            .saturating_add(size_of::<&crucible_node_provider::envelope::Envelope>())
            .saturating_add(size_of::<ColdGroupStaging<'static, 'static>>())
            .saturating_add(size_of::<[&Id; 4]>())
            .saturating_add(size_of::<[&crucible_node_contract::HashRef; 2]>())
            .saturating_add(size_of::<[&ContentRef; 13]>())
            .saturating_add(size_of::<std::slice::Iter<'static, Option<RetainedColdOwner>>>())
            .saturating_add(size_of::<std::slice::Iter<'static, Id>>())
            // Arrays above retain their source slots; these actual cursors also
            // own front/back/chain state while the corresponding walk runs.
            .saturating_add(size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<RetainedColdOwner>>>>())
            .saturating_add(size_of::<std::array::IntoIter<&'static Vec<HistoricalAliasSummary>, 4>>())
            .saturating_add(size_of::<std::iter::Flatten<std::array::IntoIter<&'static Option<Vec<u8>>, 4>>>())
            .saturating_add(size_of::<std::iter::Flatten<std::array::IntoIter<&'static Option<SealedHistoricalNativeState>, 2>>>())
            .saturating_add(size_of::<std::array::IntoIter<&'static String, 3>>())
            .saturating_add(size_of::<std::array::IntoIter<&'static crucible_node_contract::HashRef, 2>>())
            .saturating_add(size_of::<std::iter::Chain<std::slice::Iter<'static, Id>, std::array::IntoIter<&'static Id, 4>>>())
            .saturating_add(size_of::<std::iter::Chain<std::array::IntoIter<&'static ContentRef, 13>, std::option::Iter<'static, ContentRef>>>())
            .saturating_add(2 * size_of::<std::ops::Range<usize>>())
            .saturating_add(size_of::<Result<crucible_node_provider::retained_metadata::RetainedProtocolMetadataFacts, crucible_node_provider::ProviderError>>())
            .saturating_add(size_of::<Result<usize, RuntimeError>>())
            .saturating_add(size_of::<Result<(), RuntimeError>>())
            .saturating_add(size_of::<crucible_node_provider::retained_metadata::RetainedProtocolMetadataFacts>())
            .saturating_add(SealedHistoricalControllerState::original_retained_metadata_counter_scratch_data())
            .saturating_add(SealedHistoricalNativeState::original_retained_metadata_counter_scratch_data())
            .saturating_add(SealedHistoricalHostExtensionRegistry::original_retained_metadata_counter_scratch_data())
    }
}

impl<'input> ColdGroupStaging<'_, 'input> {
    pub(crate) fn slots(&mut self) -> &mut [Option<PacketCompleteArchivedOwnerData<'input>>; 3] {
        &mut self.slots
    }

    pub(crate) fn finish(&mut self) -> Result<(), RuntimeError> {
        for index in 0..3 {
            let owner = self.slots[index]
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?;
            owner
                .ensure_complete()
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            if !RetainedColdOwner::matches(owner, &self.cache.archive, &self.cache.sources[index]) {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for ColdGroupStaging<'_, '_> {
    fn drop(&mut self) {
        for index in 0..3 {
            if let Some(owner) = self.slots[index].take() {
                self.cache.owners[index] = Some(RetainedColdOwner::retain(
                    owner,
                    &self.cache.archive,
                    &self.cache.sources[index],
                ));
            }
        }
        self.cache.staging_finished = self.finished;
    }
}

impl RetainedColdOwner {
    fn matches(
        owner: &PacketCompleteArchivedOwnerData<'_>,
        archive: &CompleteOriginalRestorationSource,
        source: &Rc<PacketCompleteSemanticSource>,
    ) -> bool {
        owner
            .source
            .is_some_and(|actual| std::ptr::eq(actual, source.as_ref()))
            && owner
                .content
                .same_data(ArchivedContentData::Verified(archive.content()))
            && archive
                .archive()
                .owners()
                .iter()
                .any(|candidate| std::ptr::eq(candidate, owner.owner))
    }

    fn retain(
        owner: PacketCompleteArchivedOwnerData<'_>,
        archive: &CompleteOriginalRestorationSource,
        expected_source: &Rc<PacketCompleteSemanticSource>,
    ) -> Self {
        let association_valid = Self::matches(&owner, archive, expected_source);
        let owner_index = archive
            .archive()
            .owners()
            .iter()
            .position(|candidate| std::ptr::eq(candidate, owner.owner));
        let journal_index = owner
            .owner
            .evidence
            .iter()
            .position(|reference| reference == owner.journal_reference);
        let PacketCompleteArchivedOwnerData {
            process: _,
            thread: _,
            source: _,
            owner: _,
            content: _,
            journal_reference: _,
            snapshot_class,
            journal,
            host_limits,
            native_limits,
            before_limits,
            registry_limits,
            maximum,
            journal_storage,
            host_aliases,
            native_aliases,
            before_aliases,
            registry_aliases,
            before_reference,
            before_raw,
            before_encoded,
            before,
            host_encoded,
            native_encoded,
            registry_encoded,
            registry,
            host,
            native,
            known_requested,
            native_restoration_demand,
            attempted,
            failed,
        } = owner;
        Self {
            association_valid,
            owner_index,
            journal_index,
            snapshot_class,
            journal,
            host_limits,
            native_limits,
            before_limits,
            registry_limits,
            maximum,
            journal_storage,
            host_aliases,
            native_aliases,
            before_aliases,
            registry_aliases,
            before_reference,
            before_raw,
            before_encoded,
            host_encoded,
            native_encoded,
            registry_encoded,
            host,
            known_requested,
            native_restoration_demand,
            attempted,
            failed,
            decoded: RefCell::new(DecodedImportOwners {
                before,
                native,
                registry,
            }),
            installed_boundary: OnceCell::new(),
        }
    }

    fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Self {
            association_valid: _,
            owner_index: _,
            journal_index: _,
            snapshot_class: _,
            journal,
            host_limits: _,
            native_limits: _,
            before_limits: _,
            registry_limits: _,
            maximum: _,
            journal_storage: _,
            host_aliases,
            native_aliases,
            before_aliases,
            registry_aliases,
            before_reference,
            before_raw,
            before_encoded,
            host_encoded,
            native_encoded,
            registry_encoded,
            host,
            known_requested: _,
            native_restoration_demand: _,
            attempted: _,
            failed: _,
            decoded,
            installed_boundary: _,
        } = self;
        let decoded = decoded.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        let DecodedImportOwners {
            before,
            native,
            registry,
        } = &*decoded;
        let mut total = 0usize;
        for aliases in [
            host_aliases,
            native_aliases,
            before_aliases,
            registry_aliases,
        ] {
            add(
                &mut total,
                aliases
                    .capacity()
                    .checked_mul(size_of::<HistoricalAliasSummary>())
                    .ok_or(RuntimeError::ResourceLimit)?,
                maximum,
            )?;
        }
        add(&mut total, before_raw.capacity(), maximum)?;
        for encoded in [
            before_encoded,
            host_encoded,
            native_encoded,
            registry_encoded,
        ]
        .into_iter()
        .flatten()
        {
            add(&mut total, encoded.capacity(), maximum)?;
        }
        if let Some(reference) = before_reference {
            add(
                &mut total,
                NodeRuntime::capture_reference_storage(reference)?,
                maximum,
            )?;
        }
        if let Some(journal) = journal {
            add(&mut total, journal_storage_data(journal, maximum)?, maximum)?;
        }
        for graph in [before, native].into_iter().flatten() {
            let facts = graph
                .original_retained_metadata_facts()
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            add(
                &mut total,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                    &facts, maximum,
                )?,
                maximum,
            )?;
        }
        if let Some(graph) = host {
            let facts = graph
                .original_retained_metadata_facts()
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            add(
                &mut total,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                    &facts, maximum,
                )?,
                maximum,
            )?;
        }
        if let Some(graph) = registry {
            let facts = graph
                .original_retained_metadata_facts()
                .map_err(|_| RuntimeError::OwnerUnavailable)?;
            add(
                &mut total,
                PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                    &facts, maximum,
                )?,
                maximum,
            )?;
        }
        Ok(total)
    }
}

fn add(total: &mut usize, bytes: usize, maximum: usize) -> Result<(), RuntimeError> {
    *total = total
        .checked_add(bytes)
        .filter(|n| *n <= maximum)
        .ok_or(RuntimeError::ResourceLimit)?;
    Ok(())
}

fn journal_storage_data(
    journal: &PacketCompleteSettledJournal,
    maximum: usize,
) -> Result<usize, RuntimeError> {
    use crucible_node_provider::reference_packet::service::confirmation::{
        PacketNativeAfterConfirmationReceipt, PacketNativeAfterConfirmationRequest,
    };
    let PacketCompleteSettledJournal {
        schema,
        owner,
        participants,
        cut: _,
        ordinal: _,
        runtime,
        backend_implementation,
        semantic,
        ancestry,
        native_snapshot,
        native_control,
        native_anchor,
        native_after_protocol,
        host_protocol,
        host_extension_registry,
        confirmation_request,
        confirmation,
    } = journal;
    let PacketNativeAfterConfirmationReceipt {
        schema: receipt_schema,
        capture,
        native_after_ref,
        native_after_capacity: _,
    } = confirmation;
    let PacketNativeAfterConfirmationRequest {
        schema: request_schema,
        capture_request_id,
        capture_request_hash,
        capture_operation_id,
        capture_terminal_hash,
        capture_terminal_sequence: _,
        native_snapshot_ref,
        native_control_ref,
        native_anchor_ref,
    } = capture;
    let mut total = 0usize;
    for text in [schema, receipt_schema, request_schema] {
        add(&mut total, text.capacity(), maximum)?;
    }
    add(
        &mut total,
        participants
            .capacity()
            .checked_mul(size_of::<Id>())
            .ok_or(RuntimeError::ResourceLimit)?,
        maximum,
    )?;
    for id in participants.iter().chain([
        owner,
        confirmation_request,
        capture_request_id,
        capture_operation_id,
    ]) {
        add(&mut total, id.allocated_capacity(), maximum)?;
    }
    for reference in [
        runtime,
        backend_implementation,
        semantic,
        ancestry,
        native_snapshot,
        native_control,
        native_anchor,
        native_after_protocol,
        host_protocol,
        native_after_ref,
        native_snapshot_ref,
        native_control_ref,
        native_anchor_ref,
    ]
    .into_iter()
    .chain(host_extension_registry.iter())
    {
        add(
            &mut total,
            NodeRuntime::capture_reference_storage(reference)?,
            maximum,
        )?;
    }
    for hash in [capture_request_hash, capture_terminal_hash] {
        add(
            &mut total,
            NodeRuntime::capture_hash_storage(hash)?,
            maximum,
        )?;
    }
    Ok(total)
}

#[path = "retained/installed_import.rs"]
mod installed_import;
use installed_import::{DecodedImportOwners, ImportReleaseStage, InstalledImportBoundary};
