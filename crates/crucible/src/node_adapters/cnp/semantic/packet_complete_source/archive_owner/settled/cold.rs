//! Retains genuine current17 decoded DATA beneath its same signed archive Source.
//!
//! These loans do not reconstruct old ColdGroup types or create live Hold,
//! Source, native registration, restoration scope or resumed grants.

use super::*;
use crate::node_adapters::cnp::{
    CnpRestoredSettledValidatedNode17, OriginalSourceRestoredSettled17Read,
};
use crate::node_contract::{HostSchedulingRestoredContinuationRecord17, RuntimeError};
use crate::node_state::{CompleteOriginalNativeTicket, CompleteOriginalRestorationSource};
use crucible_node_provider::protocol_snapshot::current_controller17::ValidatedControllerSettledHistory17;
use crucible_node_provider::protocol_snapshot::restored_settled17::{
    RestoredSettledNative17Input, SealedHistoricalRestoredSettledNative17,
};
use std::{rc::Rc, thread::ThreadId};

/// Keeps the actual selected historical family without a cross-family cast.
///
/// Its discriminant follows the signed archive key, not a future capability.
/// Constructors/admission and the distinct immutable readers remain mandatory.
pub(crate) enum OriginalCompleteHistoricalColdGroup {
    InitialInvocation15(super::super::OriginalRestorationColdGroup),
    Settled17(OriginalRestoredSettledColdGroup),
}

impl OriginalCompleteHistoricalColdGroup {
    pub(crate) fn historical_family_data(&self) -> CompleteHistoricalArchiveFamily {
        match self {
            Self::InitialInvocation15(_) => CompleteHistoricalArchiveFamily::InitialInvocation15,
            Self::Settled17(_) => CompleteHistoricalArchiveFamily::Settled17,
        }
    }

    /// Counts backing of the actual retained historical family without casting.
    ///
    /// # Errors
    /// Refuses the selected original owner's origin or checked retained bound.
    pub(crate) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        match self {
            Self::InitialInvocation15(group) => group.retained_storage_data(maximum),
            Self::Settled17(group) => group.retained_storage_data(maximum),
        }
    }

    pub(crate) fn inline_root_storage_data() -> usize {
        std::mem::size_of::<Option<Self>>()
    }

    /// Conjoins the real variant getters before the installed Window reads them.
    pub(crate) fn counter_scratch_data() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<&Self>()
            + std::mem::size_of::<CompleteHistoricalArchiveFamily>()
            + super::super::OriginalRestorationColdGroup::counter_scratch_data()
            + OriginalRestoredSettledColdGroup::counter_scratch_data()
    }
}

/// Retains only validated current17 owners from this exact completed signed load.
pub(crate) struct OriginalRestoredSettledColdGroup {
    process: u32,
    thread: ThreadId,
    archive: CompleteOriginalRestorationSource,
    sources: [Rc<PacketCompleteSemanticSource>; 3],
    collection: Option<crate::node_state::RetainedCold17Collection>,
}

/// Lends exact archived current DATA while the real caller retains its SourceRead.
pub(crate) struct OriginalRestoredSettledColdOwnerView<'a> {
    pub(crate) source: &'a PacketCompleteSemanticSource,
    pub(crate) owner: &'a NativeOwnerState,
    pub(crate) host: &'a HostSchedulingRestoredContinuationRecord17,
    pub(crate) native: &'a SealedHistoricalRestoredSettledNative17,
    pub(crate) controller: &'a ValidatedControllerSettledHistory17,
    pub(crate) node: &'a CnpRestoredSettledValidatedNode17,
    pub(crate) source_history: &'a OriginalSourceRestoredSettled17Read,
    pub(crate) input: RestoredSettledNative17Input<'a>,
}

impl OriginalRestoredSettledColdGroup {
    /// Retains the actual archive and distinct Source3 before strict reconstruction.
    ///
    /// The caller admits this fixed root before entry. Rc aliases allocate no
    /// replacement content or model. An empty retained root is not a completed
    /// decode and cannot produce an owner/signing loan.
    ///
    /// # Errors
    /// Refuses occupied output, foreign archive custody, a legacy Host/family,
    /// repeated Source allocation or a mismatch with the signed owner roster.
    pub(crate) fn retain_originals_into(
        archive: &CompleteOriginalRestorationSource,
        sources: &[Rc<PacketCompleteSemanticSource>; 3],
        output: &mut Option<Self>,
    ) -> Result<(), RuntimeError> {
        archive.inner.authenticate_birth()?;
        archive.restored_host_record_data()?;
        if output.is_some()
            || (0..3)
                .any(|index| (0..index).any(|prior| Rc::ptr_eq(&sources[index], &sources[prior])))
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        for source in sources {
            let installation = source.installation();
            let mut owners = archive
                .archive()
                .owners()
                .iter()
                .filter(|owner| owner.owner == installation.owner.owner.id);
            let owner = owners.next().ok_or(RuntimeError::ForeignAuthority)?;
            if owners.next().is_some()
                || source
                    .supported_complete_historical_archive_family_data(&owner.key)
                    .map_err(|_| RuntimeError::InvalidReceipt)?
                    != CompleteHistoricalArchiveFamily::Settled17
                || !owner.participants.contains(&installation.descriptor.id)
            {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        *output = Some(Self {
            process: std::process::id(),
            thread: std::thread::current().id(),
            archive: CompleteOriginalRestorationSource {
                inner: Rc::clone(&archive.inner),
            },
            sources: std::array::from_fn(|index| Rc::clone(&sources[index])),
            collection: None,
        });
        let group = output.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
        group
            .archive
            .take_restored_decoded_collection_into_data(&mut group.collection)?;
        group.origin()?;
        Ok(())
    }

    pub(crate) fn inline_root_storage_data() -> usize {
        std::mem::size_of::<Option<Self>>()
    }

    /// Counts actual archive and initialized decoder backing, including failures.
    ///
    /// The containing enum/Option inline root and actual Source3 allocations are
    /// separate. Both a retained native attempt and a completed native owner are
    /// counted if both are present; no equality or successful-stage discount is
    /// inferred. Defining semantic17/Node/Source outputs must be added before a
    /// complete constructor can be issued; this method is not decode authority.
    ///
    /// # Errors
    /// Refuses a foreign original process/thread, child layout overflow, or an
    /// independently admitted maximum smaller than the actual retained owners.
    pub(crate) fn retained_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        self.origin()?;
        let mut total = self.archive.inner.capture_owned_storage()?;
        if total > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        if let Some(collection) = &self.collection {
            add(
                &mut total,
                collection.retained_requested_storage_data(maximum)?,
                maximum,
            )?;
        }
        Ok(total)
    }

    /// Names the cold root, partial outputs and direct raw getter views.
    pub(crate) fn counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<crate::node_state::RetainedCold17Collection>()
            + size_of::<crate::node_state::RetainedCold17MemberView<'static>>()
            + size_of::<OriginalRestoredSettledColdOwnerView<'static>>()
            + size_of::<Result<OriginalRestoredSettledColdOwnerView<'static>, RuntimeError>>()
            + size_of::<RestoredSettledNative17Input<'static>>()
            + size_of::<[&ContentRef; 5]>()
            + size_of::<[usize; 5]>()
            + OriginalSourceRestoredSettled17Read::counter_scratch_data()
            + size_of::<Result<&NativeOwnerState, RuntimeError>>()
            + size_of::<Result<&HostSchedulingRestoredContinuationRecord17, RuntimeError>>()
            + size_of::<Option<&[u8]>>()
            + size_of::<Result<&[u8], RuntimeError>>()
            + size_of::<Result<&[u8], crucible_node_provider::ProviderError>>()
            + size_of::<Result<&ContentRef, crucible_node_provider::ProviderError>>()
            + size_of::<Result<&serde_json::Value, crucible_node_provider::ProviderError>>()
            + size_of::<Result<usize, crucible_node_provider::ProviderError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<usize>()
            + size_of::<Option<usize>>()
            + crucible_node_provider::protocol_snapshot::restored_settled17::restored_settled_native17_counter_scratch_data()
            + crucible_node_provider::protocol_snapshot::current_controller17::current_controller17_counter_scratch_data()
    }

    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.archive.inner.authenticate_birth()
    }

    pub(crate) fn original_owner_data<'a>(
        &'a self,
        selected: usize,
        source: &Rc<PacketCompleteSemanticSource>,
        ticket: &'a CompleteOriginalNativeTicket,
    ) -> Result<OriginalRestoredSettledColdOwnerView<'a>, RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.origin()?;
        let collection = self
            .collection
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        collection.authenticate_completed_data(self.archive.archive())?;
        let expected = self
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(expected, source) {
            return Err(RuntimeError::ForeignAuthority);
        }
        ticket.authenticate_source(&self.archive)?;
        let owner = ticket.owner()?;
        let owner_index = self
            .archive
            .archive()
            .owners()
            .iter()
            .position(|row| std::ptr::eq(row, owner))
            .ok_or(RuntimeError::ForeignAuthority)?;
        let retained = collection.member_data(self.archive.archive(), owner_index)?;
        if &owner.state != retained.references[0] {
            return Err(RuntimeError::ForeignAuthority);
        }
        let data = ticket.restored_native_import_construction_data()?;
        data.authenticate_original_references_data(retained.references)?;
        let content = self.archive.content();
        let body = |reference| content.get(reference).ok_or(RuntimeError::InvalidReceipt);
        let input = RestoredSettledNative17Input {
            snapshot: (retained.references[0], body(retained.references[0])?),
            current_protocol: (retained.references[1], body(retained.references[1])?),
            control: (retained.references[2], body(retained.references[2])?),
            anchor: (retained.references[3], body(retained.references[3])?),
            journal: (retained.references[4], body(retained.references[4])?),
        };
        // The same immutable Source and fixed sealed-owner slots retain these
        // exact bodies. Full body hashing occurred under the strict constructor's
        // admission; this signing loan performs no unquoted repeated body walk.
        if data.archived_input_byte_extents_data()
            != input.roles_data().map(|(_, bytes)| bytes.len())
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let native = retained.native;
        if native
            .body_reference()
            .map_err(|_| RuntimeError::InvalidReceipt)?
            != retained.references[1]
            || native
                .encoded_body()
                .map_err(|_| RuntimeError::InvalidReceipt)?
                .len()
                != input.current_protocol.1.len()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let controller = retained.controller;
        controller
            .parts_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let node = retained.node;
        let source_history = retained.source_history;
        if node.node_data() != &source.installation().descriptor.id
            || !owner.evidence.contains(source_history.reference_data())
            || content.get(source_history.reference_data()).is_none()
            || content.get(node.reference_data()).is_none()
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let limits = source_history.original_generic_limits_data();
        let installed = source.installation();
        if limits
            != (
                installed.maximum_operations,
                installed.maximum_semantic_bytes,
                installed.maximum_result_bytes,
                installed.maximum_authorization_bytes,
            )
            || source_history.historical_associations_count_data() > limits.0
            || node.retained_semantic_credit_data() > limits.1
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let checkpoint = source_history.current_checkpoint_data()?;
        native
            .authenticate_current_checkpoint_data(checkpoint.0, checkpoint.1, checkpoint.2)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(OriginalRestoredSettledColdOwnerView {
            source: expected,
            owner,
            host: self.archive.restored_host_record_data()?,
            native,
            controller,
            node,
            source_history,
            input,
        })
    }
}

fn add(total: &mut usize, bytes: usize, maximum: usize) -> Result<(), RuntimeError> {
    *total = total
        .checked_add(bytes)
        .filter(|total| *total <= maximum)
        .ok_or(RuntimeError::ResourceLimit)?;
    Ok(())
}

impl OriginalCompleteHistoricalColdGroup {
    /// Borrows only the genuine immutable initial15 variant.
    ///
    /// This is a discriminant check; the selected owner's original getter and
    /// live Window/source/supervisor guard remain independently mandatory.
    pub(crate) fn initial_invocation15_data(
        &self,
    ) -> Result<&super::super::OriginalRestorationColdGroup, RuntimeError> {
        match self {
            Self::InitialInvocation15(group) => Ok(group),
            Self::Settled17(_) => Err(RuntimeError::UnsupportedFacet),
        }
    }

    /// Borrows only the distinct current17 retained owner group.
    ///
    /// The group does not lend an owner until every actual construction and
    /// ancestry conjunct has completed. This method performs no legacy cast.
    pub(crate) fn settled17_data(&self) -> Result<&OriginalRestoredSettledColdGroup, RuntimeError> {
        match self {
            Self::Settled17(group) => {
                group.origin()?;
                Ok(group)
            }
            Self::InitialInvocation15(_) => Err(RuntimeError::UnsupportedFacet),
        }
    }
}
