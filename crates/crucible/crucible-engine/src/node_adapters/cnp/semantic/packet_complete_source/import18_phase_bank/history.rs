//! Borrows the same real Source18 phase occurrence, including failed prefixes.
//!
//! These views do not serialize or construct a checkpoint. A prepared Once18
//! writer independently funds literal token preparation and correspondence,
//! retains those outputs outside this loan, then reborrows these same fields.
//! Missing bootstrap/SDK owners remain missing; no flag becomes a witness.

use super::*;
use crucible_node_transport::{
    ProviderError,
    client::{
        OriginalNativeImport18AssignmentRowHistoryData, OriginalNativeImport18BootstrapHistoryData,
        OriginalNativeImport18BootstrapRowHistoryData, OriginalNativeImport18PartialHistoryData,
    },
};

/// Borrows the attempted flag independently of whether Box construction finished.
pub(crate) struct NativeImport18SourceBankHistoryData<'a> {
    pub attempted: bool,
    pub bank: Option<NativeImport18BankHistoryData<'a>>,
}

/// Borrows the real saved row, flags and ordered owner bank without live pointers.
pub(crate) struct NativeImport18BankHistoryData<'a> {
    pub row_axes: [usize; 3],
    pub started: bool,
    pub retained: bool,
    pub failed: bool,
    pub owners: NativeImport18SourceOwnerHistoryIter<'a>,
}

/// Iterates actual owner occurrences without allocating a copied history bank.
pub(crate) struct NativeImport18SourceOwnerHistoryIter<'a> {
    inner: std::slice::Iter<'a, NativeImport18SourcePhaseOwner>,
}

/// Borrows actual immutable birth operands and every initialized phase field.
pub(crate) struct NativeImport18SourceOwnerHistoryData<'a> {
    pub recipe: &'a PacketNativeImport18PrebirthRecipeData,
    pub initial: PacketNativeImport18InitialFundingHistoryData<'a>,
    pub retained: bool,
    pub bootstrap: NativeImport18BootstrapHistoryData<'a>,
    pub prepare: NativeImport18PhaseHistoryData<'a>,
    pub commit: NativeImport18PhaseHistoryData<'a>,
    pub prepare_request: Option<&'a PacketCompleteRestorePrepareRequest>,
    pub commit_request: Option<&'a PacketCompleteRestoreCommitRequest>,
    pub binding: Option<&'a PacketNativeImport18Binding>,
    pub sdk_rows: [Option<NativeImport18SdkRowHistoryData<'a>>; 2],
    pub prepare_capsule: Option<NativeImport18SdkHistoryData<'a>>,
    pub input_upload_started: bool,
    pub input_upload_verified: bool,
    pub failed: bool,
}

/// Borrows all bootstrap signing fields independently of any SDK completion.
pub(crate) struct NativeImport18BootstrapHistoryData<'a> {
    pub sdk_row: Option<NativeImport18BootstrapSdkRowHistoryData<'a>>,
    pub sdk_owner: Option<NativeImport18BootstrapSdkHistoryData<'a>>,
    pub started: bool,
    pub assigned: bool,
    pub publishing: bool,
    pub failed: bool,
    pub request_id: Option<&'a Id>,
    pub request: Option<&'a PacketNativeImport18BootstrapRequest>,
    pub context: Option<&'a PacketNativeImport18BootstrapAckContext>,
    pub proof: Option<&'a PacketNativeImport18BootstrapAckProof>,
    pub result: Option<&'a PacketNativeImport18BootstrapResult>,
    pub receipt: Option<&'a PacketNativeImport18BootstrapAckReceipt>,
    pub literal: NativeImport18LiteralHistoryData<'a>,
}

/// Borrows each actual literal construction prefix and independent encoded bank.
pub(crate) struct NativeImport18LiteralHistoryData<'a> {
    pub attempt: Option<LiteralValue18TokenAttemptPartialData<'a>>,
    pub literal: Option<&'a LiteralValue18Data>,
    pub encoded: &'a [u8],
}

/// Borrows actual signing progress without claiming an assigned/native result.
pub(crate) struct NativeImport18PhaseHistoryData<'a> {
    pub request_id: Option<&'a Id>,
    pub baseline: Option<&'a BeginRequest>,
    pub normalized: [NativeImport18LiteralHistoryData<'a>; 5],
    pub started: bool,
    pub assigned: bool,
    pub sealed: bool,
    pub publishing: bool,
    pub verified: bool,
    pub failed: bool,
}

/// Restricts the actual dedicated Bootstrap18 owner to passive observation.
pub(crate) struct NativeImport18BootstrapSdkHistoryData<'a> {
    owner: &'a OriginalNativeImport18Bootstrap,
}

impl NativeImport18BootstrapSdkHistoryData<'_> {
    /// Visits this same owner, including typed constructor refusal prefixes.
    ///
    /// # Errors
    /// Preserves the defining SDK origin error and passive callback refusal.
    pub(crate) fn with_partial_history_data<R>(
        &self,
        inspect: impl for<'view> FnOnce(
            OriginalNativeImport18BootstrapHistoryData<'view>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.owner.with_partial_history_data(inspect)
    }

    /// Names the real passive SDK callback controls.
    pub(crate) fn counter_scratch_data<R>() -> usize {
        OriginalNativeImport18Bootstrap::partial_history_counter_scratch_data::<R>()
            + size_of::<Self>()
            + size_of::<&Self>()
    }
}

/// Restricts the saved dedicated Bootstrap18 row to its full passive DATA view.
pub(crate) struct NativeImport18BootstrapSdkRowHistoryData<'a> {
    row: &'a OriginalNativeImport18BootstrapConstructionData,
    owner: Option<&'a OriginalNativeImport18Bootstrap>,
}

impl NativeImport18BootstrapSdkRowHistoryData<'_> {
    /// Visits the same row and its actual same-bank Controller relation.
    ///
    /// # Errors
    /// Preserves the defining SDK origin error and passive callback refusal.
    pub(crate) fn with_row_history_data<R>(
        &self,
        inspect: impl for<'view> FnOnce(
            OriginalNativeImport18BootstrapRowHistoryData<'view>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.row.with_row_history_data(self.owner, inspect)
    }

    /// Names the real passive row callback controls.
    pub(crate) fn counter_scratch_data<R>() -> usize {
        OriginalNativeImport18BootstrapConstructionData::row_history_counter_scratch_data::<R>()
            + size_of::<Self>()
            + size_of::<&Self>()
    }
}

/// Restricts a real SDK capsule loan to its defining passive partial-history API.
pub(crate) struct NativeImport18SdkHistoryData<'a> {
    owner: &'a OriginalNativeImport18Assignment,
}

impl NativeImport18SdkHistoryData<'_> {
    /// Visits every actual partial without exposing the effect-bearing capsule.
    ///
    /// # Errors
    /// Preserves the defining SDK origin/loan error and either callback outcome.
    pub(crate) fn with_partial_history_data<R>(
        &self,
        inspect: impl for<'view> FnOnce(
            OriginalNativeImport18PartialHistoryData<'view>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.owner.with_partial_history_data(inspect)
    }

    /// Names the genuine passive SDK lookup and callback control frames.
    pub(crate) fn counter_scratch_data<R>() -> usize {
        OriginalNativeImport18Assignment::partial_history_counter_scratch_data::<R>()
            + size_of::<Self>()
            + size_of::<&Self>()
    }
}

/// Restricts a saved SDK quote to DATA observation; it exposes no assignment API.
pub(crate) struct NativeImport18SdkRowHistoryData<'a> {
    row: &'a OriginalNativeImport18AssignmentStorageData,
    capsule: Option<&'a OriginalNativeImport18Assignment>,
}

impl NativeImport18SdkRowHistoryData<'_> {
    /// Visits the actual complete row and its same-bank optional capsule relation.
    ///
    /// # Errors
    /// Preserves genuine SDK creator checks and either passive callback outcome.
    pub(crate) fn with_row_history_data<R>(
        &self,
        inspect: impl for<'view> FnOnce(
            OriginalNativeImport18AssignmentRowHistoryData<'view>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.row.with_row_history_data(self.capsule, inspect)
    }

    /// Names actual SDK row lookup and this restricted borrowed wrapper.
    pub(crate) fn counter_scratch_data<R>() -> usize {
        OriginalNativeImport18AssignmentStorageData::row_history_counter_scratch_data::<R>()
            + size_of::<Self>()
            + size_of::<&Self>()
    }
}

impl<'a> Iterator for NativeImport18SourceOwnerHistoryIter<'a> {
    type Item = NativeImport18SourceOwnerHistoryData<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(owner_history)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl ExactSizeIterator for NativeImport18SourceOwnerHistoryIter<'_> {}

impl PacketCompleteSemanticSource {
    /// Borrows the same bank under Source origin guards around both outcomes.
    ///
    /// The callback owns no Source or SDK phase capability. It must keep modeled
    /// failed outputs in its separate retained attempt before returning an error.
    /// Whole-owner observations happen after this shared bank loan is released.
    ///
    /// # Errors
    /// Refuses foreign Source origin, a busy bank or the callback's DATA refusal.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn with_native_import18_phase_bank_history_data<
        R,
    >(
        &self,
        inspect: impl for<'view> FnOnce(
            NativeImport18SourceBankHistoryData<'view>,
        ) -> Result<R, RuntimeError>,
    ) -> Result<R, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let slot = self
            .native_import18_phase_bank
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let attempted = self.native_import18_phase_bank_attempted.get();
        let output = inspect(NativeImport18SourceBankHistoryData {
            attempted,
            bank: slot.as_ref().map(|bank| NativeImport18BankHistoryData {
                row_axes: bank.row.requested_storage_data(),
                started: bank.started,
                retained: bank.retained,
                failed: bank.failed,
                owners: NativeImport18SourceOwnerHistoryIter {
                    inner: bank.owners.iter(),
                },
            }),
        });
        let origin = self.storage_origin_with_error::<RuntimeError>();
        let unchanged = self.native_import18_phase_bank_attempted.get() == attempted;
        drop(slot);
        origin?;
        if !unchanged {
            return Err(RuntimeError::ForeignAuthority);
        }
        output
    }

    /// Names the actual borrowed views and callback/loan controls before lookup.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn native_import18_phase_bank_history_counter_scratch_data<
        R,
    >() -> usize {
        LiteralValue18TokenAttempt::partial_counter_scratch_data()
            + size_of::<NativeImport18SourceBankHistoryData<'static>>()
            + size_of::<NativeImport18BankHistoryData<'static>>()
            // The immutable row getter borrows its real receiver and returns
            // a distinct copied axes array before the history view is built.
            + size_of::<&OriginalNativeImport18SourcePhaseBankConstructionData>()
            + size_of::<[usize; 3]>()
            + size_of::<NativeImport18SourceOwnerHistoryData<'static>>()
            + size_of::<NativeImport18BootstrapHistoryData<'static>>()
            + size_of::<Option<NativeImport18BootstrapSdkHistoryData<'static>>>()
            + size_of::<Option<NativeImport18BootstrapSdkRowHistoryData<'static>>>()
            + size_of::<NativeImport18PhaseHistoryData<'static>>() * 2
            + size_of::<NativeImport18LiteralHistoryData<'static>>()
            + size_of::<[NativeImport18LiteralHistoryData<'static>; 5]>()
            + size_of::<[Option<NativeImport18SdkRowHistoryData<'static>>; 2]>()
            + size_of::<Option<NativeImport18SdkHistoryData<'static>>>()
            + size_of::<NativeImport18SourceOwnerHistoryIter<'static>>()
            + size_of::<Option<NativeImport18SourceOwnerHistoryData<'static>>>()
            + size_of::<std::slice::Iter<'static, NativeImport18SourcePhaseOwner>>()
            + size_of::<(usize, Option<usize>)>()
            + PacketNativeImport18InitialFundingHistoryData::counter_scratch_data()
            + size_of::<PacketNativeImport18InitialFundingHistoryData<'static>>()
            + size_of::<&NativeImport18SourcePhaseOwner>()
            + size_of::<&BootstrapPartials>()
            + size_of::<&PhasePartials>()
            + size_of::<&LiteralPartial>()
            + size_of::<&PacketCompleteSemanticSource>()
            + size_of::<Ref<'static, Option<Box<NativeImport18SourcePhaseBank>>>>()
            + size_of::<Result<Ref<'static, Option<Box<NativeImport18SourcePhaseBank>>>, BorrowError>>(
            )
            + size_of::<
                Result<Ref<'static, Option<Box<NativeImport18SourcePhaseBank>>>, RuntimeError>,
            >()
            + size_of::<Option<&Box<NativeImport18SourcePhaseBank>>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<R>()
            + size_of::<Result<R, RuntimeError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<ThreadId>()
            + size_of::<&ThreadId>() * 2
            + size_of::<&u32>() * 2
            + size_of::<u32>()
            + size_of::<Retention>()
            + size_of::<bool>() * 2
    }
}

fn literal_history(value: &LiteralPartial) -> NativeImport18LiteralHistoryData<'_> {
    NativeImport18LiteralHistoryData {
        attempt: value
            .attempt
            .as_ref()
            .map(LiteralValue18TokenAttempt::partial_data),
        literal: value.literal.as_ref(),
        encoded: &value.encoded,
    }
}

pub(super) fn phase_history(value: &PhasePartials) -> NativeImport18PhaseHistoryData<'_> {
    NativeImport18PhaseHistoryData {
        request_id: value.request_id.as_ref(),
        baseline: value.baseline.as_ref(),
        normalized: [
            literal_history(&value.normalized[0]),
            literal_history(&value.normalized[1]),
            literal_history(&value.normalized[2]),
            literal_history(&value.normalized[3]),
            literal_history(&value.normalized[4]),
        ],
        started: value.started,
        assigned: value.assigned,
        sealed: value.sealed,
        publishing: value.publishing,
        verified: value.verified,
        failed: value.failed,
    }
}

fn owner_history(
    value: &NativeImport18SourcePhaseOwner,
) -> NativeImport18SourceOwnerHistoryData<'_> {
    let bootstrap = &value.bootstrap;
    NativeImport18SourceOwnerHistoryData {
        recipe: &value.recipe,
        initial: value.initial.borrowed_history_data(),
        retained: value.retention == Retention::Retained,
        bootstrap: NativeImport18BootstrapHistoryData {
            sdk_row: bootstrap.sdk_row.as_ref().map(|row| {
                NativeImport18BootstrapSdkRowHistoryData {
                    row,
                    owner: bootstrap.sdk_owner.as_ref(),
                }
            }),
            sdk_owner: bootstrap
                .sdk_owner
                .as_ref()
                .map(|owner| NativeImport18BootstrapSdkHistoryData { owner }),
            started: bootstrap.started,
            assigned: bootstrap.assigned,
            publishing: bootstrap.publishing,
            failed: bootstrap.failed,
            request_id: bootstrap.request_id.as_ref(),
            request: bootstrap.request.as_ref(),
            context: bootstrap.context.as_ref(),
            proof: bootstrap.proof.as_ref(),
            result: bootstrap.result.as_ref(),
            receipt: bootstrap.receipt.as_ref(),
            literal: NativeImport18LiteralHistoryData {
                attempt: bootstrap
                    .literal_attempt
                    .as_ref()
                    .map(LiteralValue18TokenAttempt::partial_data),
                literal: bootstrap.literal.as_ref(),
                encoded: &bootstrap.encoded,
            },
        },
        prepare: phase_history(&value.prepare),
        commit: phase_history(&value.commit),
        prepare_request: value.prepare_request.as_ref(),
        commit_request: value.commit_request.as_ref(),
        binding: value.binding.as_ref(),
        sdk_rows: [
            value.sdk_rows[0]
                .as_ref()
                .map(|row| NativeImport18SdkRowHistoryData {
                    row,
                    capsule: value.prepare_capsule.as_ref(),
                }),
            value.sdk_rows[1]
                .as_ref()
                .map(|row| NativeImport18SdkRowHistoryData {
                    row,
                    capsule: value.prepare_capsule.as_ref(),
                }),
        ],
        prepare_capsule: value
            .prepare_capsule
            .as_ref()
            .map(|owner| NativeImport18SdkHistoryData { owner }),
        input_upload_started: value.input_upload_started,
        input_upload_verified: value.input_upload_verified,
        failed: value.failed,
    }
}
