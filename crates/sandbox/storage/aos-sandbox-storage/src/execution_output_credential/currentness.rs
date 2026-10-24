//! Reuses one actually disposed Output verification peak on the same original.
//!
//! Successful native samples dispose before replacement. A failed or ambiguous
//! frame retains every reached source/credential/name/post Result permanently.

use super::*;
use super::source_open::SourceOriginal;
use crate::operator_recovery_credentials::InitialStorageCredentialBatchV1;

#[derive(Clone, Copy)]
enum Failure {
    Source,
    Credential,
    SourceComparison,
    CredentialComparison,
    CredentialPost,
    CredentialIdentity,
    NamesHealth,
    Names,
    Current,
}

// These are closed native post destinations, never an implementable success
// callback. Both invoke the same source/credential/names sampler below.
enum OutputCurrentnessReceivingV1<'loan, 'cut, 'worker, 'flight, 'original> {
    Recurring(&'loan mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'original>),
    CaptureOwed {
        worker: &'loan mut aos_sandbox_controller_domain::StorageCaptureWorkerBorrowV2<'worker, 'flight, 'original>,
        original: &'loan mut aos_sandbox_controller_domain::StorageOutputOwedAfterOriginalV1,
    },
    Owed {
        lifecycle: &'loan mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>,
        original: &'loan mut aos_sandbox_controller_domain::StorageOutputOwedAfterOriginalV1,
    },
}

impl OutputCurrentnessReceivingV1<'_, '_, '_, '_, '_> {
    fn observe_names(&mut self, journal: &aos_sandbox_controller_domain::Journal,
        names: &mut aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1,
        health: &mut Option<Result<(), aos_sandbox_controller_domain::JournalError>>,
    ) -> Result<(), aos_sandbox_controller_domain::JournalError> {
        match self {
            Self::Recurring(receiving) => receiving.observe_output_currentness_names_once_v1(journal, names, health),
            Self::Owed { lifecycle, original } => lifecycle.observe_output_owed_names_once_v1(original, journal, names, health),
            Self::CaptureOwed { worker, original } => worker.observe_capture_output_names_v3(original, journal, names, health),
        }
    }

    fn finish(&mut self) -> Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        match self {
            Self::Recurring(receiving) => receiving.finish_initial_observation_post_v1(),
            Self::Owed { lifecycle, original } => lifecycle.finish_output_owed_after_once_v1(original),
            Self::CaptureOwed { worker, original } => worker.finish_capture_output_after_v3(original),
        }
    }

    fn close(&mut self) {
        match self {
            Self::Recurring(receiving) => receiving.close_output_currentness_v1(),
            Self::Owed { lifecycle, .. } => lifecycle.close_output_owed_currentness_v1(),
            Self::CaptureOwed { worker, .. } => worker.close_capture_output_currentness_v3(),
        }
    }
}

pub(super) struct OutputCurrentnessV1 {
    source: SourceOriginal,
    credential: InitialStorageCredentialBatchV1<1>,
    source_comparison: Option<Result<(), StorageServiceError>>,
    credential_comparison: Option<Result<(), StorageServiceError>>,
    credential_post: Option<Result<(), ()>>,
    observed_credential: Option<PinnedCredential>,
    credential_identity: Option<Result<(), StorageServiceError>>,
    names_originals: aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1,
    names_health: Option<Result<(), aos_sandbox_controller_domain::JournalError>>,
    names: Option<Result<(), aos_sandbox_controller_domain::JournalError>>,
    current: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    first: Option<Failure>,
    disposed: bool,
}

impl OutputCurrentnessV1 {
    pub(super) fn new() -> Self {
        Self {
            source: SourceOriginal::new(),
            credential: InitialStorageCredentialBatchV1::new(),
            source_comparison: None,
            credential_comparison: None,
            credential_post: None,
            observed_credential: None,
            credential_identity: None,
            names_originals: aos_sandbox_controller_domain::journal::ProtectedJournalCurrentnessOriginalsV1::new(),
            names_health: None,
            names: None,
            current: None,
            first: None,
            disposed: false,
        }
    }

    pub(super) fn can_replace(&self) -> bool {
        self.first.is_none() && self.disposed
    }

    pub(super) fn observe(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::StoragePrepareReceivingLoanV1<'_>,
        expected_source: &PinnedSource,
        expected_directory: FileIdentity,
        expected_credential: &PinnedCredential,
        journal: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), StorageServiceError> {
        self.observe_inner(OutputCurrentnessReceivingV1::Recurring(receiving),
            expected_source, expected_directory, expected_credential, journal)
    }

    fn observe_inner(
        &mut self,
        mut receiving: OutputCurrentnessReceivingV1<'_, '_, '_, '_, '_>,
        expected_source: &PinnedSource,
        expected_directory: FileIdentity,
        expected_credential: &PinnedCredential,
        journal: &aos_sandbox_controller_domain::Journal,
    ) -> Result<(), StorageServiceError> {
        if self.source.capture_once(&expected_source.path).is_err() {
            self.first = Some(Failure::Source);
        }
        if self.credential.capture_once(&[CREDENTIAL_NAME], &[CREDENTIAL_BYTES]).is_err() {
            self.first.get_or_insert(Failure::Credential);
        }
        self.source_comparison = Some(if self.source.source().is_some_and(|current|
            current.path == expected_source.path && current.identity == expected_source.identity
                && current.bytes == expected_source.bytes)
        {
            Ok(())
        } else {
            Err(invalid("output credential source changed"))
        });
        if !matches!(self.source_comparison, Some(Ok(()))) {
            self.first.get_or_insert(Failure::SourceComparison);
        }
        self.credential_comparison = Some(if self.credential.directory_identity() == Some(expected_directory)
            && self.credential.bytes(0) == Some(expected_credential.bytes.as_slice())
        {
            Ok(())
        } else {
            Err(invalid("output credential changed"))
        });
        if !matches!(self.credential_comparison, Some(Ok(()))) {
            self.first.get_or_insert(Failure::CredentialComparison);
        }
        // Independently sample the actual original credential inode and fresh
        // name too; no earlier source or model refusal skips its destination.
        self.credential_post = Some(self.credential.post_once(&[CREDENTIAL_NAME], &[CREDENTIAL_BYTES]));
        if !matches!(self.credential_post, Some(Ok(()))) {
            self.first.get_or_insert(Failure::CredentialPost);
        }
        self.observed_credential = self.credential.take_pin(0, CREDENTIAL_NAME);
        self.credential_identity = Some(if self.observed_credential.as_ref()
            .is_some_and(|observed| observed.identity == expected_credential.identity
                && observed.bytes == expected_credential.bytes)
        {
            Ok(())
        } else {
            Err(invalid("output credential changed"))
        });
        if !matches!(self.credential_identity, Some(Ok(()))) {
            self.first.get_or_insert(Failure::CredentialIdentity);
        }
        self.names = Some(receiving.observe_names(
            journal, &mut self.names_originals, &mut self.names_health,
        ));
        if matches!(self.names_health, Some(Err(_))) {
            self.first.get_or_insert(Failure::NamesHealth);
        }
        if !matches!(self.names, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Names);
        }
        self.current = Some(receiving.finish());
        if !matches!(self.current, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Current);
        }
        if self.first.is_some() || !self.credential.ready_for_handoff() {
            receiving.close();
            return Err(invalid("output journal custody changed"));
        }
        // Every required fallible post is complete with all carriers still
        // resident. Only actual positive native disposition permits replacement.
        if self.credential.settle_positive_native_once().is_err() {
            std::process::abort();
        }
        self.source.settle_positive();
        self.names_originals.settle_positive_once_v1();
        self.disposed = true;
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            Failure::Source => self.source.failure(),
            Failure::Credential => self.credential.capture_failure(),
            Failure::SourceComparison => self.source_comparison.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::CredentialComparison => self.credential_comparison.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::CredentialPost => self.credential.post_failure(),
            Failure::CredentialIdentity => self.credential_identity.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error),
            Failure::NamesHealth => self.names_health.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
            Failure::Names => self.names_originals.failure().or_else(|| self.names.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as &dyn std::error::Error)),
            Failure::Current => self.current.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error),
        }
    }
}

#[derive(Clone, Copy)]
enum OwedFirst { Demand, Payment, Arm, Sample }

/// Holds the distinct final Output sampler beside an action's native originals.
///
/// Only the configured Output custody can bind and prepay this destination.
/// It is neither a response nor a capture permit; every failed native/source
/// prefix remains resident through the actual enclosing Session disposition.
pub(crate) struct StorageOutputOwedAfterV1 {
    frame: OutputCurrentnessV1,
    original: aos_sandbox_controller_domain::StorageOutputOwedAfterOriginalV1,
    demand: Option<Result<aos_sandbox_model::ResourceVector, aos_sandbox_model::AccountingError>>,
    payment: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    arm: Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
    sample: Option<Result<(), StorageServiceError>>,
    first: Option<OwedFirst>,
    entered: bool,
}

impl StorageOutputOwedAfterV1 {
    pub(crate) fn new() -> Self {
        Self { frame: OutputCurrentnessV1::new(), original: aos_sandbox_controller_domain::StorageOutputOwedAfterOriginalV1::new(),
            demand: None, payment: None, arm: None, sample: None, first: None, entered: false }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            OwedFirst::Demand => self.demand.as_ref()?.as_ref().err().map(|cause| cause as _),
            OwedFirst::Payment => self.payment.as_ref()?.as_ref().err().map(|cause| cause as _),
            OwedFirst::Arm => self.original.failure().or_else(|| self.arm.as_ref()?.as_ref().err().map(|cause| cause as _)),
            OwedFirst::Sample => self.frame.failure().or_else(|| self.original.failure())
                .or_else(|| self.sample.as_ref()?.as_ref().err().map(|cause| cause as _)),
        }
    }
}

impl StorageExecutionOutputCustodyV1 {
    pub(crate) fn prepare_owed_after_receiving_v1(&self,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        session: &aos_sandbox_controller_domain::Journal, socket: &aos_sandbox_linux::seqpacket::SeqpacketSocket,
        after: &mut StorageOutputOwedAfterV1) -> Result<(), StorageServiceError> {
        self.prepare_owed_after_inner_v3(OwedAfterReceivingV3::Lifecycle { lifecycle, session, socket }, after)
    }

    pub(crate) fn prepare_capture_owed_after_v3(&self,
        worker: &mut aos_sandbox_controller_domain::StorageCaptureWorkerBorrowV2<'_, '_, '_>,
        state: &aos_sandbox_controller_domain::Journal, verified: &aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
        after: &mut StorageOutputOwedAfterV1) -> Result<(), StorageServiceError> {
        self.prepare_owed_after_inner_v3(OwedAfterReceivingV3::Capture { worker, state, verified }, after)
    }

    fn prepare_owed_after_inner_v3(&self, mut receiving: OwedAfterReceivingV3<'_, '_, '_, '_, '_>,
        after: &mut StorageOutputOwedAfterV1) -> Result<(), StorageServiceError> {
        use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
        if after.entered { return Err(invalid("the final Output original was already entered")); }
        after.entered = true;
        // The same fixed source/credential/native recipe bounds the distinct
        // final sampler. All these rooted names were paid at actual Output
        // initialization; another copy of their bytes/files adds no namespace.
        after.demand = Some(super::startup::StorageExecutionOutputStartupV1::fixed_demand(&self.source.path)
            .and_then(|fixed| {
                let bytes = std::mem::size_of::<StorageOutputOwedAfterV1>().checked_mul(2)
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
                fixed.with(D::MetadataEntries, 0)
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            }));
        let Some(Ok(demand)) = after.demand.as_ref().copied() else {
            after.first = Some(OwedFirst::Demand);
            return Err(invalid("the final Output receiving representation is unavailable"));
        };
        after.payment = Some(receiving.reserve(self, demand));
        if !matches!(after.payment, Some(Ok(()))) {
            after.first = Some(OwedFirst::Payment);
            return Err(invalid("the final Output receiving representation was refused"));
        }
        after.arm = Some(receiving.arm(self, &mut after.original));
        if !matches!(after.arm, Some(Ok(()))) {
            after.first = Some(OwedFirst::Arm);
            return Err(invalid("the independent final Output observation was refused"));
        }
        Ok(())
    }

    pub(crate) fn finish_owed_after_receiving_v1(&self,
        lifecycle: &mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'_, '_>,
        after: &mut StorageOutputOwedAfterV1) -> Result<(), StorageServiceError> {
        let receiving = OutputCurrentnessReceivingV1::Owed { lifecycle, original: &mut after.original };
        Self::finish_owed_after_inner_v3(self, receiving, &mut after.frame, &after.arm,
            &mut after.sample, &mut after.first)
    }

    pub(crate) fn finish_capture_owed_after_v3(&self,
        worker: &mut aos_sandbox_controller_domain::StorageCaptureWorkerBorrowV2<'_, '_, '_>,
        after: &mut StorageOutputOwedAfterV1) -> Result<(), StorageServiceError> {
        let receiving = OutputCurrentnessReceivingV1::CaptureOwed { worker, original: &mut after.original };
        Self::finish_owed_after_inner_v3(self, receiving, &mut after.frame, &after.arm,
            &mut after.sample, &mut after.first)
    }

    fn finish_owed_after_inner_v3(&self, receiving: OutputCurrentnessReceivingV1<'_, '_, '_, '_, '_>,
        frame: &mut OutputCurrentnessV1, arm: &Option<Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1>>,
        sample: &mut Option<Result<(), StorageServiceError>>, first: &mut Option<OwedFirst>)
        -> Result<(), StorageServiceError> {
        if !matches!(arm, Some(Ok(()))) || sample.is_some() {
            return Err(invalid("the final Output observation is unavailable"));
        }
        *sample = Some(frame.observe_inner(receiving,
            &self.source, self.directory_identity, &self.credential,
            self.ledger.held_journal_for_receiving_v1()));
        if !matches!(sample, Some(Ok(()))) {
            first.get_or_insert(OwedFirst::Sample);
            return Err(invalid("the final Output observation refused"));
        }
        Ok(())
    }
}

// A closed choice of actual native lenders; neither branch is caller-implementable.
enum OwedAfterReceivingV3<'loan, 'cut, 'worker, 'flight, 'original> {
    Lifecycle {
        lifecycle: &'loan mut aos_sandbox_controller_domain::StorageLifecycleSessionLoanV1<'cut, 'original>,
        session: &'loan aos_sandbox_controller_domain::Journal,
        socket: &'loan aos_sandbox_linux::seqpacket::SeqpacketSocket,
    },
    Capture {
        worker: &'loan mut aos_sandbox_controller_domain::StorageCaptureWorkerBorrowV2<'worker, 'flight, 'original>,
        state: &'loan aos_sandbox_controller_domain::Journal,
        verified: &'loan aos_sandbox_broker::VerifiedStorageCaptureLifetimeV3,
    },
}

impl OwedAfterReceivingV3<'_, '_, '_, '_, '_> {
    fn reserve(&mut self, output: &StorageExecutionOutputCustodyV1,
        demand: aos_sandbox_model::ResourceVector) -> Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        match self {
            Self::Lifecycle { lifecycle, session, socket } => lifecycle.reserve_domain_additional_v1(session, socket, demand),
            Self::Capture { worker, state, verified } => worker.reserve_capture_terminal_models_v3(state,
                output.ledger.held_journal_for_receiving_v1(), verified, demand),
        }
    }

    fn arm(&mut self, output: &StorageExecutionOutputCustodyV1,
        original: &mut aos_sandbox_controller_domain::StorageOutputOwedAfterOriginalV1)
        -> Result<(), aos_sandbox_controller_domain::StorageReceivingClosedV1> {
        match self {
            Self::Lifecycle { lifecycle, session, socket } => lifecycle.arm_output_owed_after_v1(session, socket,
                output.ledger.held_journal_for_receiving_v1(), &output.source.path, original),
            Self::Capture { worker, state, verified } => worker.arm_capture_output_after_v3(state,
                output.ledger.held_journal_for_receiving_v1(), verified, &output.source.path, original),
        }
    }
}
