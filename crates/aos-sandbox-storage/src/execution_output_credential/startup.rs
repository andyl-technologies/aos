//! Genuine paid initial Output source, credential and existing-writer custody.
//!
//! Construction owns this destination before entry. The normal custody moves
//! only after actual independent source/credential/Journal/original posts and
//! native-opening settlement. Errors never reopen or provision an Output file.

use super::*;
use super::source_open::SourceOriginal;
use crate::execution_output::startup::ExecutionOutputLedgerStartupV1;
use crate::operator_recovery_credentials::InitialStorageCredentialBatchV1;
use aos_sandbox_core::{AccountingError, ResourceDimension as D, ResourceVector};

#[derive(Clone, Copy)]
enum Failure {
    Demand,
    Payment,
    Source,
    Credential,
    Decode,
    Ledger,
    SourcePost,
    CredentialPost,
    Names,
    Current,
    Closed,
}

pub(crate) struct StorageExecutionOutputStartupV1 {
    source: SourceOriginal,
    source_post: SourceOriginal,
    credentials: InitialStorageCredentialBatchV1<1>,
    demand: Option<Result<ResourceVector, AccountingError>>,
    payment: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    decoded: Option<Result<(u64, Option<ExecutionOutputLedgerKeyV1>), StorageServiceError>>,
    ledger: ExecutionOutputLedgerStartupV1,
    source_post_result: Option<Result<(), StorageServiceError>>,
    credential_post: Option<Result<(), ()>>,
    names_post: Option<Result<(), crate::execution_output::ExecutionOutputLedgerErrorV1>>,
    current: Option<Result<(), aos_sandbox::StorageReceivingClosedV1>>,
    handoff_source: Option<PinnedSource>,
    handoff_directory: Option<PathBuf>,
    handoff_directory_identity: Option<FileIdentity>,
    handoff_credential: Option<PinnedCredential>,
    ready: Option<StorageExecutionOutputCustodyV1>,
    first: Option<Failure>,
    entered: bool,
    taken: bool,
}

impl StorageExecutionOutputStartupV1 {
    pub(crate) fn new() -> Self {
        Self {
            source: SourceOriginal::new(),
            source_post: SourceOriginal::new(),
            credentials: InitialStorageCredentialBatchV1::new(),
            demand: None,
            payment: None,
            decoded: None,
            ledger: ExecutionOutputLedgerStartupV1::new(),
            source_post_result: None,
            credential_post: None,
            names_post: None,
            current: None,
            handoff_source: None,
            handoff_directory: None,
            handoff_directory_identity: None,
            handoff_credential: None,
            ready: None,
            first: None,
            entered: false,
            taken: false,
        }
    }

    pub(crate) fn open_once_v1(
        &mut self,
        receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>,
        source: &Path,
    ) -> Result<(), StorageServiceError> {
        if self.entered || self.taken || self.first.is_some() {
            self.first.get_or_insert(Failure::Closed);
            return Err(invalid("existing output ledger is unavailable or mismatched"));
        }
        self.entered = true;
        self.demand = Some(Self::fixed_demand(source));
        let Some(Ok(demand)) = self.demand.as_ref().copied() else {
            self.first = Some(Failure::Demand);
            return Err(invalid("existing output ledger is unavailable or mismatched"));
        };
        self.payment = Some(receiving.reserve_output_configuration_once_v1(source, demand));
        if !matches!(self.payment, Some(Ok(()))) {
            self.first = Some(Failure::Payment);
            return Err(invalid("existing output ledger is unavailable or mismatched"));
        }
        self.current = Some(receiving.arm_output_startup_observation_post_v1());
        if !matches!(self.current, Some(Ok(()))) {
            self.first = Some(Failure::Current);
            return Err(invalid("existing output ledger is unavailable or mismatched"));
        }

        // Every later frontier retains its actual owner; no early projection
        // can skip the already paid independent original observation below.
        self.capture(receiving, source);
        self.source_post_result = Some(self.observe_source_post(source));
        if !matches!(self.source_post_result, Some(Ok(()))) {
            self.first.get_or_insert(Failure::SourcePost);
        }
        self.credential_post = Some(self.credentials.post_once(&[CREDENTIAL_NAME], &[CREDENTIAL_BYTES]));
        if !matches!(self.credential_post, Some(Ok(()))) {
            self.first.get_or_insert(Failure::CredentialPost);
        }
        self.names_post = Some(self.ledger.observe_final_names_once_v1());
        if !matches!(self.names_post, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Names);
        }
        self.current = Some(receiving.finish_initial_observation_post_v1());
        if !matches!(self.current, Some(Ok(()))) {
            self.first.get_or_insert(Failure::Current);
        }
        if self.first.is_some() || !self.credentials.ready_for_handoff() {
            self.first.get_or_insert(Failure::Closed);
            return Err(invalid("existing output ledger is unavailable or mismatched"));
        }

        self.handoff_source = self.source.take_source();
        self.handoff_directory_identity = self.credentials.directory_identity();
        self.handoff_credential = self.credentials.take_pin(0, CREDENTIAL_NAME);
        self.handoff_directory = Some(InitialStorageCredentialBatchV1::<1>::directory_path());
        if self.handoff_source.is_none() || self.handoff_directory_identity.is_none()
            || self.handoff_credential.is_none()
        {
            self.first = Some(Failure::Closed);
            return Err(invalid("existing output ledger is unavailable or mismatched"));
        }
        // All actual normal inputs are resident on this owner before the last
        // fallible Native settlement. A refusal keeps them alongside its facade.
        if self.ledger.settle_native_once_v1(receiving).is_err() {
            self.first = Some(Failure::Ledger);
            return Err(invalid("existing output ledger is unavailable or mismatched"));
        }
        let (Some(source), Some(directory), Some(directory_identity), Some(credential), Some(ledger)) = (
            self.handoff_source.take(), self.handoff_directory.take(),
            self.handoff_directory_identity.take(), self.handoff_credential.take(),
            self.ledger.take_owner_once_v1(),
        ) else {
            // The continuously borrowed all-positive path above preflights
            // these pure moves; no native operation or allocation follows.
            std::process::abort();
        };
        self.ready = Some(StorageExecutionOutputCustodyV1 {
            source, directory, directory_identity, credential, ledger,
            receiving_current: None,
        });
        // This private completed batch performs only its already proven
        // positive disposition. Any invariant violation aborts with all owners
        // resident rather than projecting a late error after facade disposal.
        if self.credentials.settle_positive_native_once().is_err() {
            std::process::abort();
        }
        self.source.settle_positive();
        self.source_post.settle_positive();
        Ok(())
    }

    fn capture(&mut self, receiving: &mut aos_sandbox::StoragePrepareReceivingLoanV1<'_>, source: &Path) {
        if self.source.capture_once(source).is_err() {
            self.first = Some(Failure::Source);
            return;
        }
        if self.credentials.capture_once(&[CREDENTIAL_NAME], &[CREDENTIAL_BYTES]).is_err() {
            self.first = Some(Failure::Credential);
            return;
        }
        let Some(source) = self.source.source() else {
            self.first = Some(Failure::Source);
            return;
        };
        let Some(bytes) = self.credentials.bytes(0) else {
            self.first = Some(Failure::Credential);
            return;
        };
        self.decoded = Some(if bytes != source.bytes.as_slice() {
            Err(invalid("output credential differs from protected source"))
        } else {
            decode_credential(bytes).map(|(capacity, key)| (capacity, Some(key)))
        });
        let Some(Ok((capacity, key))) = self.decoded.as_mut() else {
            self.first = Some(Failure::Decode);
            return;
        };
        if self.ledger.open_once_v1(receiving, *capacity, key).is_err() {
            self.first = Some(Failure::Ledger);
        }
    }

    fn observe_source_post(&mut self, path: &Path) -> Result<(), StorageServiceError> {
        self.source_post.capture_once(path)
            .map_err(|_| invalid("output credential source changed"))?;
        let original = self.source.source().ok_or_else(|| invalid("output credential source changed"))?;
        let current = self.source_post.source().ok_or_else(|| invalid("output credential source changed"))?;
        if original.path != current.path || original.identity != current.identity || original.bytes != current.bytes {
            return Err(invalid("output credential source changed"));
        }
        Ok(())
    }

    pub(crate) fn take_once_v1(&mut self) -> Option<StorageExecutionOutputCustodyV1> {
        if self.first.is_some() || self.taken { return None; }
        self.taken = true;
        self.ready.take()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let cause: Option<&(dyn std::error::Error + 'static)> = match self.first? {
            Failure::Demand => self.demand.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Failure::Payment => self.payment.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Failure::Source => self.source.failure(),
            Failure::Credential => self.credentials.capture_failure(),
            Failure::Decode => self.decoded.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Failure::Ledger | Failure::Names => self.ledger.failure(),
            Failure::SourcePost => self.source_post.failure().or_else(|| self.source_post_result.as_ref()
                .and_then(|result| result.as_ref().err()).map(|cause| cause as _)),
            Failure::CredentialPost => self.credentials.post_failure(),
            Failure::Current => self.current.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _),
            Failure::Closed => None,
        };
        cause.or(Some(&aos_sandbox::StorageReceivingClosedV1))
    }

    pub(super) fn fixed_demand(source: &Path) -> Result<ResourceVector, AccountingError> {
        use crate::receiving_demand::{add, count, multiply};

        let depth = count(source.components().count())?;
        let steps = multiply(multiply(depth, 4)?, count(SourceOriginal::parent_step_bytes())?)?;
        let paths = multiply(count(source.as_os_str().len())?, 8)?;
        let memory = add(count(std::mem::size_of::<Self>())?, add(steps, add(paths, 16 * 1024)?)?)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::OpenFiles, add(multiply(depth, 2)?, 12)?)
            .with(D::MetadataEntries, add(multiply(depth, 6)?, 64)?))
    }
}
