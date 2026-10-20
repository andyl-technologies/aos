//! Publishes Root's real protected Environment boot-clock evidence.
//!
//! The actual Environment purpose pays the fixed capture before construction,
//! the original extent before replay, and the exact encoded append before any
//! record/transaction growth. The same protected UID0 journal and captured
//! append owner remain resident while its authenticated Root interval is lent.
//! Policy expiry comes from the existing signed held-head verifier; the native
//! boot and paired time come only from this actual Root kernel clock owner.

use std::error::Error;
use std::mem::size_of;
use aos_sandbox_core::{ObjectDigest, RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::controller_resource_reservation::RootContinuationDemandV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::{CapturedJournalOpenModeV1, CommitResult,
    EnvironmentEvidenceCapturedJournalOpenV1, JournalRecord, JournalTransaction};
use crate::normal_root::RootEnvironmentStageReceivingV1;
use crate::policy_compiler::{RetainedKernelPairedClockAttemptV1,
    continuation_policy::RootEnvironmentPolicyOriginalV1};

#[derive(Clone, Copy)]
enum First { BeforeClock, Opening, NativeAdmission, Previous, Prerequisite, PublishAdmission, Record, Transaction, Commit, Readback, AfterClock, ClockBinding, Reentry }

#[derive(Debug, thiserror::Error)]
pub(crate) enum RootEnvironmentEvidenceErrorV1 {
    #[error("Root Environment evidence interval is incomplete or already entered")]
    Closed,
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Evidence(#[from] EnvironmentProtectedEvidenceErrorV1),
    #[error(transparent)]
    Clock(#[from] SourceGenesisErrorV1),
}

pub(crate) struct RootEnvironmentEvidenceOriginalV1 {
    opening: EnvironmentEvidenceCapturedJournalOpenV1,
    opened: Option<(Journal, RecoveryReport)>,
    before_original: RetainedKernelPairedClockAttemptV1,
    before: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    previous: Option<Result<Option<DecodedEnvironmentEvidenceV1>, EnvironmentProtectedEvidenceErrorV1>>,
    native_admission: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    publish_admission: Option<Result<(), crate::normal_root::NormalRootStartupErrorV1>>,
    record: Option<Result<Vec<u8>, EnvironmentProtectedEvidenceErrorV1>>,
    transaction: Option<Result<JournalTransaction, JournalError>>,
    commit: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<(), EnvironmentProtectedEvidenceErrorV1>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    clock_binding: Option<Result<(), EnvironmentProtectedEvidenceErrorV1>>,
    first: Option<First>,
    primary: Option<Result<(), RootEnvironmentEvidenceErrorV1>>,
    closed: Option<RootEnvironmentEvidenceErrorV1>,
    entered: bool,
    prepared: bool,
    published: bool,
    after_entered: bool,
}

impl RootEnvironmentEvidenceOriginalV1 {
    pub(crate) fn begin_once_v1(stage: &mut RootEnvironmentStageReceivingV1<'_, '_>)
        -> Result<Self, RootEnvironmentEvidenceErrorV1>
    {
        let bytes = size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(
                RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()?.checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let fixed = EnvironmentEvidenceCapturedJournalOpenV1::fixed_preparation_demand()
            .map_err(|_| JournalError::JournalTooLarge)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
                .with(D::OpenFiles, 2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1 as u64))
            .map_err(|_| JournalError::JournalTooLarge)?;
        stage.admit_environment_evidence_fixed_once_v1(RootContinuationDemandV1::from_demand_v1(fixed))
            .map_err(|_| RootEnvironmentEvidenceErrorV1::Closed)?;
        let mut original = Self {
            opening: EnvironmentEvidenceCapturedJournalOpenV1::new(), opened: None,
            before_original: Default::default(), before: None, previous: None,
            native_admission: None, publish_admission: None, record: None,
            transaction: None, commit: None, readback: None,
            after_original: Default::default(), after: None, clock_binding: None,
            first: None, primary: None, closed: None, entered: true,
            prepared: false, published: false, after_entered: false,
        };
        original.before = Some(original.before_original.observe_once(None));
        if !matches!(original.before, Some(Ok(_))) { original.first = Some(First::BeforeClock); }
        // The whole returned owner exists even when the first native clock
        // failed. Its caller must retain it and always run its paid after.
        Ok(original)
    }

    pub(crate) fn clock_v1(&self) -> Option<RawPairedClockSample> {
        if self.first.is_some() { return None; }
        self.before.as_ref()?.as_ref().ok().copied()
    }

    pub(crate) fn prepare_once_v1(&mut self, stage: &mut RootEnvironmentStageReceivingV1<'_, '_>)
        -> Result<(), RootEnvironmentEvidenceErrorV1>
    {
        if self.prepared || self.first.is_some() || self.after_entered {
            self.closed.get_or_insert(RootEnvironmentEvidenceErrorV1::Closed);
            self.first.get_or_insert(First::Reentry);
            return Err(RootEnvironmentEvidenceErrorV1::Closed);
        }
        self.prepared = true;
        self.primary = Some(self.prepare_inner(stage));
        if matches!(self.primary, Some(Ok(()))) { Ok(()) }
        else { Err(RootEnvironmentEvidenceErrorV1::Closed) }
    }

    fn prepare_inner(&mut self, stage: &mut RootEnvironmentStageReceivingV1<'_, '_>)
        -> Result<(), RootEnvironmentEvidenceErrorV1>
    {
        self.first = Some(First::Opening);
        self.opening.prepare_once(environment_evidence_journal_limits(), CapturedJournalOpenModeV1::CreateAndRepair);
        let extent = self.opening.captured_extent().ok_or(RootEnvironmentEvidenceErrorV1::Closed)?;
        let bytes = usize::try_from(extent.native_bytes).ok().and_then(|bytes| bytes.checked_mul(8))
            .and_then(|bytes| bytes.checked_add(MAXIMUM_PREDECESSOR_BOOTS.checked_mul(size_of::<ObjectDigest>())?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let demand = extent.dominant_native_receiving_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| JournalError::JournalTooLarge)?;
        self.first = Some(First::NativeAdmission);
        self.native_admission = Some(stage.admit_environment_evidence_native_once_v1(
            RootContinuationDemandV1::from_demand_v1(demand)));
        if !matches!(self.native_admission, Some(Ok(()))) { return Err(RootEnvironmentEvidenceErrorV1::Closed); }
        self.first = Some(First::Opening);
        self.opening.replay_once();
        self.opened = self.opening.take_opened();
        let (journal, _) = self.opened.as_mut().ok_or(RootEnvironmentEvidenceErrorV1::Closed)?;
        self.first = Some(First::Previous);
        self.previous = Some((|| {
            let authority = journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?;
            let mut rows = authority.records()?;
            match (rows.next(), rows.next()) {
                (None, None) => Ok(None),
                (Some((key, value)), None) if key == PROTECTED_ENVIRONMENT_EVIDENCE_KEY =>
                    decode_evidence(value).map(Some),
                _ => Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence),
            }
        })());
        if !matches!(self.previous, Some(Ok(_))) { return Err(RootEnvironmentEvidenceErrorV1::Closed); }
        self.first = None;
        Ok(())
    }

    pub(crate) fn publish_once_v1(
        &mut self, stage: &mut RootEnvironmentStageReceivingV1<'_, '_>,
        policy: &RootEnvironmentPolicyOriginalV1,
        deployment: &crate::environment::deployment::RootEnvironmentDeploymentOriginalV1,
        compiler: &crate::policy_compiler::provisioning_current::RootEnvironmentCompilerOriginalV1,
    ) -> Result<(), RootEnvironmentEvidenceErrorV1> {
        if self.published || self.first.is_some() || self.after_entered || !self.prepared {
            self.closed.get_or_insert(RootEnvironmentEvidenceErrorV1::Closed);
            self.first.get_or_insert(First::Reentry);
            return Err(RootEnvironmentEvidenceErrorV1::Closed);
        }
        self.published = true;
        self.primary = Some(self.publish_inner(stage, policy, deployment, compiler));
        if matches!(self.primary, Some(Ok(()))) { Ok(()) } else { Err(RootEnvironmentEvidenceErrorV1::Closed) }
    }

    fn publish_inner(
        &mut self, stage: &mut RootEnvironmentStageReceivingV1<'_, '_>,
        policy: &RootEnvironmentPolicyOriginalV1,
        deployment: &crate::environment::deployment::RootEnvironmentDeploymentOriginalV1,
        compiler: &crate::policy_compiler::provisioning_current::RootEnvironmentCompilerOriginalV1,
    ) -> Result<(), RootEnvironmentEvidenceErrorV1> {
        let before = self.clock_v1().ok_or(RootEnvironmentEvidenceErrorV1::Closed)?;
        self.first = Some(First::Prerequisite);
        if policy.verified_at_v1() != Some(before) || deployment.completed_v1().is_none() {
            return Err(RootEnvironmentEvidenceErrorV1::Closed);
        }
        let verified = policy.verified_v1().ok_or(RootEnvironmentEvidenceErrorV1::Closed)?;
        let expiry = verified.0.head().expires_at().min(verified.1.expires_at())
            .min(compiler.expires_at_v1()?);
        let expiry = u64::try_from(expiry).map_err(|_| RootEnvironmentEvidenceErrorV1::Closed)?;
        let authenticated = u64::try_from(before.wall_seconds()).map_err(|_| RootEnvironmentEvidenceErrorV1::Closed)?;
        let boot = super::super::authority_clock::linux_kernel_boot_commitment_v1(before.host_boot_id());
        let previous = self.previous.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootEnvironmentEvidenceErrorV1::Closed)?;
        let count = previous.as_ref().map_or(0, |old| old.predecessor_boots.len()
            + usize::from(old.current_boot != boot));
        if count > MAXIMUM_PREDECESSOR_BOOTS { return Err(RootEnvironmentEvidenceErrorV1::Closed); }
        let record_bytes = count.checked_mul(32).and_then(|bytes| bytes.checked_add(FIXED_PREFIX_BYTES + DIGEST_BYTES))
            .ok_or(JournalError::JournalTooLarge)?;
        let encoded = encoded_transaction_append_bytes([RecordShape {
            key_bytes: PROTECTED_ENVIRONMENT_EVIDENCE_KEY.len(), value_bytes: Some(record_bytes),
        }].into_iter()).map_err(|_| JournalError::JournalTooLarge)?;
        let bytes = record_bytes.checked_mul(8)
            .and_then(|bytes| bytes.checked_add(3 * size_of::<JournalTransaction>() + 4 * size_of::<JournalRecord>()))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let journal = &self.opened.as_ref().ok_or(RootEnvironmentEvidenceErrorV1::Closed)?.0;
        let demand = journal.captured_append_receiving_demand_v1(encoded)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::StorageBytes, encoded)
                .with(D::MetadataEntries, u64::from(previous.is_none())))
            .map_err(|_| JournalError::JournalTooLarge)?;
        self.first = Some(First::PublishAdmission);
        self.publish_admission = Some(stage.admit_environment_evidence_publish_once_v1(
            RootContinuationDemandV1::from_demand_v1(demand)));
        if !matches!(self.publish_admission, Some(Ok(()))) { return Err(RootEnvironmentEvidenceErrorV1::Closed); }
        self.first = Some(First::Record);
        self.record = Some((|| {
            let mut predecessors = previous.as_ref().map_or_else(Vec::new, |old| old.predecessor_boots.clone());
            if let Some(old) = previous.as_ref().filter(|old| old.current_boot != boot) {
                predecessors.push(old.current_boot);
                predecessors.sort();
                predecessors.dedup();
            }
            format::encode_evidence_v1(boot, EnvironmentLeaseTimeV1::new(before.boottime_nanoseconds())
                .map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?,
                authenticated, expiry, &predecessors)
        })());
        let record = self.record.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootEnvironmentEvidenceErrorV1::Closed)?;
        let identity: [u8; 32] = Sha256::new().chain_update(b"aos.sandbox.environment.root-evidence-transaction.v1\0")
            .chain_update(record).finalize().into();
        let mut transaction_id = [0; 16];
        transaction_id.copy_from_slice(&identity[..16]);
        self.first = Some(First::Transaction);
        self.transaction = Some(JournalTransaction::new(transaction_id, vec![JournalRecord::put(
            RecordNamespace::RuntimeAuthority, PROTECTED_ENVIRONMENT_EVIDENCE_KEY.to_vec(), record.clone(),
        )]).map_err(JournalError::from));
        let transaction = self.transaction.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootEnvironmentEvidenceErrorV1::Closed)?;
        self.first = Some(First::Commit);
        let journal = &mut self.opened.as_mut().ok_or(RootEnvironmentEvidenceErrorV1::Closed)?.0;
        self.commit = Some(journal.claim_protected_authority(RecordNamespace::RuntimeAuthority)?.commit(transaction));
        if !matches!(self.commit, Some(Ok(_))) { return Err(RootEnvironmentEvidenceErrorV1::Closed); }
        self.first = Some(First::Readback);
        self.readback = Some(if journal.get(RecordNamespace::RuntimeAuthority, PROTECTED_ENVIRONMENT_EVIDENCE_KEY)
            == Some(record.as_slice()) { Ok(()) } else { Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence) });
        if !matches!(self.readback, Some(Ok(()))) { return Err(RootEnvironmentEvidenceErrorV1::Closed); }
        self.first = None;
        Ok(())
    }

    pub(crate) fn finish_available_once_v1(&mut self) -> Result<(), RootEnvironmentEvidenceErrorV1> {
        if self.after_entered || !self.entered {
            self.closed.get_or_insert(RootEnvironmentEvidenceErrorV1::Closed);
            self.first.get_or_insert(First::Reentry);
            return Err(RootEnvironmentEvidenceErrorV1::Closed);
        }
        self.after_entered = true;
        self.after = Some(self.after_original.observe_once(
            self.before.as_ref().and_then(|value| value.as_ref().ok()).copied()));
        if !matches!(self.after, Some(Ok(_))) { self.first.get_or_insert(First::AfterClock); }
        self.clock_binding = Some((|| {
            let before = self.before.as_ref().and_then(|value| value.as_ref().ok()).copied()
                .ok_or(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
            let after = self.after.as_ref().and_then(|value| value.as_ref().ok()).copied()
                .ok_or(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
            before.validate_later_sample(after).map_err(|_| EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
            let record = self.record.as_ref().and_then(|value| value.as_ref().ok())
                .ok_or(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence)?;
            let decoded = decode_evidence(record)?;
            if after.wall_seconds() < 0 || u64::try_from(after.wall_seconds()).ok()
                .is_none_or(|wall| wall >= decoded.valid_until_unix_seconds)
            { return Err(EnvironmentProtectedEvidenceErrorV1::InvalidEvidence); }
            Ok(())
        })());
        if !matches!(self.clock_binding, Some(Ok(()))) { self.first.get_or_insert(First::ClockBinding); }
        if self.failure().is_none() && matches!(self.commit, Some(Ok(_)))
            && matches!(self.readback, Some(Ok(()))) && matches!(self.clock_binding, Some(Ok(())))
        { Ok(()) } else { Err(RootEnvironmentEvidenceErrorV1::Closed) }
    }

    pub(crate) fn completed_record_v1(&self) -> Option<&[u8]> {
        if !self.after_entered || self.failure().is_some() || !matches!(self.clock_binding, Some(Ok(()))) { return None; }
        self.record.as_ref()?.as_ref().ok().map(Vec::as_slice)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            Some(First::BeforeClock) => self.before_original.failure().or_else(|| cause(&self.before)),
            Some(First::Opening) => self.opening.failure(),
            Some(First::NativeAdmission) => cause(&self.native_admission),
            Some(First::Previous) => cause(&self.previous),
            Some(First::Prerequisite) => cause(&self.primary),
            Some(First::PublishAdmission) => cause(&self.publish_admission),
            Some(First::Record) => cause(&self.record),
            Some(First::Transaction) => cause(&self.transaction),
            Some(First::Commit) => self.opened.as_ref().and_then(|(journal, _)| journal.retained_native_append_failure_v1())
                .or_else(|| cause(&self.commit)),
            Some(First::Readback) => cause(&self.readback),
            Some(First::AfterClock) => self.after_original.failure().or_else(|| cause(&self.after)),
            Some(First::ClockBinding) => cause(&self.clock_binding),
            Some(First::Reentry) => self.closed.as_ref().map(|cause| cause as _),
            None => None,
        };
        selected.or_else(|| cause(&self.primary)).or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
