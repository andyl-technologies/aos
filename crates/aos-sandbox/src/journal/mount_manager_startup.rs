//! Purpose-limited journal authority for one Mount-manager startup capture.
//!
//! The scope reads exactly namespaces 40, 39, 2, and 45, derives the complete
//! startup expectation and absence tables, and may append exactly one immutable
//! namespace-45 `AOSMMCAP1` row. It cannot mutate source lifecycle state.

use std::sync::Arc;

use aos_sandbox_protocol::mount_manager_startup::{
    DerivedMountManagerStartupV1, ManagerControlPolicyWitnessV1, ManagerControlSourceV1,
    MountManagerStartupCaptureV1, MountManagerStartupPolicyV1, StartupSourceSubjectV1,
    decode_mount_manager_startup_policy_v1, encode_mount_manager_startup_capture_v1,
    encode_mount_manager_startup_policy_v1, is_mount_manager_startup_capture_key_v1,
    is_mount_manager_startup_policy_history_key_v1, mount_manager_startup_capture_key_v1,
    mount_manager_startup_policy_history_key_v1, mount_manager_startup_policy_key_v1,
    validate_mount_manager_startup_capture_history_v1,
    validate_mount_manager_startup_capture_policy_v1,
    validate_mount_manager_startup_capture_successor_v1,
    validate_mount_manager_startup_policy_history_v1,
    validate_mount_manager_startup_policy_successor_v1,
};
use aos_sandbox_protocol::mount_source_acquisition_state::{
    ProviderIntentV2, ProviderMethodV2, ProviderQueryOwnerV2, RecordRefV2, ReleaseProofV2,
    SourceProviderSessionV2, validate_mount_source_state_graph_v2,
};
use sha2::{Digest as _, Sha256};

use super::{
    JournalAuthorityInstance, JournalError, JournalRecord, JournalTransaction,
    ProtectedAuthorityScope, ProtectedJournalAuthority, ProtectedJournalSnapshot, RecordNamespace,
};

/// Retains one current, fully derived startup state behind an opaque snapshot.
#[must_use = "prepared startup state must be committed or discarded"]
pub struct MountManagerStartupPreparedStateV1 {
    snapshot: ProtectedJournalSnapshot,
    policy: MountManagerStartupPolicyV1,
    derived: DerivedMountManagerStartupV1,
    previous_capture: Option<MountManagerStartupCaptureV1>,
    absence_death_subjects: Vec<MountManagerStartupDeathSubjectV1>,
}

/// Binds one eligible absence to the exact persisted last custody execution.
#[derive(Clone)]
pub(crate) struct MountManagerStartupDeathSubjectV1 {
    pub(crate) acquisition_id: [u8; 32],
    pub(crate) terminal_proof_attempt: RecordRefV2,
    pub(crate) terminal_proof_session: SourceProviderSessionV2,
    pub(crate) last_custody_attempt: RecordRefV2,
    pub(crate) last_custody_session: SourceProviderSessionV2,
}

/// Proves exact preflight of one internally constructed capture append.
#[must_use = "startup preflight must be consumed by its exact commit"]
pub struct MountManagerStartupCapturePreflightV1 {
    snapshot: ProtectedJournalSnapshot,
    transaction: JournalTransaction,
    capture: MountManagerStartupCaptureV1,
}

/// Classifies exact replay of one staged startup capture after an ambiguous append.
pub(crate) enum MountManagerStartupCaptureRecoveryV1 {
    /// The exact staged row is the canonical durable history tail.
    Applied,
    /// The staged row is absent and remains valid for one exact retry.
    Retry(MountManagerStartupCapturePreflightV1),
}

/// Records the exact durable boundary of one startup capture append.
#[must_use = "startup capture receipt carries durable provenance"]
pub struct MountManagerStartupCaptureReceiptV1 {
    before_sequence: u64,
    after_sequence: u64,
    capture_sequence: u64,
    capture_id: [u8; 32],
    capture_record_digest: [u8; 32],
}

/// Records one exact protected offline startup-policy advancement.
#[must_use = "startup policy receipt carries durable provenance"]
pub struct MountManagerStartupPolicyReceiptV1 {
    instance: Arc<JournalAuthorityInstance>,
    sequence: u64,
    generation: u64,
    record_digest: [u8; 32],
}

impl MountManagerStartupPreparedStateV1 {
    pub(crate) const fn policy(&self) -> &MountManagerStartupPolicyV1 {
        &self.policy
    }

    pub(crate) const fn derived(&self) -> &DerivedMountManagerStartupV1 {
        &self.derived
    }

    pub(crate) fn next_capture_link(&self) -> Result<(u64, [u8; 32]), JournalError> {
        match &self.previous_capture {
            Some(previous) => Ok((
                previous
                    .capture_sequence
                    .checked_add(1)
                    .ok_or(JournalError::SequenceExhausted)?,
                previous.record_digest,
            )),
            None => Ok((1, [0; 32])),
        }
    }

    pub(crate) fn absence_death_subjects(&self) -> &[MountManagerStartupDeathSubjectV1] {
        &self.absence_death_subjects
    }
}

impl MountManagerStartupCaptureReceiptV1 {
    /// Returns the immutable capture sequence, identity, and record digest.
    #[must_use]
    pub const fn capture(&self) -> (u64, [u8; 32], [u8; 32]) {
        (
            self.capture_sequence,
            self.capture_id,
            self.capture_record_digest,
        )
    }

    /// Returns the journal sequence interval occupied by the atomic append.
    #[must_use]
    pub const fn journal_sequence_interval(&self) -> (u64, u64) {
        (self.before_sequence, self.after_sequence)
    }
}

impl MountManagerStartupPolicyReceiptV1 {
    /// Returns the immutable policy generation and record digest.
    #[must_use]
    pub const fn policy(&self) -> (u64, [u8; 32]) {
        (self.generation, self.record_digest)
    }

    /// Revalidates that this exact policy remains the current protected head.
    ///
    /// # Errors
    ///
    /// Returns an error after compaction, replacement, another journal
    /// instance, or any policy-head rewrite.
    pub fn validate_current(
        &self,
        authority: &ProtectedJournalAuthority<'_>,
    ) -> Result<(), JournalError> {
        authority.validate_mount_manager_startup_authority()?;
        let key = mount_manager_startup_policy_key_v1();
        let current = authority
            .journal
            .get(RecordNamespace::MountManagerStartupAuthority, &key)
            .ok_or(JournalError::AuthorityPreflightMismatch)?;
        let policy = decode_mount_manager_startup_policy_v1(current)
            .map_err(|_| JournalError::MalformedRecord("invalid startup policy head"))?;
        if !Arc::ptr_eq(&self.instance, &authority.journal.authority_instance)
            || self.sequence > authority.journal.snapshot_sequence()
            || (policy.generation, policy.record_digest) != (self.generation, self.record_digest)
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }
}

impl ProtectedJournalAuthority<'_> {
    pub(crate) fn validate_manager_control_source_descendant_v1(
        &self,
        source: &ManagerControlSourceV1,
        capture_id: [u8; 32],
        capture_record_digest: [u8; 32],
    ) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        if !matches!(
            (self.namespace, self.scope),
            (
                RecordNamespace::MountSourceAcquisition,
                ProtectedAuthorityScope::SingleNamespace
                    | ProtectedAuthorityScope::MountSourceConsumption
            ) | (
                RecordNamespace::MountManagerStartupAuthority,
                ProtectedAuthorityScope::MountManagerStartup
            )
        ) {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let graph = validate_mount_source_state_graph_v2(
            self.journal
                .records(RecordNamespace::MountSourceAcquisition),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup acquisition graph"))?;
        let row = graph
            .acquisitions
            .get(&source.acquisition_id)
            .ok_or(JournalError::AuthorityPreflightMismatch)?;
        let evidence = row
            .evidence
            .as_ref()
            .ok_or(JournalError::AuthorityPreflightMismatch)?;
        if row.revision < source.acquisition_revision
            || row.negative_custody_digest.is_some()
            || evidence.source_realization_handle != source.source_realization_handle
            || evidence.descriptor_commitment != source.descriptor_commitment
            || evidence.source_kernel_boot_id != source.kernel_boot_id
            || evidence.source_device != source.device
            || evidence.source_inode != source.inode
            || evidence.source_unique_mount_id != source.unique_mount_id
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let captures = validate_mount_manager_startup_capture_history_v1(
            self.journal
                .records(RecordNamespace::MountManagerStartupAuthority)
                .filter(|(key, _)| is_mount_manager_startup_capture_key_v1(key)),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup capture history"))?;
        if !captures.iter().any(|capture| {
            (capture.capture_id, capture.record_digest) == (capture_id, capture_record_digest)
        }) {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_mount_manager_source_proof_current_v1(
        &self,
        acquisition_id: [u8; 32],
        acquisition_revision: u64,
        acquisition_record_digest: [u8; 32],
        capture_id: [u8; 32],
        capture_record_digest: [u8; 32],
    ) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        if !matches!(
            (self.namespace, self.scope),
            (
                RecordNamespace::MountSourceAcquisition,
                ProtectedAuthorityScope::SingleNamespace
                    | ProtectedAuthorityScope::MountSourceConsumption
            ) | (
                RecordNamespace::MountManagerStartupAuthority,
                ProtectedAuthorityScope::MountManagerStartup
            )
        ) {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let graph = validate_mount_source_state_graph_v2(
            self.journal
                .records(RecordNamespace::MountSourceAcquisition),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup acquisition graph"))?;
        let row = graph
            .acquisitions
            .get(&acquisition_id)
            .ok_or(JournalError::AuthorityPreflightMismatch)?;
        if (row.revision, row.record_digest) != (acquisition_revision, acquisition_record_digest) {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        let captures = validate_mount_manager_startup_capture_history_v1(
            self.journal
                .records(RecordNamespace::MountManagerStartupAuthority)
                .filter(|(key, _)| is_mount_manager_startup_capture_key_v1(key)),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup capture history"))?;
        if !captures.iter().any(|capture| {
            (capture.capture_id, capture.record_digest) == (capture_id, capture_record_digest)
        }) {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        Ok(())
    }

    pub(crate) fn validate_manager_control_policy_witness_v1(
        &self,
        witness: &ManagerControlPolicyWitnessV1,
        require_current: bool,
    ) -> Result<(), JournalError> {
        self.validate_mount_manager_startup_scope()?;
        let policy_key = mount_manager_startup_policy_key_v1();
        let current = self
            .journal
            .get(RecordNamespace::MountManagerStartupAuthority, &policy_key)
            .map(decode_mount_manager_startup_policy_v1)
            .transpose()
            .map_err(|_| JournalError::MalformedRecord("invalid startup policy head"))?
            .ok_or(JournalError::MalformedRecord(
                "startup policy head is absent",
            ))?;
        let history = validate_mount_manager_startup_policy_history_v1(
            self.journal
                .records(RecordNamespace::MountManagerStartupAuthority)
                .filter(|(key, _)| is_mount_manager_startup_policy_history_key_v1(key)),
            &current,
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup policy history"))?;
        let policy = if witness.policy_generation == current.generation {
            &current
        } else {
            history
                .iter()
                .find(|policy| policy.generation == witness.policy_generation)
                .ok_or(JournalError::AuthorityPreflightMismatch)?
        };
        if (
            witness.policy_digest,
            witness.control_key_id,
            witness.control_key_generation,
            witness.control_public_key,
        ) != (
            policy.record_digest,
            policy.manager_control_key_id,
            policy.manager_control_key_generation,
            policy.manager_control_public_key,
        ) || (require_current && policy.generation != current.generation)
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }

        let captures = validate_mount_manager_startup_capture_history_v1(
            self.journal
                .records(RecordNamespace::MountManagerStartupAuthority)
                .filter(|(key, _)| is_mount_manager_startup_capture_key_v1(key)),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup capture history"))?;
        let capture = captures
            .iter()
            .find(|capture| capture.capture_sequence == witness.capture_sequence)
            .ok_or(JournalError::AuthorityPreflightMismatch)?;
        let manager_execution_commitment =
            aos_sandbox_protocol::mount_manager_startup::startup_execution_identity_commitment_v1(
                &capture.execution,
            )
            .map_err(|_| JournalError::MalformedRecord("invalid manager execution"))?;
        if capture.capture_id != witness.capture_id
            || capture.record_digest != witness.capture_record_digest
            || capture.policy_generation != witness.policy_generation
            || capture.policy_digest != witness.policy_digest
            || capture.descriptor_count != witness.descriptor_count
            || capture.activation_count != witness.activation_count
            || capture.expected_descriptor_count != witness.expected_descriptor_count
            || capture.source_subject_count != witness.source_subject_count
            || capture.cleanup_subject_count != witness.cleanup_subject_count
            || capture.terminal_subject_count != witness.terminal_subject_count
            || capture.descriptor_table_digest != witness.descriptor_table_digest
            || capture.activation_table_digest != witness.activation_table_digest
            || capture.expected_table_digest != witness.expected_table_digest
            || capture.source_subjects_digest != witness.source_subjects_digest
            || manager_execution_commitment != witness.manager_execution_commitment
            || capture.execution != witness.manager_execution
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        Ok(())
    }

    /// Installs one canonical monotone startup policy through the sealed ns45 path.
    ///
    /// Generic namespace-45 record and transaction APIs are deliberately
    /// unavailable. This offline provisioning seam accepts only the exact
    /// `AOSMMSTA1` key/value and validates its predecessor before commit.
    ///
    /// # Errors
    ///
    /// Returns an error for another namespace/scope, malformed existing
    /// history, a discontinuous policy successor, or failed durability.
    #[doc(hidden)]
    pub fn install_mount_manager_startup_policy_v1(
        &mut self,
        policy: MountManagerStartupPolicyV1,
    ) -> Result<MountManagerStartupPolicyReceiptV1, JournalError> {
        self.validate_mount_manager_startup_authority()?;
        let policy_key = mount_manager_startup_policy_key_v1();
        let previous = self
            .journal
            .get(RecordNamespace::MountManagerStartupAuthority, &policy_key)
            .map(decode_mount_manager_startup_policy_v1)
            .transpose()
            .map_err(|_| JournalError::MalformedRecord("invalid startup policy head"))?;
        if let Some(previous) = previous.as_ref() {
            validate_mount_manager_startup_policy_history_v1(
                self.journal
                    .records(RecordNamespace::MountManagerStartupAuthority)
                    .filter(|(key, _)| is_mount_manager_startup_policy_history_key_v1(key)),
                previous,
            )
            .map_err(|_| JournalError::MalformedRecord("invalid startup policy history"))?;
        } else if self
            .journal
            .records(RecordNamespace::MountManagerStartupAuthority)
            .any(|(key, _)| is_mount_manager_startup_policy_history_key_v1(key))
        {
            return Err(JournalError::MalformedRecord(
                "startup policy history exists without a head",
            ));
        }
        validate_mount_manager_startup_capture_history_v1(
            self.journal
                .records(RecordNamespace::MountManagerStartupAuthority)
                .filter(|(key, _)| is_mount_manager_startup_capture_key_v1(key)),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup capture history"))?;
        validate_mount_manager_startup_policy_successor_v1(previous.as_ref(), &policy)
            .map_err(|_| JournalError::MalformedRecord("startup policy is not monotone"))?;
        let value = encode_mount_manager_startup_policy_v1(&policy)
            .map_err(|_| JournalError::MalformedRecord("invalid startup policy"))?;
        let mut records = Vec::with_capacity(if previous.is_some() { 2 } else { 1 });
        if let Some(previous) = previous.as_ref() {
            let history_key = mount_manager_startup_policy_history_key_v1(previous.generation)
                .map_err(|_| JournalError::MalformedRecord("invalid startup policy history key"))?;
            if self
                .journal
                .get(RecordNamespace::MountManagerStartupAuthority, &history_key)
                .is_some()
            {
                return Err(JournalError::DuplicateRecordKey);
            }
            records.push(JournalRecord::put(
                RecordNamespace::MountManagerStartupAuthority,
                history_key,
                encode_mount_manager_startup_policy_v1(previous).map_err(|_| {
                    JournalError::MalformedRecord("invalid previous startup policy")
                })?,
            ));
        }
        records.push(JournalRecord::put(
            RecordNamespace::MountManagerStartupAuthority,
            policy_key,
            value,
        ));
        let transaction = JournalTransaction::new(
            startup_policy_transaction_id(policy.generation, policy.record_digest),
            records,
        )?;
        self.journal
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        self.journal.commit(&transaction)?;

        Ok(MountManagerStartupPolicyReceiptV1 {
            instance: Arc::clone(&self.journal.authority_instance),
            sequence: self.journal.snapshot_sequence(),
            generation: policy.generation,
            record_digest: policy.record_digest,
        })
    }

    pub(crate) fn prepare_mount_manager_startup_state_v1(
        &self,
        current_kernel_boot_id: [u8; 16],
    ) -> Result<MountManagerStartupPreparedStateV1, JournalError> {
        self.validate_mount_manager_startup_scope()?;
        let policy_key = mount_manager_startup_policy_key_v1();
        let policy_value = self
            .journal
            .get(RecordNamespace::MountManagerStartupAuthority, &policy_key)
            .ok_or(JournalError::MalformedTransaction(
                "Mount-manager startup policy head is absent",
            ))?;
        let policy = decode_mount_manager_startup_policy_v1(policy_value)
            .map_err(|_| JournalError::MalformedRecord("invalid startup policy head"))?;
        let mut policies = validate_mount_manager_startup_policy_history_v1(
            self.journal
                .records(RecordNamespace::MountManagerStartupAuthority)
                .filter(|(key, _)| is_mount_manager_startup_policy_history_key_v1(key)),
            &policy,
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup policy history"))?;
        policies.push(policy.clone());
        let captures = validate_mount_manager_startup_capture_history_v1(
            self.journal
                .records(RecordNamespace::MountManagerStartupAuthority)
                .filter(|(key, _)| is_mount_manager_startup_capture_key_v1(key)),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup capture history"))?;
        validate_capture_policy_history(&policies, &captures)?;
        let acquisition_records = self
            .journal
            .records(RecordNamespace::MountSourceAcquisition)
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect::<Vec<_>>();
        let acquisition_graph = validate_mount_source_state_graph_v2(
            acquisition_records
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup acquisition graph"))?;
        let derived = aos_sandbox_protocol::mount_manager_startup::derive_mount_manager_startup_v1(
            &policy,
            self.journal.snapshot_sequence(),
            current_kernel_boot_id,
            acquisition_records
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            self.journal.records(RecordNamespace::MountSourcePin),
            self.journal.records(RecordNamespace::Operation),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup source projection"))?;
        let absence_death_subjects = derived
            .source_subjects
            .iter()
            .filter_map(|subject| match subject {
                StartupSourceSubjectV1::Terminal(subject) => Some(startup_death_subject(
                    &acquisition_graph,
                    subject.acquisition_id,
                )),
                StartupSourceSubjectV1::Cleanup(_) => None,
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(MountManagerStartupPreparedStateV1 {
            snapshot: self.current_snapshot(),
            policy,
            derived,
            previous_capture: captures.last().cloned(),
            absence_death_subjects,
        })
    }

    pub(crate) fn preflight_mount_manager_startup_capture_v1(
        &self,
        prepared: MountManagerStartupPreparedStateV1,
        capture: MountManagerStartupCaptureV1,
    ) -> Result<MountManagerStartupCapturePreflightV1, JournalError> {
        self.validate_mount_manager_startup_scope()?;
        self.validate_snapshot(&prepared.snapshot)?;
        validate_mount_manager_startup_capture_policy_v1(&prepared.policy, &capture)
            .map_err(|_| JournalError::MalformedRecord("capture violates startup policy"))?;
        validate_mount_manager_startup_capture_successor_v1(
            prepared.previous_capture.as_ref(),
            &capture,
        )
        .map_err(|_| JournalError::MalformedRecord("capture history is discontinuous"))?;
        if capture.derivation != prepared.derived.head
            || capture.expected_descriptors != prepared.derived.expected_descriptors
            || capture.source_subjects != prepared.derived.source_subjects
            || capture.expected_table_digest != prepared.derived.expected_table_digest
            || capture.source_subjects_digest != prepared.derived.source_subjects_digest
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }

        let key = mount_manager_startup_capture_key_v1(capture.capture_sequence)
            .map_err(|_| JournalError::MalformedRecord("invalid startup capture key"))?;
        if self
            .journal
            .get(RecordNamespace::MountManagerStartupAuthority, &key)
            .is_some()
        {
            return Err(JournalError::DuplicateRecordKey);
        }
        let value = encode_mount_manager_startup_capture_v1(&capture)
            .map_err(|_| JournalError::MalformedRecord("invalid startup capture"))?;
        let transaction = JournalTransaction::new(
            startup_transaction_id(capture.capture_id),
            vec![JournalRecord::put(
                RecordNamespace::MountManagerStartupAuthority,
                key,
                value,
            )],
        )?;
        self.journal
            .preflight_transactions(std::slice::from_ref(&transaction))?;

        Ok(MountManagerStartupCapturePreflightV1 {
            snapshot: prepared.snapshot,
            transaction,
            capture,
        })
    }

    pub(crate) fn commit_mount_manager_startup_capture_v1(
        &mut self,
        preflight: &MountManagerStartupCapturePreflightV1,
    ) -> Result<MountManagerStartupCaptureReceiptV1, JournalError> {
        self.validate_mount_manager_startup_scope()?;
        self.validate_snapshot(&preflight.snapshot)?;
        let before_sequence = self.journal.snapshot_sequence();
        self.journal.commit(&preflight.transaction)?;

        Ok(MountManagerStartupCaptureReceiptV1 {
            before_sequence,
            after_sequence: self.journal.snapshot_sequence(),
            capture_sequence: preflight.capture.capture_sequence,
            capture_id: preflight.capture.capture_id,
            capture_record_digest: preflight.capture.record_digest,
        })
    }

    /// Replays one exact staged capture after its append outcome became unknown.
    pub(crate) fn recover_mount_manager_startup_capture_v1(
        &self,
        capture: &MountManagerStartupCaptureV1,
        current_kernel_boot_id: [u8; 16],
    ) -> Result<MountManagerStartupCaptureRecoveryV1, JournalError> {
        let prepared = self.prepare_mount_manager_startup_state_v1(current_kernel_boot_id)?;

        if prepared.previous_capture.as_ref() == Some(capture) {
            validate_recovered_capture_current(&prepared, capture)?;
            return Ok(MountManagerStartupCaptureRecoveryV1::Applied);
        }

        let preflight =
            self.preflight_mount_manager_startup_capture_v1(prepared, capture.clone())?;
        Ok(MountManagerStartupCaptureRecoveryV1::Retry(preflight))
    }

    /// Validates all protected histories needed before the fixed owner is exposed.
    pub(crate) fn validate_mount_manager_startup_replay_v1(
        &self,
    ) -> Result<(u64, usize), JournalError> {
        self.validate_mount_manager_startup_scope()?;
        let policy_key = mount_manager_startup_policy_key_v1();
        let policy = self
            .journal
            .get(RecordNamespace::MountManagerStartupAuthority, &policy_key)
            .map(decode_mount_manager_startup_policy_v1)
            .transpose()
            .map_err(|_| JournalError::MalformedRecord("invalid startup policy head"))?
            .ok_or(JournalError::MalformedRecord(
                "startup policy head is absent",
            ))?;
        let mut policies = validate_mount_manager_startup_policy_history_v1(
            self.journal
                .records(RecordNamespace::MountManagerStartupAuthority)
                .filter(|(key, _)| is_mount_manager_startup_policy_history_key_v1(key)),
            &policy,
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup policy history"))?;
        policies.push(policy.clone());
        let captures = validate_mount_manager_startup_capture_history_v1(
            self.journal
                .records(RecordNamespace::MountManagerStartupAuthority)
                .filter(|(key, _)| is_mount_manager_startup_capture_key_v1(key)),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup capture history"))?;
        validate_capture_policy_history(&policies, &captures)?;
        validate_mount_source_state_graph_v2(
            self.journal
                .records(RecordNamespace::MountSourceAcquisition),
        )
        .map_err(|_| JournalError::MalformedRecord("invalid startup acquisition graph"))?;

        Ok((policy.generation, captures.len()))
    }

    fn validate_mount_manager_startup_scope(&self) -> Result<(), JournalError> {
        self.journal.ensure_protected_authority()?;
        if self.scope != ProtectedAuthorityScope::MountManagerStartup {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Ok(())
    }
}

fn validate_capture_policy_history(
    policies: &[MountManagerStartupPolicyV1],
    captures: &[MountManagerStartupCaptureV1],
) -> Result<(), JournalError> {
    for capture in captures {
        let referenced_policy = policies
            .iter()
            .find(|candidate| candidate.generation == capture.policy_generation)
            .filter(|candidate| candidate.record_digest == capture.policy_digest)
            .ok_or(JournalError::MalformedRecord(
                "startup capture references an absent policy",
            ))?;
        validate_mount_manager_startup_capture_policy_v1(referenced_policy, capture)
            .map_err(|_| JournalError::MalformedRecord("startup capture violates policy"))?;
    }

    Ok(())
}

fn validate_recovered_capture_current(
    prepared: &MountManagerStartupPreparedStateV1,
    capture: &MountManagerStartupCaptureV1,
) -> Result<(), JournalError> {
    let derived = prepared.derived();
    let captured_head = capture.derivation;
    let current_head = derived.head;
    let source_state_is_exact = (
        current_head.acquisition_record_count,
        current_head.acquisition_state_digest,
        current_head.source_pin_record_count,
        current_head.source_pin_state_digest,
        current_head.mount_resource_record_count,
        current_head.mount_resource_state_digest,
    ) == (
        captured_head.acquisition_record_count,
        captured_head.acquisition_state_digest,
        captured_head.source_pin_record_count,
        captured_head.source_pin_state_digest,
        captured_head.mount_resource_record_count,
        captured_head.mount_resource_state_digest,
    );
    if (
        prepared.policy().generation,
        prepared.policy().record_digest,
    ) != (capture.policy_generation, capture.policy_digest)
        || !source_state_is_exact
        || derived.expected_descriptors != capture.expected_descriptors
        || derived.source_subjects != capture.source_subjects
        || derived.expected_table_digest != capture.expected_table_digest
        || derived.source_subjects_digest != capture.source_subjects_digest
    {
        return Err(JournalError::StaleAuthoritySnapshot);
    }

    Ok(())
}

fn startup_death_subject(
    graph: &aos_sandbox_protocol::mount_source_acquisition_state::MountSourceAcquisitionStateV2,
    acquisition_id: [u8; 32],
) -> Result<MountManagerStartupDeathSubjectV1, JournalError> {
    let row = graph
        .acquisitions
        .get(&acquisition_id)
        .ok_or(JournalError::MalformedRecord(
            "absence acquisition is absent",
        ))?;
    let release_proof = row
        .release_proof
        .as_ref()
        .ok_or(JournalError::MalformedRecord(
            "absence release proof is absent",
        ))?;
    let terminal_proof_attempt = match release_proof {
        ReleaseProofV2::ProviderReceipt { attempt, .. }
        | ReleaseProofV2::ProviderInventory { attempt, .. } => *attempt,
    };
    let terminal_attempt = graph
        .provider_attempts
        .get(&terminal_proof_attempt.id)
        .filter(|attempt| {
            attempt.revision == terminal_proof_attempt.revision
                && attempt.record_digest == terminal_proof_attempt.record_digest
                && attempt.scope == row.scope
        })
        .ok_or(JournalError::MalformedRecord(
            "absence terminal proof attempt is inconsistent",
        ))?;
    let terminal_proof_session = graph
        .provider_sessions
        .get(&terminal_attempt.session_id)
        .filter(|session| {
            session.session_id == terminal_attempt.session_id
                && session.record_digest == terminal_attempt.session_record_digest
                && session.scope == row.scope
        })
        .ok_or(JournalError::MalformedRecord(
            "absence terminal proof session is inconsistent",
        ))?
        .clone();
    let last_custody_attempt = match release_proof {
        ReleaseProofV2::ProviderReceipt { attempt, .. } => *attempt,
        ReleaseProofV2::ProviderInventory { .. } => row
            .release_lineage
            .as_ref()
            .map(|lineage| lineage.tail)
            .ok_or(JournalError::MalformedRecord(
                "absence Release lineage is absent",
            ))?,
    };
    let attempt = graph
        .provider_attempts
        .get(&last_custody_attempt.id)
        .filter(|attempt| {
            attempt.revision == last_custody_attempt.revision
                && attempt.record_digest == last_custody_attempt.record_digest
                && attempt.method == ProviderMethodV2::Release
                && attempt.scope == row.scope
                && matches!(
                    (&attempt.owner, &attempt.intent),
                    (
                        ProviderQueryOwnerV2::Release { acquisition_id: owner },
                        ProviderIntentV2::Release { value },
                    ) if *owner == acquisition_id
                        && value.acquisition_id == acquisition_id
                        && value.provider_acquisition == row.provider_acquisition
                )
        })
        .ok_or(JournalError::MalformedRecord(
            "absence Release attempt is inconsistent",
        ))?;
    let last_custody_session = graph
        .provider_sessions
        .get(&attempt.session_id)
        .filter(|session| {
            session.session_id == attempt.session_id
                && session.record_digest == attempt.session_record_digest
                && session.scope == row.scope
        })
        .ok_or(JournalError::MalformedRecord(
            "absence Release session is inconsistent",
        ))?
        .clone();
    Ok(MountManagerStartupDeathSubjectV1 {
        acquisition_id,
        terminal_proof_attempt,
        terminal_proof_session,
        last_custody_attempt,
        last_custody_session,
    })
}

fn startup_transaction_id(capture_id: [u8; 32]) -> [u8; 16] {
    let digest = Sha256::digest(
        [
            b"aos.sandbox.mount-manager.startup-transaction.v1\0".as_slice(),
            capture_id.as_slice(),
        ]
        .concat(),
    );
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    identity
}

fn startup_policy_transaction_id(generation: u64, record_digest: [u8; 32]) -> [u8; 16] {
    let digest = Sha256::digest(
        [
            b"aos.sandbox.mount-manager.startup-policy-transaction.v1\0".as_slice(),
            generation.to_be_bytes().as_slice(),
            record_digest.as_slice(),
        ]
        .concat(),
    );
    let mut identity = [0; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    identity
}
