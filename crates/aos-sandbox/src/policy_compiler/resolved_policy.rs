//! Structural Policy-state readback under the real fixed state writer.
//!
//! Canonical state is not authenticated policy authority. This owner opens
//! only the existing `state.journal`, never Root's `authority.journal`. Its
//! borrowed claim must be authenticated independently by a genuine Root-last
//! flight, including pinned signing context, floors, retained input/history,
//! exact candidate and Policy output. Byte equality alone is insufficient.

use std::path::Path;

#[cfg(test)]
use std::path::PathBuf;

use aos_sandbox_core::format::decode_policy;
use aos_sandbox_core::model::Policy;
use aos_sandbox_core::{
    DecodeLimits, MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, ProjectId,
    SandboxId,
};

use super::protected_journal::{
    decode_current_payload, policy_current_key, policy_key, validate_state_candidate_body,
    validated_candidate_body,
};
use super::protected_owner::{
    POLICY_STATE_JOURNAL, PROTECTED_POLICY_ROOT, policy_state_journal_limits,
};
use super::{
    PolicyCompilerJournalErrorV1, PolicyCompilerJournalRecordKindV1, PolicyCompilerJournalSchemaV1,
    PolicyPublicationPrerequisitesV1,
};
use crate::lifecycle::protected_journal_adapter::{
    ProtectedCurrentRecordCandidateV1, protected_current_record_candidates_v1,
};
use crate::{Journal, RecoveryReport};

#[cfg(test)]
pub(super) mod tests;

/// Retains the existing fixed Policy state writer without acquiring Root early.
///
/// Its readback is strictly nonauthorizing. Existing authenticated bootstrap
/// replay and publication owners remain unchanged. There is no caller-chosen
/// policy root, replay validator or Policy-byte constructor.
pub struct PolicyCompilerStateReadbackOwnerV1 {
    journal: Journal,
    location: PolicyStateLocationV1,
}

#[derive(Default)]
struct PolicyStateLocationV1 {
    #[cfg(test)]
    fixture_root: Option<PathBuf>,
}

impl PolicyStateLocationV1 {
    fn recheck(&self, journal: &Journal) -> Result<(), crate::JournalError> {
        #[cfg(test)]
        if let Some(root) = &self.fixture_root {
            return journal.validate_held_protected_at_uid_for_test(
                root,
                POLICY_STATE_JOURNAL,
                journal.protected_owner_uid()?,
            );
        }
        journal.validate_held_root_owned_at(PROTECTED_POLICY_ROOT, POLICY_STATE_JOURNAL)
    }
}

impl PolicyCompilerStateReadbackOwnerV1 {
    /// Opens the fixed existing Policy writer without creating or repairing it.
    ///
    /// This is the PRE-ROOT transport's opener. Missing state, an incomplete
    /// append or pending compaction cannot be converted into a fresh state.
    ///
    /// # Errors
    ///
    /// Rejects missing, unsafe, unhealthy or already-held journal/lock names.
    pub fn open_existing_fixed_protected() -> Result<Self, PolicyCompilerJournalErrorV1> {
        let (journal, _) = Journal::open_existing_protected_at_for_uid(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_STATE_JOURNAL,
            policy_state_journal_limits(),
            0,
        )?;
        let location = PolicyStateLocationV1::default();
        location.recheck(&journal)?;
        Ok(Self { journal, location })
    }

    /// Opens only the existing fixed protected Policy state journal.
    ///
    /// This opener belongs to the existing privileged Policy owner. The
    /// unprivileged Controller has no access to that root, and must not widen
    /// its modes or use a second serial authority connection to obtain it.
    /// A live continuation transport preserving this writer through Root-last
    /// verification remains a separate installed-runtime prerequisite.
    ///
    /// # Errors
    ///
    /// Rejects unsafe root ownership, journal/lock names, lost writer custody
    /// or unhealthy journal recovery. It does not open Root authority state.
    pub fn open_fixed_protected() -> Result<(Self, RecoveryReport), PolicyCompilerJournalErrorV1> {
        let (journal, report) = Journal::open_protected_at(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_STATE_JOURNAL,
            policy_state_journal_limits(),
        )?;
        journal.validate_held_root_owned_at(PROTECTED_POLICY_ROOT, POLICY_STATE_JOURNAL)?;
        Ok((
            Self {
                journal,
                location: PolicyStateLocationV1::default(),
            },
            report,
        ))
    }

    /// Projects canonical current Policy claims while retaining the same writer.
    ///
    /// The callback must acquire Source, Cache and genuine Root/Mount custody
    /// later, in that order; it must not reacquire Controller or Policy. Root
    /// must authenticate the complete claims before any consumer read grant.
    /// The writer is never dropped/reopened between projection and callback.
    ///
    /// # Errors
    ///
    /// Rejects malformed state, unavailable Current/Candidate, inconsistent
    /// lineage or changed fixed protected path/names before or after callback.
    pub fn with_current_policy_claim<R>(
        &mut self,
        project: ProjectId,
        sandbox: SandboxId,
        action: impl for<'policy> FnOnce(&HeldResolvedRuntimePolicyV1<'policy>) -> R,
    ) -> Result<R, PolicyCompilerJournalErrorV1> {
        self.location.recheck(&self.journal)?;
        let candidates =
            protected_current_record_candidates_v1::<PolicyCompilerJournalSchemaV1>(&self.journal)?;
        for candidate in &candidates {
            validate_state_candidate_body(candidate)?;
        }
        let claim = HeldResolvedRuntimePolicyV1::from_structural_candidates(
            &self.journal,
            &self.location,
            &candidates,
            project,
            sandbox,
        )?;
        claim.recheck()?;
        let result = action(&claim);
        claim.recheck()?;
        Ok(result)
    }
}

/// Borrows canonical current Policy claims without authenticating their authority.
///
/// All four RFC cache domains remain representable: Private, TrustDomain,
/// Public and Project. The separate Project-only Publisher policy format is
/// unchanged. A genuine live Root-last verifier must join exact signing
/// lineage and current owner heads; this value alone grants no read or mount.
pub struct HeldResolvedRuntimePolicyV1<'policy> {
    journal: &'policy Journal,
    location: &'policy PolicyStateLocationV1,
    sequence: u64,
    project: ProjectId,
    sandbox: SandboxId,
    generation: u64,
    candidate: ObjectDigest,
    complete_preimage: bool,
    normalized_input: ObjectDigest,
    diagnostics: ObjectDigest,
    current_envelope: ObjectDigest,
    candidate_envelope: ObjectDigest,
    candidate_bytes: &'policy [u8],
    policy: Policy,
    policy_bytes: &'policy [u8],
    outputs: [ObjectDescriptor; 4],
    prerequisites: PolicyPublicationPrerequisitesV1,
}

impl<'policy> HeldResolvedRuntimePolicyV1<'policy> {
    fn from_structural_candidates(
        journal: &'policy Journal,
        location: &'policy PolicyStateLocationV1,
        candidates: &'policy [ProtectedCurrentRecordCandidateV1<PolicyCompilerJournalSchemaV1>],
        project: ProjectId,
        sandbox: SandboxId,
    ) -> Result<Self, PolicyCompilerJournalErrorV1> {
        let current_key = policy_current_key(project, sandbox)?;
        let current = candidates
            .iter()
            .find(|record| record.key() == &current_key)
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let current_header = decode_current_payload(current.body())?;
        let candidate_key = policy_key(
            PolicyCompilerJournalRecordKindV1::Candidate,
            project,
            sandbox,
            current_header.candidate,
        )?;
        let candidate = candidates
            .iter()
            .find(|record| record.key() == &candidate_key)
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let body = candidate.body();
        let (header, [bytes, _, _, _]) = validated_candidate_body(body)?;
        if header.project != project
            || header.sandbox != sandbox
            || current_header.project != project
            || current_header.sandbox != sandbox
            || header.generation != current_header.generation
            || header.candidate != current_header.candidate
            || header.normalized_input != current_header.normalized_input
            || header.diagnostics != current_header.diagnostics
            || header.prerequisites != current_header.prerequisites
            || header.prerequisite_tuple != current_header.prerequisite_tuple
        {
            return Err(PolicyCompilerJournalErrorV1::NonCanonicalPublication);
        }

        // The shared codec owns V2/V3 offsets, canonical output checks and the
        // V3 preimage join. Neither version independently authenticates Root.
        let policy = decode_policy(bytes, DecodeLimits::default())
            .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let descriptor = |index: usize, media: PortableMediaType| {
            Ok::<_, PolicyCompilerJournalErrorV1>(ObjectDescriptor::new(
                MediaType::new(media.as_str())
                    .map_err(|_| PolicyCompilerJournalErrorV1::NonCanonicalPublication)?,
                header.outputs[index].0,
                header.outputs[index].1,
            ))
        };
        let outputs = [
            descriptor(0, PortableMediaType::Policy)?,
            descriptor(1, PortableMediaType::Optimization)?,
            descriptor(2, PortableMediaType::Content)?,
            descriptor(3, PortableMediaType::Content)?,
        ];
        Ok(Self {
            journal,
            location,
            sequence: journal.snapshot_sequence(),
            project,
            sandbox,
            generation: header.generation,
            candidate: header.candidate,
            complete_preimage: header.has_complete_preimage(),
            normalized_input: header.normalized_input,
            diagnostics: header.diagnostics,
            current_envelope: current.envelope_digest(),
            candidate_envelope: candidate.envelope_digest(),
            candidate_bytes: body,
            policy,
            policy_bytes: bytes,
            outputs,
            prerequisites: header.prerequisite_tuple,
        })
    }

    /// Returns the canonical decoded Policy, not a disclosure grant.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Returns original canonical bytes from the structurally checked Candidate.
    #[must_use]
    pub const fn policy_bytes(&self) -> &[u8] {
        self.policy_bytes
    }

    /// Borrows exact canonical Candidate evidence for independent verification.
    ///
    /// V3 includes complete preimage consistency; neither these bytes nor a
    /// V2 structural observation authenticate current Policy/Root authority.
    #[must_use]
    pub const fn candidate_bytes(&self) -> &[u8] {
        self.candidate_bytes
    }

    /// Returns exact output descriptor claims for independent Root verification.
    #[must_use]
    pub const fn policy_descriptor(&self) -> &ObjectDescriptor {
        &self.outputs[0]
    }

    /// Returns all four checked output descriptor claims in canonical order.
    #[must_use]
    pub const fn outputs(&self) -> &[ObjectDescriptor; 4] {
        &self.outputs
    }

    /// Returns the retained diagnostics-body commitment claim.
    #[must_use]
    pub const fn diagnostics(&self) -> ObjectDigest {
        self.diagnostics
    }

    /// Returns the project and sandbox named by the retained current records.
    #[must_use]
    pub const fn target(&self) -> (ProjectId, SandboxId) {
        (self.project, self.sandbox)
    }

    /// Returns candidate commitment claims and retained publication generation.
    #[must_use]
    pub const fn candidate(&self) -> (ObjectDigest, u64) {
        (self.candidate, self.generation)
    }

    /// Reports complete candidate-preimage consistency, not Root authority.
    ///
    /// Legacy V2 claims remain observable but cannot supply complete worker
    /// policy evidence. V3 still requires independent current Root verification.
    #[must_use]
    pub const fn has_complete_preimage(&self) -> bool {
        self.complete_preimage
    }

    /// Returns exact Current and Candidate envelope commitments for comparison.
    #[must_use]
    pub const fn envelopes(&self) -> (ObjectDigest, ObjectDigest) {
        (self.current_envelope, self.candidate_envelope)
    }

    /// Returns the normalized retained compiler-input commitment claim.
    #[must_use]
    pub const fn normalized_input(&self) -> ObjectDigest {
        self.normalized_input
    }

    /// Returns prerequisite claims, not authenticated current owner heads.
    #[must_use]
    pub const fn prerequisites(&self) -> &PolicyPublicationPrerequisitesV1 {
        &self.prerequisites
    }

    /// Rechecks the same healthy fixed state writer/path/names and sequence.
    ///
    /// # Errors
    ///
    /// Rejects poisoned custody, renamed paths/files or changed shared state.
    pub fn recheck(&self) -> Result<(), PolicyCompilerJournalErrorV1> {
        self.location.recheck(self.journal)?;
        if self.sequence != self.journal.snapshot_sequence() {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(())
    }
}
