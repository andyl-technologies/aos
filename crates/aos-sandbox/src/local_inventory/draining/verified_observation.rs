//! Optional construction of verified drain observations.
//!
//! This owner retains the complete trusted evidence factories, protected joins,
//! canonical commitments, and currentness checks used by remote drain integration.
//! Raw reports and retained-history DATA remain in the parent.

use sha2::{Digest as _, Sha256};

use aos_sandbox_core::{ObjectDigest, ObservationSequence};

use crate::local_inventory::assignment::{
    SnapshotTransferCompletionV1, VerifiedAssignmentAuthorityV1, VerifiedGuardianStateV1,
};
use crate::local_inventory::evidence::AuthenticatedEvidenceContextV1;
use crate::local_inventory::evidence_authority::VerifierEvidenceGrantV1;

use super::{
    DrainAssignmentObservationV1, DrainAssignmentPlanV1, DrainAssignmentProgressV1,
    DrainAssignmentStrategyV1, DrainContainmentEvidenceV1, DrainDirectiveV1,
    DrainGuardianEvidenceV1, DrainGuardianStateV1, DrainObservationV1, DrainPhaseV1,
    DrainReleaseEvidenceV1, DrainSnapshotEvidenceV1, InvalidDrainModel,
    observation_phase_consistent,
};

impl DrainGuardianEvidenceV1 {
    /// Constructs current guardian evidence for one exact assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::EvidenceMismatch`] for zero commitments or generation.
    pub(in crate::local_inventory) fn from_guardian_verifier(
        grant: VerifierEvidenceGrantV1<(
            AuthenticatedEvidenceContextV1,
            ObjectDigest,
            u64,
            ObjectDigest,
            DrainGuardianStateV1,
            ObjectDigest,
        )>,
    ) -> Result<Self, InvalidDrainModel> {
        let (
            (context, assignment_digest, lease_generation, lease_digest, state, evidence_digest),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || issuance_sequence == 0
            || verifier_context != context
            || assignment_digest.as_bytes() == &[0; 32]
            || lease_generation == 0
            || lease_digest.as_bytes() == &[0; 32]
            || evidence_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        Ok(Self {
            context,
            assignment_digest,
            lease_generation,
            lease_digest,
            state,
            evidence_digest,
        })
    }
}

impl DrainSnapshotEvidenceV1 {
    /// Constructs immutable snapshot and transfer-manifest evidence.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::EvidenceMismatch`] for a zero identity or digest.
    pub(in crate::local_inventory) fn from_snapshot_verifier(
        grant: VerifierEvidenceGrantV1<(
            AuthenticatedEvidenceContextV1,
            DrainGuardianEvidenceV1,
            DrainAssignmentPlanV1,
            SnapshotTransferCompletionV1,
            u64,
        )>,
    ) -> Result<Self, InvalidDrainModel> {
        let (
            (context, guardian, plan, completion, verified_at_unix_seconds),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || issuance_sequence == 0
            || verifier_context != context
            || guardian.assignment_digest() != plan.assignment_digest()
            || guardian.state() != DrainGuardianStateV1::Armed
            || guardian.context().node() != context.node()
            || guardian.context().lineage() != context.lineage()
            || guardian.context().audience_digest() != context.audience_digest()
            || guardian.context().disclosure_domain_digest() != context.disclosure_domain_digest()
            || !guardian.context().is_current_at(verified_at_unix_seconds)
            || completion.identity().sandbox() != plan.sandbox()
            || completion.identity().incarnation() != plan.incarnation()
            || completion.identity().assignment_epoch() != plan.epoch()
            || completion.identity().desired_generation() != plan.desired_generation()
            || completion.identity().assignment_digest() != plan.assignment_digest()
            || completion.identity().source_node() != context.node()
            || completion.identity().audience_digest() != context.audience_digest()
            || completion.identity().disclosure_domain_digest()
                != context.disclosure_domain_digest()
            || completion.root_digest().as_bytes() == &[0; 32]
            || !completion
                .evidence_context()
                .is_current_at(verified_at_unix_seconds)
            || !completion
                .protected_journal_record()
                .context()
                .is_current_at(verified_at_unix_seconds)
            || !completion.dependencies_current_at(verified_at_unix_seconds)
            || !context.is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        Ok(Self {
            context,
            guardian,
            sandbox: plan.sandbox(),
            incarnation: plan.incarnation(),
            epoch: plan.epoch(),
            desired_generation: plan.desired_generation(),
            assignment_digest: plan.assignment_digest(),
            completion,
        })
    }
}

impl DrainContainmentEvidenceV1 {
    /// Constructs fail-closed containment evidence for one assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::EvidenceMismatch`] unless payload stop,
    /// network default-drop, assignment binding, and a contained guardian fact
    /// are all present.
    pub(in crate::local_inventory) fn from_containment_verifier(
        grant: VerifierEvidenceGrantV1<(
            ObjectDigest,
            bool,
            bool,
            DrainGuardianEvidenceV1,
            ObjectDigest,
        )>,
    ) -> Result<Self, InvalidDrainModel> {
        let (
            (assignment_digest, payload_stopped, network_default_drop, guardian, evidence_digest),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || issuance_sequence == 0
            || verifier_context != guardian.context()
            || assignment_digest.as_bytes() == &[0; 32]
            || assignment_digest != guardian.assignment_digest()
            || !payload_stopped
            || !network_default_drop
            || guardian.state() == DrainGuardianStateV1::Armed
            || evidence_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        Ok(Self {
            assignment_digest,
            payload_stopped,
            network_default_drop,
            guardian,
            evidence_digest,
        })
    }
}

impl DrainReleaseEvidenceV1 {
    /// Constructs release evidence for one exact assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::EvidenceMismatch`] for a zero commitment.
    pub(in crate::local_inventory) fn from_release_verifier(
        grant: VerifierEvidenceGrantV1<(
            AuthenticatedEvidenceContextV1,
            DrainContainmentEvidenceV1,
            ObjectDigest,
        )>,
    ) -> Result<Self, InvalidDrainModel> {
        let (
            (context, containment, released_inventory_digest),
            verifier_domain_digest,
            replay_fence,
            issuance_sequence,
            verifier_context,
        ) = grant.into_parts();
        let assignment_digest = containment.assignment_digest();
        if verifier_domain_digest.as_bytes() == &[0; 32]
            || replay_fence.as_bytes() == &[0; 32]
            || issuance_sequence == 0
            || verifier_context != context
            || assignment_digest.as_bytes() == &[0; 32]
            || containment.evidence_digest().as_bytes() == &[0; 32]
            || released_inventory_digest.as_bytes() == &[0; 32]
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        Ok(Self {
            context,
            assignment_digest,
            containment_digest: containment.evidence_digest(),
            released_inventory_digest,
        })
    }
}

impl DrainAssignmentObservationV1 {
    /// Derives progress for one exact planned assignment.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel::EvidenceMismatch`] when evidence does not
    /// match the exact assignment, strategy, or reported progress.
    pub(in crate::local_inventory) fn from_authenticated_node(
        plan: DrainAssignmentPlanV1,
        progress: DrainAssignmentProgressV1,
        snapshot_evidence: Option<DrainSnapshotEvidenceV1>,
        containment_evidence: Option<DrainContainmentEvidenceV1>,
        release_evidence: Option<DrainReleaseEvidenceV1>,
    ) -> Result<Self, InvalidDrainModel> {
        let needs_containment = matches!(
            progress,
            DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
        );
        let needs_release = progress == DrainAssignmentProgressV1::Released;
        let needs_snapshot = plan.strategy() == DrainAssignmentStrategyV1::SnapshotStopAndReplace
            && matches!(
                progress,
                DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
            );
        let snapshot_allowed = progress != DrainAssignmentProgressV1::Pending;
        let containment_allowed = matches!(
            progress,
            DrainAssignmentProgressV1::Contained
                | DrainAssignmentProgressV1::Released
                | DrainAssignmentProgressV1::Blocked(_)
        );
        let release_allowed = matches!(
            progress,
            DrainAssignmentProgressV1::Released | DrainAssignmentProgressV1::Blocked(_)
        );
        if (needs_snapshot && snapshot_evidence.is_none())
            || (plan.strategy() != DrainAssignmentStrategyV1::SnapshotStopAndReplace
                && snapshot_evidence.is_some())
            || (!snapshot_allowed && snapshot_evidence.is_some())
            || (needs_containment && containment_evidence.is_none())
            || (needs_release && release_evidence.is_none())
            || (!containment_allowed && containment_evidence.is_some())
            || (!release_allowed && release_evidence.is_some())
            || (release_evidence.is_some() && containment_evidence.is_none())
            || (release_evidence.is_some()
                && plan.strategy() == DrainAssignmentStrategyV1::SnapshotStopAndReplace
                && snapshot_evidence.is_none())
            || containment_evidence
                .is_some_and(|evidence| evidence.assignment_digest() != plan.assignment_digest())
            || release_evidence
                .is_some_and(|evidence| evidence.assignment_digest() != plan.assignment_digest())
            || release_evidence
                .zip(containment_evidence)
                .is_some_and(|(release, containment)| {
                    release.containment_digest() != containment.evidence_digest()
                })
            || snapshot_evidence.as_ref().is_some_and(|evidence| {
                evidence.sandbox() != plan.sandbox()
                    || evidence.incarnation() != plan.incarnation()
                    || evidence.epoch() != plan.epoch()
                    || evidence.desired_generation() != plan.desired_generation()
                    || evidence.assignment_digest() != plan.assignment_digest()
            })
        {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        Ok(Self {
            sandbox: plan.sandbox(),
            incarnation: plan.incarnation(),
            epoch: plan.epoch(),
            desired_generation: plan.desired_generation(),
            assignment_digest: plan.assignment_digest(),
            progress,
            snapshot_evidence,
            containment_evidence,
            release_evidence,
        })
    }
}

impl DrainObservationV1 {
    /// Rebuilds a complete drain observation from protected opaque evidence.
    pub(in crate::local_inventory) fn from_protected_owner(
        directive: &DrainDirectiveV1,
        reported: &Self,
        snapshot_completion: Option<SnapshotTransferCompletionV1>,
        snapshot_authority: VerifiedAssignmentAuthorityV1,
        containment_authority: VerifiedAssignmentAuthorityV1,
        verified_at_unix_seconds: u64,
    ) -> Result<Self, InvalidDrainModel> {
        if directive.assignments().len() != 1
            || reported.assignments().len() != 1
            || !reported.matches(directive)
            || !reported.context().is_current_at(verified_at_unix_seconds)
        {
            return Err(InvalidDrainModel::ObservationCoverageMismatch);
        }
        let plan = directive.assignments()[0];
        let raw = &reported.assignments()[0];
        if !snapshot_authority.matches_drain_plan(
            plan,
            reported.context(),
            verified_at_unix_seconds,
        ) || !containment_authority.matches_drain_plan(
            plan,
            reported.context(),
            verified_at_unix_seconds,
        ) {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        let snapshot_guardian =
            protected_drain_guardian(snapshot_authority, plan, DrainGuardianStateV1::Armed)?;
        let containment_guardian = protected_drain_guardian(
            containment_authority,
            plan,
            DrainGuardianStateV1::ExplicitlyContained,
        )?;
        let snapshot_evidence = snapshot_completion
            .map(|completion| {
                if completion.identity().sandbox() != plan.sandbox()
                    || completion.identity().incarnation() != plan.incarnation()
                    || completion.identity().assignment_epoch() != plan.epoch()
                    || completion.identity().desired_generation() != plan.desired_generation()
                    || completion.identity().assignment_digest() != plan.assignment_digest()
                    || completion.identity().source_node() != reported.node()
                {
                    return Err(InvalidDrainModel::EvidenceMismatch);
                }
                Ok(DrainSnapshotEvidenceV1 {
                    context: reported.context(),
                    guardian: snapshot_guardian,
                    sandbox: plan.sandbox(),
                    incarnation: plan.incarnation(),
                    epoch: plan.epoch(),
                    desired_generation: plan.desired_generation(),
                    assignment_digest: plan.assignment_digest(),
                    completion,
                })
            })
            .transpose()?;
        let needs_containment = matches!(
            raw.progress(),
            DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
        );
        let containment_evidence = needs_containment.then(|| DrainContainmentEvidenceV1 {
            assignment_digest: plan.assignment_digest(),
            payload_stopped: true,
            network_default_drop: true,
            guardian: containment_guardian,
            evidence_digest: protected_drain_containment_digest(
                plan,
                containment_guardian,
                reported,
            ),
        });
        let release_evidence = (raw.progress() == DrainAssignmentProgressV1::Released).then(|| {
            DrainReleaseEvidenceV1 {
                context: reported.context(),
                assignment_digest: plan.assignment_digest(),
                containment_digest: containment_evidence
                    .map(DrainContainmentEvidenceV1::evidence_digest)
                    .unwrap_or_else(|| {
                        protected_drain_containment_digest(plan, containment_guardian, reported)
                    }),
                released_inventory_digest: protected_drain_release_digest(plan, reported),
            }
        });
        let assignment = DrainAssignmentObservationV1::from_authenticated_node(
            plan,
            raw.progress(),
            snapshot_evidence,
            containment_evidence,
            release_evidence,
        )?;
        Self::from_authenticated_node(
            directive,
            reported.context(),
            reported.sequence(),
            reported.phase(),
            vec![assignment],
            reported.observed_at_unix_seconds(),
        )
    }

    /// Constructs a complete observation against one exact directive.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidDrainModel`] for sentinel observation generations or
    /// when assignment coverage differs from the directive.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::local_inventory) fn from_authenticated_node(
        directive: &DrainDirectiveV1,
        context: AuthenticatedEvidenceContextV1,
        sequence: ObservationSequence,
        phase: DrainPhaseV1,
        assignments: Vec<DrainAssignmentObservationV1>,
        observed_at_unix_seconds: u64,
    ) -> Result<Self, InvalidDrainModel> {
        let progress = assignments
            .iter()
            .map(DrainAssignmentObservationV1::progress)
            .collect::<Vec<_>>();
        if sequence.get() == 0
            || context.node() != directive.node()
            || !context.is_current_at(observed_at_unix_seconds)
        {
            return Err(InvalidDrainModel::Unspecified);
        }
        if assignments.len() != directive.assignments().len()
            || !assignments
                .windows(2)
                .all(|pair| pair[0].sandbox() < pair[1].sandbox())
            || assignments
                .iter()
                .zip(directive.assignments())
                .any(|(observed, planned)| !observed.matches(*planned))
        {
            return Err(InvalidDrainModel::ObservationCoverageMismatch);
        }
        if !observation_phase_consistent(directive, phase, &progress) {
            return Err(InvalidDrainModel::ProgressMismatch);
        }
        if assignments.iter().any(|observation| {
            !drain_evidence_is_current(observation, context, observed_at_unix_seconds)
        }) {
            return Err(InvalidDrainModel::EvidenceMismatch);
        }
        let reassignment_ready = directive
            .assignments()
            .iter()
            .zip(&assignments)
            .filter_map(|(plan, observation)| {
                let replacement = matches!(
                    plan.strategy(),
                    DrainAssignmentStrategyV1::SnapshotStopAndReplace
                        | DrainAssignmentStrategyV1::StopAndReplace
                );
                let contained = matches!(
                    observation.progress(),
                    DrainAssignmentProgressV1::Contained | DrainAssignmentProgressV1::Released
                );
                (replacement && contained).then_some(plan.sandbox())
            })
            .collect();

        Ok(Self {
            operation: directive.operation(),
            node: directive.node(),
            generation: directive.generation(),
            context,
            sequence,
            phase,
            assignments,
            reassignment_ready,
            observed_at_unix_seconds,
        })
    }
}

fn protected_drain_guardian(
    authority: VerifiedAssignmentAuthorityV1,
    plan: DrainAssignmentPlanV1,
    required: DrainGuardianStateV1,
) -> Result<DrainGuardianEvidenceV1, InvalidDrainModel> {
    let state = match authority.guardian_state() {
        VerifiedGuardianStateV1::Armed => DrainGuardianStateV1::Armed,
        VerifiedGuardianStateV1::Contained => DrainGuardianStateV1::ExplicitlyContained,
        VerifiedGuardianStateV1::ExpiredAndContained => DrainGuardianStateV1::ExpiredAndContained,
    };
    if state != required {
        return Err(InvalidDrainModel::EvidenceMismatch);
    }
    Ok(DrainGuardianEvidenceV1 {
        context: authority.context(),
        assignment_digest: plan.assignment_digest(),
        lease_generation: authority.lease_generation(),
        lease_digest: authority.lease_digest(),
        state,
        evidence_digest: authority.guardian_digest(),
    })
}

fn protected_drain_containment_digest(
    plan: DrainAssignmentPlanV1,
    guardian: DrainGuardianEvidenceV1,
    observation: &DrainObservationV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.drain.protected-containment.v1\0")
            .chain_update(plan.assignment_digest().as_bytes())
            .chain_update(guardian.evidence_digest().as_bytes())
            .chain_update(observation.sequence().get().to_be_bytes())
            .chain_update(observation.context().canonical_frame_digest().as_bytes())
            .finalize()
            .into(),
    )
}

fn protected_drain_release_digest(
    plan: DrainAssignmentPlanV1,
    observation: &DrainObservationV1,
) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"aos.drain.protected-release.v1\0")
            .chain_update(plan.assignment_digest().as_bytes())
            .chain_update(observation.sequence().get().to_be_bytes())
            .chain_update(observation.context().canonical_frame_digest().as_bytes())
            .finalize()
            .into(),
    )
}

fn drain_evidence_is_current(
    observation: &DrainAssignmentObservationV1,
    observation_context: AuthenticatedEvidenceContextV1,
    observed_at_unix_seconds: u64,
) -> bool {
    let context_matches = |context: AuthenticatedEvidenceContextV1| {
        context.node() == observation_context.node()
            && context.lineage() == observation_context.lineage()
            && context.audience_digest() == observation_context.audience_digest()
            && context.disclosure_domain_digest() == observation_context.disclosure_domain_digest()
            && context.is_current_at(observed_at_unix_seconds)
    };
    observation.snapshot_evidence().is_none_or(|evidence| {
        context_matches(evidence.context())
            && context_matches(evidence.guardian().context())
            && evidence
                .completion()
                .evidence_context()
                .is_current_at(observed_at_unix_seconds)
            && evidence
                .completion()
                .protected_journal_record()
                .context()
                .is_current_at(observed_at_unix_seconds)
            && evidence
                .completion()
                .dependencies_current_at(observed_at_unix_seconds)
    }) && observation
        .containment_evidence()
        .is_none_or(|evidence| context_matches(evidence.guardian().context()))
        && observation
            .release_evidence()
            .is_none_or(|evidence| context_matches(evidence.context()))
}
