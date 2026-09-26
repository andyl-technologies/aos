//! Canonical hierarchy evidence recovered from protected-current records.
//!
//! These bodies are never decoded directly by request paths. The dormant
//! journal owner first authenticates the enclosing current protected record,
//! then this module mints the corresponding opaque evidence value.
//!
//! ```text
//! AOSHPE01 | version:u16 | evidence-kind:u8 | reserved:u8 | typed fields
//! ```

use aos_sandbox_core::{
    AssignmentEpoch, AttachmentId, AttachmentSlotId, DesiredGeneration, ExportId, IncarnationId,
    MediaType, NamespaceGeneration, NodeId, ObjectDescriptor, ObjectDigest, ProjectId, Revision,
    SandboxId, SnapshotId, ViewId,
};

use super::evidence::{
    CurrentAssignmentEvidenceV1, CurrentLiveInspectionObservationV1,
    CurrentSlotInventoryEvidenceV1, InspectionGrantModeV1, RetainedSnapshotManifestV1,
    RetainedViewSourceEvidenceV1, SlotInventoryStateV1, VerifiedAttachmentAuthorityV1,
    VerifiedDetachAuthorityV1, VerifiedDetachCompletionV1, VerifiedInspectionGrantV1,
    VerifiedRealizationTransactionCompletionV1,
};
use super::realizer::{RealizationStageV1, ReplacementTransactionV1};
use super::recovery::{
    DetachStageV1, PreparedRealizationRecoveryDecisionV1, PreparedSnapshotRecoveryDecisionV1,
    RebootInventoryStateV1, RebootRealizationInventoryV1, VerifiedDetachRebootInventoryV1,
    VerifiedPreparedRealizationAuthorityV1, VerifiedPublishedRollbackAuthorityV1,
    VerifiedSnapshotRecoveryAuthorityV1, VerifiedStageTransitionV1,
};

const MAGIC: &[u8; 8] = b"AOSHPE01";
const VERSION: u16 = 1;
const MAXIMUM_MEDIA_TYPE_BYTES: usize = 255;

/// Seals evidence construction to this authenticated protected-record decoder.
pub(super) struct ProtectedCurrentEvidenceAuthorityV1 {
    _private: (),
}

const PROTECTED_CURRENT_AUTHORITY: ProtectedCurrentEvidenceAuthorityV1 =
    ProtectedCurrentEvidenceAuthorityV1 { _private: () };

/// Selects one journal-authenticated hierarchy evidence body.
pub(crate) enum HierarchyProtectedEvidenceV1 {
    InspectionGrant(VerifiedInspectionGrantV1),
    SnapshotManifest(RetainedSnapshotManifestV1),
    LiveInspection(CurrentLiveInspectionObservationV1),
    Assignment(CurrentAssignmentEvidenceV1),
    ViewSource(RetainedViewSourceEvidenceV1),
    SlotInventory(CurrentSlotInventoryEvidenceV1),
    AttachmentAuthority(VerifiedAttachmentAuthorityV1),
    DetachAuthority(VerifiedDetachAuthorityV1),
    DetachCompletion(VerifiedDetachCompletionV1),
    TransactionCompletion(VerifiedRealizationTransactionCompletionV1),
    SnapshotRecoveryAuthority(VerifiedSnapshotRecoveryAuthorityV1),
    StageTransition(VerifiedStageTransitionV1),
    RebootRealizationInventory(RebootRealizationInventoryV1),
    PublishedRollbackAuthority(VerifiedPublishedRollbackAuthorityV1),
    PreparedRealizationAuthority(VerifiedPreparedRealizationAuthorityV1),
    DetachRebootInventory(VerifiedDetachRebootInventoryV1),
}

impl HierarchyProtectedEvidenceV1 {
    pub(crate) const fn tag(&self) -> u8 {
        match self {
            Self::InspectionGrant(_) => 1,
            Self::SnapshotManifest(_) => 2,
            Self::LiveInspection(_) => 3,
            Self::Assignment(_) => 4,
            Self::ViewSource(_) => 5,
            Self::SlotInventory(_) => 6,
            Self::AttachmentAuthority(_) => 7,
            Self::DetachAuthority(_) => 8,
            Self::DetachCompletion(_) => 9,
            Self::TransactionCompletion(_) => 10,
            Self::SnapshotRecoveryAuthority(_) => 11,
            Self::StageTransition(_) => 12,
            Self::RebootRealizationInventory(_) => 13,
            Self::PublishedRollbackAuthority(_) => 14,
            Self::PreparedRealizationAuthority(_) => 15,
            Self::DetachRebootInventory(_) => 16,
        }
    }

    pub(crate) fn identity(&self) -> [u8; 48] {
        let mut identity = [0; 48];
        match self {
            Self::InspectionGrant(value) => {
                copy_id(&mut identity, 0, value.project().as_bytes());
                copy_id(&mut identity, 16, value.observer().as_bytes());
                copy_id(&mut identity, 32, value.descendant().as_bytes());
            }
            Self::SnapshotManifest(value) => {
                copy_id(&mut identity, 0, value.project().as_bytes());
                copy_id(&mut identity, 16, value.sandbox().as_bytes());
                copy_id(&mut identity, 32, value.snapshot().as_bytes());
            }
            Self::LiveInspection(value) => {
                copy_id(&mut identity, 0, value.project().as_bytes());
                copy_id(&mut identity, 16, value.sandbox().as_bytes());
                copy_id(&mut identity, 32, value.incarnation().as_bytes());
            }
            Self::Assignment(value) => {
                copy_id(&mut identity, 0, value.project().as_bytes());
                copy_id(&mut identity, 16, value.sandbox().as_bytes());
                copy_id(&mut identity, 32, value.incarnation().as_bytes());
            }
            Self::ViewSource(value) => {
                copy_id(&mut identity, 0, value.project().as_bytes());
                copy_id(&mut identity, 16, value.owner().as_bytes());
                copy_id(&mut identity, 32, value.view().as_bytes());
            }
            Self::SlotInventory(value) => {
                copy_id(&mut identity, 0, value.sandbox().as_bytes());
                copy_id(&mut identity, 16, value.incarnation().as_bytes());
                copy_id(&mut identity, 32, value.destination_slot().as_bytes());
            }
            Self::AttachmentAuthority(value) => {
                copy_id(&mut identity, 0, value.attachment().as_bytes());
                identity[16..32].copy_from_slice(&value.request_commitment().as_bytes()[..16]);
                identity[32..48].copy_from_slice(&value.lease_commitment().as_bytes()[..16]);
            }
            Self::DetachAuthority(value) => {
                copy_id(&mut identity, 0, value.attachment().as_bytes());
                identity[16..32].copy_from_slice(&value.request_commitment().as_bytes()[..16]);
                identity[32..48].copy_from_slice(&value.policy_commitment().as_bytes()[..16]);
            }
            Self::DetachCompletion(value) => {
                copy_id(&mut identity, 0, value.project().as_bytes());
                copy_id(&mut identity, 16, value.attachment().as_bytes());
                identity[32..48].copy_from_slice(&value.detach_commitment().as_bytes()[..16]);
            }
            Self::TransactionCompletion(value) => {
                copy_id(&mut identity, 0, value.project().as_bytes());
                identity[16..32].copy_from_slice(&value.plan_commitment().as_bytes()[..16]);
                identity[32..48]
                    .copy_from_slice(&value.transaction_state_commitment().as_bytes()[..16]);
            }
            Self::SnapshotRecoveryAuthority(value) => {
                copy_id(&mut identity, 0, value.project().as_bytes());
                copy_id(&mut identity, 16, value.snapshot().as_bytes());
                identity[32..48].copy_from_slice(&value.preparation_commitment().as_bytes()[..16]);
            }
            Self::StageTransition(value) => {
                copy_id(&mut identity, 0, value.attachment().as_bytes());
                identity[16..32].copy_from_slice(&value.recipe_commitment().as_bytes()[..16]);
                identity[32..48].copy_from_slice(&value.inventory_commitment().as_bytes()[..16]);
            }
            Self::RebootRealizationInventory(value) => {
                copy_id(&mut identity, 0, value.attachment().as_bytes());
                identity[16..32].copy_from_slice(&value.recipe_commitment().as_bytes()[..16]);
                identity[32..48].copy_from_slice(&value.inventory_commitment().as_bytes()[..16]);
            }
            Self::PublishedRollbackAuthority(value) => {
                copy_id(&mut identity, 0, value.attachment().as_bytes());
                identity[16..32].copy_from_slice(&value.recipe_commitment().as_bytes()[..16]);
                identity[32..48].copy_from_slice(&value.authority_commitment().as_bytes()[..16]);
            }
            Self::PreparedRealizationAuthority(value) => {
                copy_id(&mut identity, 0, value.attachment().as_bytes());
                identity[16..32].copy_from_slice(&value.recipe_commitment().as_bytes()[..16]);
                identity[32..48].copy_from_slice(&value.authority_commitment().as_bytes()[..16]);
            }
            Self::DetachRebootInventory(value) => {
                copy_id(&mut identity, 0, value.attachment().as_bytes());
                identity[16..32].copy_from_slice(&value.detach_commitment().as_bytes()[..16]);
                identity[32..48].copy_from_slice(&value.inventory_commitment().as_bytes()[..16]);
            }
        }
        identity
    }
}

pub(crate) fn encode_hierarchy_protected_evidence_v1(
    evidence: &HierarchyProtectedEvidenceV1,
) -> Option<Vec<u8>> {
    if !canonical_evidence(evidence) {
        return None;
    }
    let mut writer = Writer::new(evidence.tag());
    match evidence {
        HierarchyProtectedEvidenceV1::InspectionGrant(value) => {
            writer.id(value.project().as_bytes());
            writer.id(value.observer().as_bytes());
            writer.u64(value.observer_generation().get());
            writer.id(value.descendant().as_bytes());
            writer.u8(match value.mode() {
                InspectionGrantModeV1::Stable => 1,
                InspectionGrantModeV1::LiveKernelCoupled => 2,
            });
            writer.u64(value.revocation_generation().get());
            writer.digest(value.grant_commitment());
        }
        HierarchyProtectedEvidenceV1::SnapshotManifest(value) => {
            writer.id(value.project().as_bytes());
            writer.id(value.sandbox().as_bytes());
            writer.id(value.snapshot().as_bytes());
            writer.u64(value.captured_generation().get());
            writer.descriptor(value.manifest())?;
            writer.digest(value.export_closure_commitment());
            writer.digest(value.retention_plan_commitment());
            writer.digest(value.preparation_commitment());
            writer.digest(value.retention_proof_commitment());
        }
        HierarchyProtectedEvidenceV1::LiveInspection(value) => {
            writer.id(value.project().as_bytes());
            writer.id(value.sandbox().as_bytes());
            writer.u64(value.desired_generation().get());
            writer.id(value.incarnation().as_bytes());
            writer.u64(value.namespace_generation().get());
            writer.u64(value.assignment_epoch().get());
            writer.id(value.node().as_bytes());
            writer.digest(value.observation_set_commitment());
            writer.digest(value.observation_commitment());
        }
        HierarchyProtectedEvidenceV1::Assignment(value) => {
            writer.id(value.project().as_bytes());
            writer.id(value.sandbox().as_bytes());
            writer.u64(value.desired_generation().get());
            writer.id(value.incarnation().as_bytes());
            writer.u64(value.namespace_generation().get());
            writer.u64(value.assignment_epoch().get());
            writer.id(value.node().as_bytes());
            writer.digest(value.observation_set_commitment());
            writer.digest(value.assignment_commitment());
        }
        HierarchyProtectedEvidenceV1::ViewSource(value) => {
            writer.id(value.project().as_bytes());
            writer.id(value.owner().as_bytes());
            writer.u64(value.owner_generation().get());
            writer.id(value.export().as_bytes());
            writer.id(value.view().as_bytes());
            writer.u64(value.view_revision().get());
            writer.descriptor(value.view_descriptor())?;
            writer.digest(value.source_handle_commitment());
            writer.digest(value.retention_proof_commitment());
            match (
                value.source_incarnation(),
                value.source_node(),
                value.source_namespace_generation(),
                value.source_assignment_epoch(),
                value.current_observation_set_commitment(),
            ) {
                (None, None, None, None, None) => writer.u8(0),
                (
                    Some(incarnation),
                    Some(node),
                    Some(namespace),
                    Some(epoch),
                    Some(observation),
                ) => {
                    writer.u8(1);
                    writer.id(incarnation.as_bytes());
                    writer.id(node.as_bytes());
                    writer.u64(namespace.get());
                    writer.u64(epoch.get());
                    writer.digest(observation);
                }
                _ => return None,
            }
        }
        HierarchyProtectedEvidenceV1::SlotInventory(value) => {
            writer.id(value.sandbox().as_bytes());
            writer.id(value.incarnation().as_bytes());
            writer.u64(value.namespace_generation().get());
            writer.id(value.node().as_bytes());
            writer.u64(value.assignment_epoch().get());
            writer.digest(value.observation_set_commitment());
            writer.id(value.destination_slot().as_bytes());
            match value.state() {
                SlotInventoryStateV1::Empty => writer.u8(1),
                SlotInventoryStateV1::ImmediatePredecessor {
                    attachment,
                    generation,
                    recipe_commitment,
                } => {
                    writer.u8(2);
                    writer.id(attachment.as_bytes());
                    writer.u64(generation.get());
                    writer.digest(*recipe_commitment);
                }
            }
            writer.digest(value.inventory_commitment());
        }
        HierarchyProtectedEvidenceV1::AttachmentAuthority(value) => {
            writer.id(value.attachment().as_bytes());
            writer.u64(value.desired_generation().get());
            writer.digest(value.request_commitment());
            writer.digest(value.policy_commitment());
            writer.digest(value.lease_commitment());
        }
        HierarchyProtectedEvidenceV1::DetachAuthority(value) => {
            writer.id(value.attachment().as_bytes());
            writer.u64(value.attachment_generation().get());
            writer.digest(value.request_commitment());
            writer.digest(value.policy_commitment());
        }
        HierarchyProtectedEvidenceV1::DetachCompletion(value) => {
            writer.id(value.project().as_bytes());
            writer.u64(value.tree_generation().get());
            writer.id(value.attachment().as_bytes());
            writer.u64(value.attachment_generation().get());
            writer.digest(value.detach_commitment());
            writer.digest(value.detach_history_commitment());
            writer.digest(value.inventory_commitment());
            writer.digest(value.completion_commitment());
        }
        HierarchyProtectedEvidenceV1::TransactionCompletion(value) => {
            writer.id(value.project().as_bytes());
            writer.u64(value.tree_generation().get());
            writer.digest(value.plan_commitment());
            writer.digest(value.transaction_state_commitment());
            writer.digest(value.terminal_heads_commitment());
            writer.digest(value.completion_commitment());
        }
        HierarchyProtectedEvidenceV1::SnapshotRecoveryAuthority(value) => {
            writer.id(value.project().as_bytes());
            writer.id(value.snapshot().as_bytes());
            writer.digest(value.preparation_commitment());
            writer.u8(match value.decision() {
                PreparedSnapshotRecoveryDecisionV1::Continue => 1,
                PreparedSnapshotRecoveryDecisionV1::Rollback => 2,
            });
            writer.digest(value.authority_commitment());
        }
        HierarchyProtectedEvidenceV1::StageTransition(value) => {
            writer.id(value.attachment().as_bytes());
            writer.u64(value.attachment_generation().get());
            writer.digest(value.recipe_commitment());
            writer.u8(value.from() as u8);
            writer.u8(value.to() as u8);
            writer.digest(value.inventory_commitment());
        }
        HierarchyProtectedEvidenceV1::RebootRealizationInventory(value) => {
            writer.id(value.attachment().as_bytes());
            writer.u64(value.attachment_generation().get());
            writer.digest(value.recipe_commitment());
            writer.u8(reboot_inventory_state_code(value.state()));
            writer.replacement(value.recoverable_predecessor());
            writer.digest(value.inventory_commitment());
        }
        HierarchyProtectedEvidenceV1::PublishedRollbackAuthority(value) => {
            writer.id(value.attachment().as_bytes());
            writer.u64(value.attachment_generation().get());
            writer.digest(value.recipe_commitment());
            writer.digest(value.authority_commitment());
        }
        HierarchyProtectedEvidenceV1::PreparedRealizationAuthority(value) => {
            writer.id(value.attachment().as_bytes());
            writer.u64(value.attachment_generation().get());
            writer.digest(value.recipe_commitment());
            writer.u8(match value.decision() {
                PreparedRealizationRecoveryDecisionV1::Continue => 1,
                PreparedRealizationRecoveryDecisionV1::Rollback => 2,
            });
            writer.digest(value.authority_commitment());
        }
        HierarchyProtectedEvidenceV1::DetachRebootInventory(value) => {
            writer.id(value.attachment().as_bytes());
            writer.u64(value.attachment_generation().get());
            writer.digest(value.detach_commitment());
            writer.u8(value.stage() as u8);
            writer.digest(value.inventory_commitment());
        }
    }
    Some(writer.finish())
}

pub(crate) fn decode_hierarchy_protected_evidence_v1(
    bytes: &[u8],
) -> Option<HierarchyProtectedEvidenceV1> {
    let mut cursor = Cursor::new(bytes)?;
    let evidence = match cursor.tag {
        1 => HierarchyProtectedEvidenceV1::InspectionGrant(
            VerifiedInspectionGrantV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                cursor.project()?,
                cursor.sandbox()?,
                cursor.desired_generation()?,
                cursor.sandbox()?,
                match cursor.u8()? {
                    1 => InspectionGrantModeV1::Stable,
                    2 => InspectionGrantModeV1::LiveKernelCoupled,
                    _ => return None,
                },
                cursor.revision()?,
                cursor.digest()?,
            ),
        ),
        2 => HierarchyProtectedEvidenceV1::SnapshotManifest(
            RetainedSnapshotManifestV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                cursor.project()?,
                cursor.sandbox()?,
                SnapshotId::from_bytes(cursor.array()?),
                cursor.desired_generation()?,
                cursor.descriptor()?,
                cursor.digest()?,
                cursor.digest()?,
                cursor.digest()?,
                cursor.digest()?,
            ),
        ),
        3 => HierarchyProtectedEvidenceV1::LiveInspection(
            CurrentLiveInspectionObservationV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                cursor.project()?,
                cursor.sandbox()?,
                cursor.desired_generation()?,
                IncarnationId::from_bytes(cursor.array()?),
                NamespaceGeneration::new(cursor.u64()?),
                AssignmentEpoch::new(cursor.u64()?),
                NodeId::from_bytes(cursor.array()?),
                cursor.digest()?,
                cursor.digest()?,
            ),
        ),
        4 => HierarchyProtectedEvidenceV1::Assignment(
            CurrentAssignmentEvidenceV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                cursor.project()?,
                cursor.sandbox()?,
                cursor.desired_generation()?,
                IncarnationId::from_bytes(cursor.array()?),
                NamespaceGeneration::new(cursor.u64()?),
                AssignmentEpoch::new(cursor.u64()?),
                NodeId::from_bytes(cursor.array()?),
                cursor.digest()?,
                cursor.digest()?,
            ),
        ),
        5 => {
            let project = cursor.project()?;
            let owner = cursor.sandbox()?;
            let owner_generation = cursor.desired_generation()?;
            let export = ExportId::from_bytes(cursor.array()?);
            let view = ViewId::from_bytes(cursor.array()?);
            let view_revision = cursor.revision()?;
            let descriptor = cursor.descriptor()?;
            let source_handle = cursor.digest()?;
            let retention = cursor.digest()?;
            let live = cursor.u8()?;
            let (incarnation, node, namespace_generation, assignment_epoch, observation) =
                match live {
                    0 => (None, None, None, None, None),
                    1 => (
                        Some(IncarnationId::from_bytes(cursor.array()?)),
                        Some(NodeId::from_bytes(cursor.array()?)),
                        Some(NamespaceGeneration::new(cursor.u64()?)),
                        Some(AssignmentEpoch::new(cursor.u64()?)),
                        Some(cursor.digest()?),
                    ),
                    _ => return None,
                };
            HierarchyProtectedEvidenceV1::ViewSource(
                RetainedViewSourceEvidenceV1::from_verified_parts(
                    &PROTECTED_CURRENT_AUTHORITY,
                    project,
                    owner,
                    owner_generation,
                    export,
                    view,
                    view_revision,
                    descriptor,
                    source_handle,
                    retention,
                    incarnation,
                    node,
                    namespace_generation,
                    assignment_epoch,
                    observation,
                ),
            )
        }
        6 => {
            let sandbox = cursor.sandbox()?;
            let incarnation = IncarnationId::from_bytes(cursor.array()?);
            let namespace_generation = NamespaceGeneration::new(cursor.u64()?);
            let node = NodeId::from_bytes(cursor.array()?);
            let assignment_epoch = AssignmentEpoch::new(cursor.u64()?);
            let observation = cursor.digest()?;
            let slot = AttachmentSlotId::from_bytes(cursor.array()?);
            let state = match cursor.u8()? {
                1 => SlotInventoryStateV1::Empty,
                2 => SlotInventoryStateV1::ImmediatePredecessor {
                    attachment: AttachmentId::from_bytes(cursor.array()?),
                    generation: cursor.desired_generation()?,
                    recipe_commitment: cursor.digest()?,
                },
                _ => return None,
            };
            HierarchyProtectedEvidenceV1::SlotInventory(
                CurrentSlotInventoryEvidenceV1::from_verified_parts(
                    &PROTECTED_CURRENT_AUTHORITY,
                    sandbox,
                    incarnation,
                    namespace_generation,
                    node,
                    assignment_epoch,
                    observation,
                    slot,
                    state,
                    cursor.digest()?,
                ),
            )
        }
        7 => HierarchyProtectedEvidenceV1::AttachmentAuthority(
            VerifiedAttachmentAuthorityV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                AttachmentId::from_bytes(cursor.array()?),
                cursor.desired_generation()?,
                cursor.digest()?,
                cursor.digest()?,
                cursor.digest()?,
            ),
        ),
        8 => HierarchyProtectedEvidenceV1::DetachAuthority(
            VerifiedDetachAuthorityV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                AttachmentId::from_bytes(cursor.array()?),
                cursor.desired_generation()?,
                cursor.digest()?,
                cursor.digest()?,
            ),
        ),
        9 => HierarchyProtectedEvidenceV1::DetachCompletion(
            VerifiedDetachCompletionV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                cursor.project()?,
                cursor.revision()?,
                AttachmentId::from_bytes(cursor.array()?),
                cursor.desired_generation()?,
                cursor.digest()?,
                cursor.digest()?,
                cursor.digest()?,
                cursor.digest()?,
            ),
        ),
        10 => HierarchyProtectedEvidenceV1::TransactionCompletion(
            VerifiedRealizationTransactionCompletionV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                cursor.project()?,
                cursor.revision()?,
                cursor.digest()?,
                cursor.digest()?,
                cursor.digest()?,
                cursor.digest()?,
            ),
        ),
        11 => HierarchyProtectedEvidenceV1::SnapshotRecoveryAuthority(
            VerifiedSnapshotRecoveryAuthorityV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                cursor.project()?,
                SnapshotId::from_bytes(cursor.array()?),
                cursor.digest()?,
                match cursor.u8()? {
                    1 => PreparedSnapshotRecoveryDecisionV1::Continue,
                    2 => PreparedSnapshotRecoveryDecisionV1::Rollback,
                    _ => return None,
                },
                cursor.digest()?,
            ),
        ),
        12 => HierarchyProtectedEvidenceV1::StageTransition(
            VerifiedStageTransitionV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                AttachmentId::from_bytes(cursor.array()?),
                cursor.desired_generation()?,
                cursor.digest()?,
                realization_stage(cursor.u8()?)?,
                realization_stage(cursor.u8()?)?,
                cursor.digest()?,
            ),
        ),
        13 => HierarchyProtectedEvidenceV1::RebootRealizationInventory(
            RebootRealizationInventoryV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                AttachmentId::from_bytes(cursor.array()?),
                cursor.desired_generation()?,
                cursor.digest()?,
                reboot_inventory_state(cursor.u8()?)?,
                cursor.replacement()?,
                cursor.digest()?,
            ),
        ),
        14 => HierarchyProtectedEvidenceV1::PublishedRollbackAuthority(
            VerifiedPublishedRollbackAuthorityV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                AttachmentId::from_bytes(cursor.array()?),
                cursor.desired_generation()?,
                cursor.digest()?,
                cursor.digest()?,
            ),
        ),
        15 => HierarchyProtectedEvidenceV1::PreparedRealizationAuthority(
            VerifiedPreparedRealizationAuthorityV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                AttachmentId::from_bytes(cursor.array()?),
                cursor.desired_generation()?,
                cursor.digest()?,
                match cursor.u8()? {
                    1 => PreparedRealizationRecoveryDecisionV1::Continue,
                    2 => PreparedRealizationRecoveryDecisionV1::Rollback,
                    _ => return None,
                },
                cursor.digest()?,
            ),
        ),
        16 => HierarchyProtectedEvidenceV1::DetachRebootInventory(
            VerifiedDetachRebootInventoryV1::from_verified_parts(
                &PROTECTED_CURRENT_AUTHORITY,
                AttachmentId::from_bytes(cursor.array()?),
                cursor.desired_generation()?,
                cursor.digest()?,
                detach_stage(cursor.u8()?)?,
                cursor.digest()?,
            ),
        ),
        _ => return None,
    };
    cursor.finish()?;
    (encode_hierarchy_protected_evidence_v1(&evidence)?.as_slice() == bytes).then_some(evidence)
}

fn canonical_evidence(evidence: &HierarchyProtectedEvidenceV1) -> bool {
    let identity = evidence.identity();
    identity.chunks_exact(16).all(|part| part != [0; 16])
        && evidence_digests(evidence)
            .into_iter()
            .all(|digest| digest.as_bytes() != &[0; 32])
        && evidence_generations(evidence)
            .into_iter()
            .all(|generation| generation != 0 && generation != u64::MAX)
        && canonical_recovery_evidence(evidence)
}

fn canonical_recovery_evidence(evidence: &HierarchyProtectedEvidenceV1) -> bool {
    match evidence {
        HierarchyProtectedEvidenceV1::StageTransition(value) => matches!(
            (value.from(), value.to()),
            (RealizationStageV1::Planned, RealizationStageV1::Prepared)
                | (RealizationStageV1::Prepared, RealizationStageV1::Published)
                | (RealizationStageV1::Published, RealizationStageV1::Verified)
                | (RealizationStageV1::Verified, RealizationStageV1::Draining)
                | (RealizationStageV1::Draining, RealizationStageV1::Reaped)
                | (RealizationStageV1::Verified, RealizationStageV1::Reaped)
                | (
                    RealizationStageV1::Planned | RealizationStageV1::Prepared,
                    RealizationStageV1::Aborted
                )
                | (
                    RealizationStageV1::Published
                        | RealizationStageV1::Verified
                        | RealizationStageV1::Draining,
                    RealizationStageV1::Faulted
                )
        ),
        HierarchyProtectedEvidenceV1::RebootRealizationInventory(value) => {
            value.recoverable_predecessor().is_none_or(|replacement| {
                replacement.successor() == value.attachment()
                    && replacement.predecessor().as_bytes() != &[0; 16]
                    && replacement.predecessor() != replacement.successor()
                    && replacement.predecessor_recipe_commitment().as_bytes() != &[0; 32]
                    && replacement.transaction_commitment().as_bytes() != &[0; 32]
            })
        }
        _ => true,
    }
}

fn evidence_digests(evidence: &HierarchyProtectedEvidenceV1) -> Vec<ObjectDigest> {
    match evidence {
        HierarchyProtectedEvidenceV1::InspectionGrant(value) => vec![value.grant_commitment()],
        HierarchyProtectedEvidenceV1::SnapshotManifest(value) => vec![
            value.manifest().digest(),
            value.export_closure_commitment(),
            value.retention_plan_commitment(),
            value.preparation_commitment(),
            value.retention_proof_commitment(),
        ],
        HierarchyProtectedEvidenceV1::LiveInspection(value) => vec![
            value.observation_set_commitment(),
            value.observation_commitment(),
        ],
        HierarchyProtectedEvidenceV1::Assignment(value) => vec![
            value.observation_set_commitment(),
            value.assignment_commitment(),
        ],
        HierarchyProtectedEvidenceV1::ViewSource(value) => {
            let mut values = vec![
                value.view_descriptor().digest(),
                value.source_handle_commitment(),
                value.retention_proof_commitment(),
            ];
            values.extend(value.current_observation_set_commitment());
            values
        }
        HierarchyProtectedEvidenceV1::SlotInventory(value) => vec![
            value.observation_set_commitment(),
            value.inventory_commitment(),
        ],
        HierarchyProtectedEvidenceV1::AttachmentAuthority(value) => vec![
            value.request_commitment(),
            value.policy_commitment(),
            value.lease_commitment(),
        ],
        HierarchyProtectedEvidenceV1::DetachAuthority(value) => {
            vec![value.request_commitment(), value.policy_commitment()]
        }
        HierarchyProtectedEvidenceV1::DetachCompletion(value) => vec![
            value.detach_commitment(),
            value.detach_history_commitment(),
            value.inventory_commitment(),
            value.completion_commitment(),
        ],
        HierarchyProtectedEvidenceV1::TransactionCompletion(value) => vec![
            value.plan_commitment(),
            value.transaction_state_commitment(),
            value.terminal_heads_commitment(),
            value.completion_commitment(),
        ],
        HierarchyProtectedEvidenceV1::SnapshotRecoveryAuthority(value) => {
            vec![value.preparation_commitment(), value.authority_commitment()]
        }
        HierarchyProtectedEvidenceV1::StageTransition(value) => {
            vec![value.recipe_commitment(), value.inventory_commitment()]
        }
        HierarchyProtectedEvidenceV1::RebootRealizationInventory(value) => {
            let mut digests = vec![value.recipe_commitment(), value.inventory_commitment()];
            if let Some(replacement) = value.recoverable_predecessor() {
                digests.push(replacement.predecessor_recipe_commitment());
                digests.push(replacement.transaction_commitment());
            }
            digests
        }
        HierarchyProtectedEvidenceV1::PublishedRollbackAuthority(value) => {
            vec![value.recipe_commitment(), value.authority_commitment()]
        }
        HierarchyProtectedEvidenceV1::PreparedRealizationAuthority(value) => {
            vec![value.recipe_commitment(), value.authority_commitment()]
        }
        HierarchyProtectedEvidenceV1::DetachRebootInventory(value) => {
            vec![value.detach_commitment(), value.inventory_commitment()]
        }
    }
}

fn evidence_generations(evidence: &HierarchyProtectedEvidenceV1) -> Vec<u64> {
    match evidence {
        HierarchyProtectedEvidenceV1::InspectionGrant(value) => vec![
            value.observer_generation().get(),
            value.revocation_generation().get(),
        ],
        HierarchyProtectedEvidenceV1::SnapshotManifest(value) => {
            vec![value.captured_generation().get()]
        }
        HierarchyProtectedEvidenceV1::LiveInspection(value) => vec![
            value.desired_generation().get(),
            value.namespace_generation().get(),
            value.assignment_epoch().get(),
        ],
        HierarchyProtectedEvidenceV1::Assignment(value) => vec![
            value.desired_generation().get(),
            value.namespace_generation().get(),
            value.assignment_epoch().get(),
        ],
        HierarchyProtectedEvidenceV1::ViewSource(value) => {
            let mut values = vec![value.owner_generation().get(), value.view_revision().get()];
            values.extend(
                value
                    .source_namespace_generation()
                    .map(NamespaceGeneration::get),
            );
            values.extend(value.source_assignment_epoch().map(AssignmentEpoch::get));
            values
        }
        HierarchyProtectedEvidenceV1::SlotInventory(value) => vec![
            value.namespace_generation().get(),
            value.assignment_epoch().get(),
        ],
        HierarchyProtectedEvidenceV1::AttachmentAuthority(value) => {
            vec![value.desired_generation().get()]
        }
        HierarchyProtectedEvidenceV1::DetachAuthority(value) => {
            vec![value.attachment_generation().get()]
        }
        HierarchyProtectedEvidenceV1::DetachCompletion(value) => vec![
            value.tree_generation().get(),
            value.attachment_generation().get(),
        ],
        HierarchyProtectedEvidenceV1::TransactionCompletion(value) => {
            vec![value.tree_generation().get()]
        }
        HierarchyProtectedEvidenceV1::SnapshotRecoveryAuthority(_) => Vec::new(),
        HierarchyProtectedEvidenceV1::StageTransition(value) => {
            vec![value.attachment_generation().get()]
        }
        HierarchyProtectedEvidenceV1::RebootRealizationInventory(value) => {
            let mut generations = vec![value.attachment_generation().get()];
            if let Some(replacement) = value.recoverable_predecessor() {
                generations.push(replacement.predecessor_generation().get());
            }
            generations
        }
        HierarchyProtectedEvidenceV1::PublishedRollbackAuthority(value) => {
            vec![value.attachment_generation().get()]
        }
        HierarchyProtectedEvidenceV1::PreparedRealizationAuthority(value) => {
            vec![value.attachment_generation().get()]
        }
        HierarchyProtectedEvidenceV1::DetachRebootInventory(value) => {
            vec![value.attachment_generation().get()]
        }
    }
}

fn copy_id(target: &mut [u8; 48], offset: usize, value: &[u8; 16]) {
    target[offset..offset + 16].copy_from_slice(value);
}

fn reboot_inventory_state_code(state: RebootInventoryStateV1) -> u8 {
    match state {
        RebootInventoryStateV1::Absent => 1,
        RebootInventoryStateV1::Prepared => 2,
        RebootInventoryStateV1::Published => 3,
        RebootInventoryStateV1::Verified => 4,
        RebootInventoryStateV1::Draining => 5,
        RebootInventoryStateV1::Reaped => 6,
        RebootInventoryStateV1::Aborted => 7,
        RebootInventoryStateV1::Faulted => 8,
    }
}

fn reboot_inventory_state(code: u8) -> Option<RebootInventoryStateV1> {
    match code {
        1 => Some(RebootInventoryStateV1::Absent),
        2 => Some(RebootInventoryStateV1::Prepared),
        3 => Some(RebootInventoryStateV1::Published),
        4 => Some(RebootInventoryStateV1::Verified),
        5 => Some(RebootInventoryStateV1::Draining),
        6 => Some(RebootInventoryStateV1::Reaped),
        7 => Some(RebootInventoryStateV1::Aborted),
        8 => Some(RebootInventoryStateV1::Faulted),
        _ => None,
    }
}

fn realization_stage(code: u8) -> Option<RealizationStageV1> {
    match code {
        0 => Some(RealizationStageV1::Planned),
        1 => Some(RealizationStageV1::Prepared),
        2 => Some(RealizationStageV1::Published),
        3 => Some(RealizationStageV1::Verified),
        4 => Some(RealizationStageV1::Draining),
        5 => Some(RealizationStageV1::Reaped),
        6 => Some(RealizationStageV1::Aborted),
        7 => Some(RealizationStageV1::Faulted),
        _ => None,
    }
}

fn detach_stage(code: u8) -> Option<DetachStageV1> {
    match code {
        0 => Some(DetachStageV1::Planned),
        1 => Some(DetachStageV1::Detached),
        2 => Some(DetachStageV1::Verified),
        3 => Some(DetachStageV1::Completed),
        4 => Some(DetachStageV1::Aborted),
        5 => Some(DetachStageV1::Faulted),
        _ => None,
    }
}

struct Cursor<'a> {
    remaining: &'a [u8],
    tag: u8,
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new(tag: u8) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&[tag, 0]);
        Self { bytes }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn id(&mut self, value: &[u8; 16]) {
        self.bytes.extend_from_slice(value);
    }

    fn digest(&mut self, value: ObjectDigest) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    fn descriptor(&mut self, value: &ObjectDescriptor) -> Option<()> {
        let media = value.media_type().as_str().as_bytes();
        let length = u16::try_from(media.len()).ok()?;
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(media);
        self.digest(value.digest());
        self.u64(value.encoded_size());
        Some(())
    }

    fn replacement(&mut self, value: Option<ReplacementTransactionV1>) {
        let Some(value) = value else {
            self.u8(0);
            return;
        };
        self.u8(1);
        self.id(value.predecessor().as_bytes());
        self.id(value.successor().as_bytes());
        self.u64(value.predecessor_generation().get());
        self.digest(value.predecessor_recipe_commitment());
        self.digest(value.transaction_commitment());
    }
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 12
            || &bytes[..8] != MAGIC
            || u16::from_be_bytes(bytes[8..10].try_into().ok()?) != VERSION
            || bytes[11] != 0
        {
            return None;
        }
        Some(Self {
            remaining: &bytes[12..],
            tag: bytes[10],
        })
    }

    fn finish(self) -> Option<()> {
        self.remaining.is_empty().then_some(())
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let (value, remaining) = self.remaining.split_at_checked(length)?;
        self.remaining = remaining;
        Some(value)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.array()?))
    }

    fn digest(&mut self) -> Option<ObjectDigest> {
        Some(ObjectDigest::from_bytes(self.array()?))
    }

    fn project(&mut self) -> Option<ProjectId> {
        Some(ProjectId::from_bytes(self.array()?))
    }

    fn sandbox(&mut self) -> Option<SandboxId> {
        Some(SandboxId::from_bytes(self.array()?))
    }

    fn revision(&mut self) -> Option<Revision> {
        Some(Revision::new(self.u64()?))
    }

    fn desired_generation(&mut self) -> Option<DesiredGeneration> {
        Some(DesiredGeneration::new(self.u64()?))
    }

    fn descriptor(&mut self) -> Option<ObjectDescriptor> {
        let media_length = usize::from(self.u16()?);
        if media_length == 0 || media_length > MAXIMUM_MEDIA_TYPE_BYTES {
            return None;
        }
        let media_type =
            MediaType::new(std::str::from_utf8(self.take(media_length)?).ok()?).ok()?;
        Some(ObjectDescriptor::new(
            media_type,
            self.digest()?,
            self.u64()?,
        ))
    }

    fn replacement(&mut self) -> Option<Option<ReplacementTransactionV1>> {
        match self.u8()? {
            0 => Some(None),
            1 => Some(Some(ReplacementTransactionV1::from_durable_parts(
                AttachmentId::from_bytes(self.array()?),
                AttachmentId::from_bytes(self.array()?),
                self.desired_generation()?,
                self.digest()?,
                self.digest()?,
            ))),
            _ => None,
        }
    }
}
