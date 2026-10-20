//! Constructs complete public retirement data models separately from wire values.
//!
//! Embedded byte records are independently built by the primitive oracle and
//! also decoded into complete independently constructed nested public models.

use super::wire;
use terrane_format::bucket::{
    BucketCapabilities, GenerationManifest, PackExclusion, StoreProfile, Tombstone,
};
use terrane_format::gc::GcLease;
use terrane_format::gc::publication::{BackendBinding, PublicationState, RemoteProvider};
use terrane_format::gc::retirement::*;

const PACK: [u8; 16] = [0x12; 16];
const NONCE: [u8; 32] = [0x34; 32];

/// Constructs claimed backend fields without any backend implementation.
pub(super) fn backend(local: bool) -> BackendBinding {
    if local {
        BackendBinding::Local {
            root: b"/a".to_vec(),
            root_device: 1,
            root_inode: 2,
            coordination_device: 3,
            coordination_inode: 4,
        }
    } else {
        BackendBinding::Remote {
            provider: RemoteProvider::S3,
            endpoint: "e".into(),
            bucket: "b".into(),
            prefix: vec![],
            resource_nonce: [1; 32],
            coordination_key: b"c".to_vec(),
            coordination_nonce: [2; 32],
        }
    }
}

fn lease() -> GcLease {
    GcLease {
        holder: "A".into(),
        epoch: 2,
        expiry: 100,
    }
}

fn exclusion() -> Exclusion {
    Exclusion {
        pack: PACK,
        cycle: 3,
        epoch: 2,
    }
}

/// Constructs every Tombstone field rather than decoding its bytes.
pub(super) fn tombstone() -> Tombstone {
    Tombstone {
        pack_id: PACK,
        cycle: 3,
        tombstoned_at: 4,
        removed_entries: 0,
        epoch: 2,
    }
}

fn pointer(key: impl Into<String>, byte: u8) -> RecordPointer {
    RecordPointer {
        key: key.into(),
        digest: [byte; 32],
    }
}

fn slot(revision: u64, byte: u8) -> OwnershipSlot {
    OwnershipSlot {
        revision,
        digest: [byte; 32],
    }
}

fn trash() -> RemoteArtifact {
    let bytes = wire::tombstone().encode();
    RemoteArtifact {
        key: format!("trash/3/{}", "12".repeat(16)),
        digest: *blake3::hash(&bytes).as_bytes(),
        size: bytes.len() as u64,
    }
}

/// Constructs all sweep fields, including each initial artifact and witness.
pub(super) fn sweep() -> RemoteSweepDeleteAuthorization {
    let key = format!("objects/pack/12/{}", "12".repeat(16));
    RemoteSweepDeleteAuthorization {
        nonce: NONCE,
        backend: backend(false),
        exclusion: exclusion(),
        lease: lease(),
        deletion_seconds: 2,
        artifacts: [
            RemoteArtifact {
                key: format!("{key}.pack"),
                digest: [7; 32],
                size: 52,
            },
            RemoteArtifact {
                key: format!("{key}.idx"),
                digest: wire::index_digest(),
                size: 36,
            },
            trash(),
        ],
        witness: wire::witness(),
        tombstone: wire::tombstone().encode(),
        deletion_elapsed_nanos: 2_000_000_000,
        fence: pointer("gc/3/fence/2", 8),
        grace_seconds: 1,
        grace_elapsed_nanos: 1_000_000_000,
    }
}

/// Constructs every copied alternative field and its backend-specific barrier.
pub(super) fn copied(local: bool, lineage: bool) -> CopiedRetirementAuthorization {
    let tombstone = wire::tombstone().encode();
    let barrier = if local {
        BarrierArtifact::Local(LocalBarrierArtifact {
            key: format!("trash/3/{}", "12".repeat(16)),
            nonce: [5; 32],
            tombstone: tombstone.clone(),
            file_identity: vec![6],
        })
    } else {
        BarrierArtifact::Remote(trash())
    };
    CopiedRetirementAuthorization {
        nonce: NONCE,
        backend: backend(local),
        exclusion: exclusion(),
        lease: lease(),
        deletion_seconds: 2,
        barrier,
        tombstone,
        deletion_elapsed_nanos: 2_000_000_000,
        fence: pointer("gc/3/fence/2", 8),
        grace_seconds: 1,
        grace_elapsed_nanos: 1_000_000_000,
        genesis: slot(0, 9),
        preparation: slot(1, 10),
        lineage_fence: lineage.then(|| pointer("gc/3/fence/2", 21)),
    }
}

/// Constructs the owning enum independently of the corresponding wire alternative.
pub(super) fn authorization(copied_case: bool, local: bool) -> PermanentDeleteAuthorization {
    if copied_case {
        PermanentDeleteAuthorization::Copied(copied(local, false))
    } else {
        PermanentDeleteAuthorization::Sweep(sweep())
    }
}

/// Constructs all preparation plan fields, including the whole nested lease.
pub(super) fn plan(local: bool) -> CopiedRetirementPlan {
    CopiedRetirementPlan {
        nonce: NONCE,
        backend: backend(local),
        exclusion: exclusion(),
        lease: lease(),
        genesis: slot(0, 9),
        fence: pointer("gc/3/fence/0", 11),
        tombstone: wire::tombstone().encode(),
        grace_seconds: 1,
        deletion_seconds: 2,
    }
}

/// Constructs disjoint copied visibility or permanent pointer fields.
pub(super) fn selection(permanent: bool, digest: [u8; 32]) -> PermanentOwnerSelection {
    if permanent {
        PermanentOwnerSelection::Permanent(RecordPointer {
            key: wire::operation_key(),
            digest,
        })
    } else {
        PermanentOwnerSelection::CopiedVisibility
    }
}

/// Constructs the complete public publication-state model embedded by passes/fences.
pub(super) fn state(
    revision: u64,
    local: bool,
    owners: Vec<PermanentBurnOwner>,
    guard: Option<[u8; 32]>,
    loss: u64,
) -> PublicationState {
    PublicationState {
        revision,
        loss_generation: loss,
        sources: vec![],
        binding: backend(local),
        branches: vec![],
        guard,
        burn_owners: Some(owners),
    }
}

/// Constructs every pass field and every nested observation alternative.
pub(super) fn progress(local: bool, completed: bool, copied: bool) -> PermanentDeletePass {
    let digest = wire::raw(&wire::authorization(copied, local, false));
    let owner = PermanentBurnOwner {
        pack: PACK,
        selection: selection(true, digest),
    };
    let mut observations = vec![RequestObservation {
        artifact: ObservedArtifact::Pack,
        instance: ObservedInstance::Unversioned,
        state: ObservationState::ConfirmedAbsent,
    }];
    if !local {
        observations.extend([
            RequestObservation {
                artifact: ObservedArtifact::Pack,
                instance: ObservedInstance::Version(b"version".to_vec()),
                state: ObservationState::ConfirmedAbsent,
            },
            RequestObservation {
                artifact: ObservedArtifact::Pack,
                instance: ObservedInstance::Marker(b"marker".to_vec()),
                state: ObservationState::Indeterminate,
            },
        ]);
    }
    observations.extend([
        RequestObservation {
            artifact: ObservedArtifact::Index,
            instance: ObservedInstance::Unversioned,
            state: ObservationState::Indeterminate,
        },
        RequestObservation {
            artifact: ObservedArtifact::Trash(3),
            instance: ObservedInstance::Unversioned,
            state: ObservationState::Deferred,
        },
    ]);
    PermanentDeletePass {
        authorization_digest: digest,
        owner: slot(3, 12),
        revision: if copied { 2 } else { 1 },
        pass: 0,
        event: 0,
        predecessor: slot(4, 13),
        state: state(4, local, vec![owner], None, 1),
        lease: lease(),
        backend: backend(local),
        phase: if completed {
            PassPhase::PassCompleted
        } else {
            PassPhase::Open
        },
        observations,
        coverage: [if completed {
            PassCoverage::CandidateTraversalCompleted
        } else {
            PassCoverage::Unknown
        }; 3],
        nonce: [14; 32],
        placement_fence: local.then(|| pointer("gc/3/fence/4", 15)),
    }
}

/// Constructs operation phases and complete nested authorizations/pointers.
pub(super) fn operation(
    phase: OperationPhase,
    copied: bool,
    local: bool,
) -> PermanentDeleteOperation {
    let revision = match phase {
        OperationPhase::Proposed => 0,
        _ if copied => 2,
        _ => 1,
    };
    let pass = (phase == OperationPhase::Owned).then(|| RecordPointer {
        key: format!("gc/3/reconcile/{}/{revision}", "0e".repeat(32)),
        digest: wire::raw(&wire::progress(local, false, copied)),
    });
    PermanentDeleteOperation {
        revision,
        phase,
        authorization: authorization(copied, local),
        owner: (phase == OperationPhase::Owned).then(|| slot(3, 12)),
        pass,
    }
}

/// Constructs all capabilities fields, including the store profile.
pub(super) fn capabilities() -> BucketCapabilities {
    BucketCapabilities {
        layout_version: 2,
        create_if_absent: true,
        compare_and_swap: true,
        ranges: true,
        presign: false,
        multi_writer: true,
        probed_at: 4,
        profile: StoreProfile {
            identity: "terrane-v1".into(),
            algorithm: "blake3".into(),
            chunk: "cdc-1m".into(),
            seed: [0; 32],
        },
        generation: Some(1),
        ref_names: Some(vec![]),
        publication_protocol: Some(1),
    }
}

/// Constructs every generation field, including exclusion and burn records.
pub(super) fn manifest(copied: bool) -> GenerationManifest {
    GenerationManifest {
        generation: 1,
        shards: vec![],
        written_at: 4,
        cycle: 3,
        inventory: Some(vec![]),
        exclusions: Some(vec![PackExclusion {
            pack_id: PACK,
            cycle: 3,
            epoch: 2,
        }]),
        burns: Some(if copied { vec![PACK] } else { vec![] }),
    }
}

/// Constructs all common fence fields and the complete nested publication state.
pub(super) fn current_fields(copied: bool, local: bool) -> CurrentCollectionFence {
    let owners = if copied {
        vec![PermanentBurnOwner {
            pack: PACK,
            selection: PermanentOwnerSelection::CopiedVisibility,
        }]
    } else {
        vec![]
    };
    CurrentCollectionFence {
        capabilities: wire::capabilities().encode(),
        manifest: Some(wire::manifest(copied).encode()),
        refs: vec![],
        guard: [17; 32],
        state: state(2, local, owners, Some([17; 32]), 0),
        roots: pointer("gc/3/roots", 18),
        marks: pointer("gc/3/state", 19),
        backend: backend(local),
        controls: vec![],
    }
}

/// Constructs all twelve copied placement fence fields independently.
pub(super) fn copied_fence(local: bool) -> CopiedPlacementFence {
    let common = current_fields(true, local);
    CopiedPlacementFence {
        capabilities: common.capabilities,
        manifest: common.manifest.unwrap(),
        refs: common.refs,
        guard: common.guard,
        state: common.state,
        roots: common.roots,
        marks: common.marks,
        backend: common.backend,
        controls: common.controls,
        genesis: slot(0, 9),
        projection: pointer(format!("publication/snapshots/2:{}", "00".repeat(32)), 20),
    }
}
