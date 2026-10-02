//! Tests inert local journal and permanent-retirement representations, never effects.

use super::{
    publication::binding,
    support::{Generator, cbor_properties, check_record},
};
use terrane_core::gc::publication::*;
use terrane_core::gc::retirement::*;
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_core::{bucket, gc, pack_format};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn tombstone(exclusion: Exclusion) -> Vec<u8> {
    bucket::Tombstone {
        pack_id: exclusion.pack,
        cycle: exclusion.cycle,
        epoch: exclusion.epoch,
        tombstoned_at: 0,
        removed_entries: 0,
    }
    .encode()
}

fn artifact_key(pack: &[u8; 16], index: bool) -> String {
    let id = hex(pack);
    format!(
        "objects/pack/{}/{id}.{}",
        &id[..2],
        if index { "idx" } else { "pack" }
    )
}

fn barrier(exclusion: Exclusion) -> RemoteArtifact {
    let bytes = tombstone(exclusion);
    RemoteArtifact {
        key: format!("trash/{}/{}", exclusion.cycle, hex(&exclusion.pack)),
        digest: *blake3::hash(&bytes).as_bytes(),
        size: bytes.len() as u64,
    }
}

fn witness(pack: [u8; 16]) -> Vec<u8> {
    [
        pack_format::Header::new(pack, false, false).encode(),
        pack_format::encode_index(&[]),
    ]
    .concat()
}

fn authorization(
    generator: &mut Generator,
    case: usize,
    copied: bool,
) -> PermanentDeleteAuthorization {
    let exclusion = Exclusion {
        pack: generator.bytes(),
        cycle: case as u64,
        epoch: case as u64 + 1,
    };
    let lease = gc::GcLease {
        holder: format!("collector-{case}"),
        epoch: exclusion.epoch,
        expiry: u64::MAX,
    };
    let fence = RecordPointer {
        key: format!("gc/{case}/fence/2"),
        digest: generator.bytes(),
    };
    if copied {
        let backend = binding(case);
        let remote = barrier(exclusion);
        let barrier = if case % 2 == 0 {
            BarrierArtifact::Local(LocalBarrierArtifact {
                key: remote.key,
                nonce: generator.bytes(),
                tombstone: tombstone(exclusion),
                file_identity: generator.bytes::<128>()[..[1, 31, 128][case % 3]].to_vec(),
            })
        } else {
            BarrierArtifact::Remote(remote)
        };
        PermanentDeleteAuthorization::Copied(CopiedRetirementAuthorization {
            nonce: generator.bytes(),
            backend,
            exclusion,
            lease,
            deletion_seconds: 2,
            barrier,
            tombstone: tombstone(exclusion),
            deletion_elapsed_nanos: 2_000_000_000,
            fence,
            grace_seconds: 1,
            grace_elapsed_nanos: 1_000_000_000,
            genesis: OwnershipSlot {
                revision: 0,
                digest: generator.bytes(),
            },
            preparation: OwnershipSlot {
                revision: 1,
                digest: generator.bytes(),
            },
            lineage_fence: (case % 3 == 0).then(|| RecordPointer {
                key: format!("gc/{case}/fence/2"),
                digest: generator.bytes(),
            }),
        })
    } else {
        let witness = witness(exclusion.pack);
        let index_digest = TERRANE_V1
            .calculate(IdentityKind::Index, &witness)
            .unwrap()
            .terrane_v1_digest()
            .unwrap();
        PermanentDeleteAuthorization::Sweep(RemoteSweepDeleteAuthorization {
            nonce: generator.bytes(),
            backend: binding(case * 2 + 1),
            exclusion,
            lease,
            deletion_seconds: 2,
            artifacts: [
                RemoteArtifact {
                    key: artifact_key(&exclusion.pack, false),
                    digest: generator.bytes(),
                    size: 52,
                },
                RemoteArtifact {
                    key: artifact_key(&exclusion.pack, true),
                    digest: index_digest,
                    size: witness.len() as u64,
                },
                barrier(exclusion),
            ],
            witness,
            tombstone: tombstone(exclusion),
            deletion_elapsed_nanos: 2_000_000_000,
            fence,
            grace_seconds: 1,
            grace_elapsed_nanos: 1_000_000_000,
        })
    }
}

#[test]
fn permanent_authorization_preparation_and_progress_models_preserve_disjoint_cases() {
    let mut generator = Generator::new(0x591e_b2a8_7794_fd2b);
    for case in 0..12 {
        for copied in [false, true] {
            let auth = authorization(&mut generator, case, copied);
            check_record!(
                "permanent authorization union",
                auth.clone(),
                PermanentDeleteAuthorization
            );
            check_record!(
                "permanent retirement publication proof",
                PublicationProof::PermanentRetirement {
                    authorization: auth.encode().unwrap(),
                    carried: vec![]
                },
                PublicationProof
            );
            match &auth {
                PermanentDeleteAuthorization::Sweep(sweep) => {
                    check_record!(
                        "remote sweep authorization",
                        sweep.clone(),
                        RemoteSweepDeleteAuthorization
                    );
                    let mut invalid = sweep.clone();
                    invalid.deletion_elapsed_nanos -= 1;
                    assert!(invalid.encode().is_err());
                    invalid = sweep.clone();
                    invalid.grace_seconds = u64::MAX;
                    assert!(invalid.encode().is_err());
                }
                PermanentDeleteAuthorization::Copied(copy) => {
                    check_record!(
                        "copied retirement authorization",
                        copy.clone(),
                        CopiedRetirementAuthorization
                    );
                    let plan = CopiedRetirementPlan {
                        nonce: copy.nonce,
                        backend: copy.backend.clone(),
                        exclusion: copy.exclusion,
                        lease: copy.lease.clone(),
                        genesis: copy.genesis,
                        fence: copy.fence.clone(),
                        tombstone: copy.tombstone.clone(),
                        grace_seconds: copy.grace_seconds,
                        deletion_seconds: copy.deletion_seconds,
                    };
                    check_record!("copied retirement plan", plan.clone(), CopiedRetirementPlan);
                    for phase in [PreparationPhase::Preparing, PreparationPhase::Abandoned] {
                        check_record!(
                            "copied preparation",
                            CopiedRetirementPreparation {
                                revision: case as u64,
                                phase,
                                plan: plan.clone()
                            },
                            CopiedRetirementPreparation
                        );
                    }
                    let mut invalid = copy.clone();
                    invalid.genesis.revision = 1;
                    assert!(invalid.encode().is_err());
                }
            }
            for phase in [
                OperationPhase::Proposed,
                OperationPhase::Cancelled,
                OperationPhase::Owned,
            ] {
                let owned = phase == OperationPhase::Owned;
                check_record!(
                    "permanent operation",
                    PermanentDeleteOperation {
                        revision: 4,
                        phase,
                        authorization: auth.clone(),
                        owner: owned.then(|| OwnershipSlot {
                            revision: 3,
                            digest: generator.bytes()
                        }),
                        pass: owned.then(|| RecordPointer {
                            key: format!("gc/{case}/reconcile/{}/4", "01".repeat(32)),
                            digest: generator.bytes()
                        })
                    },
                    PermanentDeleteOperation
                );
            }
            let pointer = RecordPointer {
                key: format!(
                    "gc/{case}/delete/{}/{}",
                    hex(&auth.exclusion().pack),
                    hex(auth.nonce())
                ),
                digest: generator.bytes(),
            };
            for selection in [
                PermanentOwnerSelection::CopiedVisibility,
                PermanentOwnerSelection::Permanent(pointer),
            ] {
                check_record!(
                    "permanent owner selection",
                    selection.clone(),
                    PermanentOwnerSelection
                );
                check_record!(
                    "permanent burn owner",
                    PermanentBurnOwner {
                        pack: auth.exclusion().pack,
                        selection
                    },
                    PermanentBurnOwner
                );
            }
        }
    }
}

#[test]
fn permanent_pass_models_cover_observation_handles_states_and_complete_coverage() {
    let mut generator = Generator::new(0x129e_9918_35b1_f0a7);
    for case in 0..12 {
        let backend = binding(case);
        let state = PublicationState {
            revision: 4,
            loss_generation: 1,
            sources: vec![],
            binding: backend.clone(),
            branches: vec![],
            guard: None,
            burn_owners: Some(vec![]),
        };
        for phase in [PassPhase::Open, PassPhase::PassCompleted] {
            let instances = if case % 2 == 0 {
                vec![ObservedInstance::Unversioned]
            } else {
                vec![
                    ObservedInstance::Unversioned,
                    ObservedInstance::Version(
                        generator.bytes::<128>()[..[1, 32, 128][case % 3]].to_vec(),
                    ),
                    ObservedInstance::Marker(generator.bytes::<128>().to_vec()),
                ]
            };
            let mut observations = vec![];
            for artifact in [
                ObservedArtifact::Pack,
                ObservedArtifact::Index,
                ObservedArtifact::Trash(0),
                ObservedArtifact::Trash(u64::MAX),
            ] {
                for instance in &instances {
                    observations.push(RequestObservation {
                        artifact,
                        instance: instance.clone(),
                        state: if phase == PassPhase::Open && case % 4 == 0 {
                            ObservationState::Planned
                        } else {
                            [
                                ObservationState::ConfirmedAbsent,
                                ObservationState::Indeterminate,
                                ObservationState::Deferred,
                            ][case % 3]
                        },
                    });
                }
            }
            let model = PermanentDeletePass {
                authorization_digest: generator.bytes(),
                owner: OwnershipSlot {
                    revision: 3,
                    digest: generator.bytes(),
                },
                revision: 2,
                pass: case as u64,
                event: generator.next(),
                predecessor: OwnershipSlot {
                    revision: 4,
                    digest: generator.bytes(),
                },
                state: state.clone(),
                lease: gc::GcLease {
                    holder: "collector".into(),
                    epoch: case as u64,
                    expiry: u64::MAX,
                },
                backend: backend.clone(),
                phase,
                observations,
                coverage: if phase == PassPhase::Open {
                    [PassCoverage::Unknown; 3]
                } else {
                    [
                        PassCoverage::CandidateTraversalCompleted,
                        PassCoverage::QualifiedAllVersionAbsenceAtObservation,
                        PassCoverage::CandidateTraversalCompleted,
                    ]
                },
                nonce: generator.bytes(),
                placement_fence: (case % 2 == 0).then(|| RecordPointer {
                    key: format!("gc/{case}/fence/4"),
                    digest: generator.bytes(),
                }),
            };
            check_record!(
                "permanent reconciliation pass",
                model.clone(),
                PermanentDeletePass
            );
            let mut invalid = model;
            invalid.observations.swap(0, 1);
            assert!(invalid.encode().is_err());
        }
    }
}

#[test]
fn current_and_copied_fence_models_validate_represented_inventory_and_backend() {
    let mut generator = Generator::new(0x34b7_ef22_9a03_3147);
    for case in 0..12 {
        let backend = binding(case);
        let guard = generator.bytes();
        let capabilities = bucket::BucketCapabilities {
            layout_version: 2,
            create_if_absent: true,
            compare_and_swap: true,
            ranges: true,
            presign: false,
            multi_writer: false,
            probed_at: generator.next(),
            profile: bucket::StoreProfile {
                identity: "terrane-v1".into(),
                algorithm: "blake3".into(),
                chunk: "cdc-1m".into(),
                seed: generator.bytes(),
            },
            generation: Some(1),
            ref_names: Some(vec![]),
            publication_protocol: Some(1),
        }
        .encode()
        .unwrap();
        let manifest = bucket::GenerationManifest {
            generation: 1,
            shards: vec![],
            written_at: generator.next(),
            cycle: case as u64,
            inventory: Some(vec![]),
            exclusions: Some(vec![]),
            burns: Some(vec![]),
        }
        .encode()
        .unwrap();
        let state = PublicationState {
            revision: 2,
            loss_generation: case as u64,
            sources: vec![],
            binding: backend.clone(),
            branches: vec![],
            guard: Some(guard),
            burn_owners: Some(vec![]),
        };
        let roots = RecordPointer {
            key: format!("gc/{case}/roots"),
            digest: generator.bytes(),
        };
        let marks = RecordPointer {
            key: format!("gc/{case}/state"),
            digest: generator.bytes(),
        };
        check_record!(
            "current collection fence",
            CurrentCollectionFence {
                capabilities: capabilities.clone(),
                manifest: Some(manifest.clone()),
                refs: vec![],
                guard,
                state: state.clone(),
                roots: roots.clone(),
                marks: marks.clone(),
                backend: backend.clone(),
                controls: vec![]
            },
            CurrentCollectionFence
        );
        check_record!(
            "copied placement fence",
            CopiedPlacementFence {
                capabilities,
                manifest,
                refs: vec![],
                guard,
                state,
                roots,
                marks,
                backend,
                controls: vec![],
                genesis: OwnershipSlot {
                    revision: 0,
                    digest: generator.bytes()
                },
                projection: RecordPointer {
                    key: format!("publication/snapshots/2:{}", "00".repeat(32)),
                    digest: generator.bytes()
                }
            },
            CopiedPlacementFence
        );
    }
}

#[test]
fn local_v1_delete_operations_roundtrip_exact_embedded_authorization_and_all_phases() {
    let mut generator = Generator::new(0x92d1_f897_327b_997b);
    for case in 0..12 {
        let exclusion = Exclusion {
            pack: generator.bytes(),
            cycle: case as u64,
            epoch: case as u64 + 1,
        };
        let witness = witness(exclusion.pack);
        let index_digest = TERRANE_V1
            .calculate(IdentityKind::Index, &witness)
            .unwrap()
            .terrane_v1_digest()
            .unwrap();
        let lease = gc::GcLease {
            holder: "collector".into(),
            epoch: exclusion.epoch,
            expiry: u64::MAX,
        };
        let auth = gc::DeleteAuthorization {
            nonce: generator.bytes(),
            pack_id: exclusion.pack,
            cycle: exclusion.cycle,
            epoch: exclusion.epoch,
            original_lease: lease.clone(),
            deletion_seconds: case as u64,
            artifacts: [
                gc::ArtifactVersion {
                    key: artifact_key(&exclusion.pack, false),
                    nonce: generator.bytes(),
                    binding: gc::ArtifactBinding::Pack {
                        digest: generator.bytes(),
                        size: 52,
                    },
                    file_identity: vec![1],
                },
                gc::ArtifactVersion {
                    key: artifact_key(&exclusion.pack, true),
                    nonce: generator.bytes(),
                    binding: gc::ArtifactBinding::Index {
                        digest: index_digest,
                        size: witness.len() as u64,
                    },
                    file_identity: vec![2],
                },
                gc::ArtifactVersion {
                    key: barrier(exclusion).key,
                    nonce: generator.bytes(),
                    binding: gc::ArtifactBinding::Trash(tombstone(exclusion)),
                    file_identity: vec![3],
                },
            ],
            index_witness: witness,
            elapsed_ns: case as u64 * 1_000_000_000,
        };
        for phase in [
            gc::DeletePhase::Authorized,
            gc::DeletePhase::Invalidated,
            gc::DeletePhase::PackAbsent,
            gc::DeletePhase::IndexAbsent,
            gc::DeletePhase::ContainersConfirmed,
            gc::DeletePhase::Done,
            gc::DeletePhase::Cancelled,
        ] {
            let model = gc::DeleteOperation {
                authorization: auth.clone(),
                phase,
                revision: case as u64,
                current_lease: lease.clone(),
            };
            let bytes = model.encode().unwrap();
            let key = auth.operation_key();
            assert_eq!(gc::DeleteOperation::decode(&bytes, &key).unwrap(), model);
            assert_eq!(
                gc::DeleteOperation::decode(&bytes, &key)
                    .unwrap()
                    .authorization
                    .encode()
                    .unwrap(),
                auth.encode().unwrap()
            );
            cbor_properties("local-v1 delete operation", &bytes, |input| {
                gc::DeleteOperation::decode(input, &key)?.encode()
            });
            assert!(gc::DeleteOperation::decode(&bytes, "gc/0/delete/invalid/invalid").is_err());
        }
    }
}
