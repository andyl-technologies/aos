//! Generates commit, ref, bucket, collector, and creation-journal record models.

use super::support::{Generator, cbor_properties, check_record, token_bytes};
use terrane_format::{bucket, gc, refs};

/// Builds a selected ref record with the supplied sequence and fixed fixture fields.
pub(super) fn head(seq: u64) -> refs::RefRecord {
    refs::RefRecord {
        commit: [8; 32],
        seq,
        writer_epoch: 1,
        home: refs::Locality::default(),
        policy: None,
        candidate_id: Some([9; 32]),
    }
}

/// Builds a seeded Commit model with case-selected provenance and optional fields.
///
/// # Panics
/// Panics if the fixed request cannot be converted into its Commit context.
pub(super) fn commit(generator: &mut Generator, case: usize) -> refs::Commit {
    let mut model = refs::Commit {
        tree: generator.bytes(),
        parents: (0..case % 4).map(|_| generator.bytes()).collect(),
        provenance: refs::Provenance {
            issuer: "issuer".into(),
            token_id: generator.bytes(),
            subject: format!("principal-{case}"),
            kind: [
                refs::PrincipalKind::Human,
                refs::PrincipalKind::Workload,
                refs::PrincipalKind::Service,
            ][case % 3],
            workload_identity: (case.is_multiple_of(2)).then(|| "workload".into()),
            process: "property-test".into(),
            observed_at: generator.next(),
            writer_epoch: generator.next(),
            source: [
                refs::CommitSource::Built,
                refs::CommitSource::Uploaded,
                refs::CommitSource::Imported,
                refs::CommitSource::Merged,
                refs::CommitSource::Derived,
                refs::CommitSource::Migrated,
            ][case % 6],
            embedded_token: None,
        },
        timestamp: generator.next(),
        message: if case.is_multiple_of(2) {
            String::new()
        } else {
            format!("message {case}\0λ")
        },
        profile_pair: refs::ProfilePair {
            tree_format: 1,
            chunk_profile: "cdc-1m".into(),
            recipe: None,
            conflicted: (case.is_multiple_of(2)).then_some(case.is_multiple_of(4)),
            lease: (case.is_multiple_of(3)).then(|| refs::Lease {
                owner: "owner".into(),
                expiry: u64::MAX,
            }),
            required_properties: (case.is_multiple_of(4)).then(|| vec![0xa0]),
            entry_receipts: (case.is_multiple_of(2)).then(Vec::new),
            commit_context: None,
        },
        packs: (case.is_multiple_of(3)).then(|| {
            vec![refs::PackLocation {
                pack_id: generator.bytes(),
                locality: refs::Locality {
                    region: Some("region".into()),
                    zone: Some("zone".into()),
                    host: Some("host".into()),
                },
            }]
        }),
        signature: (case.is_multiple_of(2)).then(|| generator.bytes()),
    };
    if case.is_multiple_of(3) {
        model.provenance.embedded_token = Some(token_bytes(1, 2, generator));
        model.profile_pair.commit_context = Some(
            refs::CommitContext::from_request(&terrane_format::auth::Request {
                reference: b"refs/heads/_/main",
                verb: terrane_format::auth::Verb::Commit,
                roots: &[
                    terrane_format::auth::RequestRoot {
                        path: b"/",
                        domain: "public",
                    },
                    terrane_format::auth::RequestRoot {
                        path: b"/graft",
                        domain: "tenant:generated",
                    },
                ],
                now: 0,
                surface: "sdk",
                locality: &refs::Locality::default(),
                epochs: &[],
            })
            .unwrap(),
        );
        model.profile_pair.recipe = Some(
            terrane_format::algebra::Recipe::Overlay(&[generator.bytes(), generator.bytes()])
                .encode(),
        );
    }
    model
}

#[test]
fn commit_ref_reflog_and_annotation_models_preserve_optional_fields() {
    let mut generator = Generator::new(0xb881_35e2_39a7_f021);
    for case in 0..24 {
        let mut model = commit(&mut generator, case);
        if case % 3 == 0 {
            model.profile_pair.entry_receipts = Some(vec![refs::EntryReceipt {
                root: generator.bytes(),
                path: b"file".to_vec(),
                origin: refs::EntryOrigin::Current,
                attributes: Some(vec![("sha256".into(), refs::EntryOrigin::Current)]),
                reintroduced_from: Some(refs::EntrySource {
                    commit: generator.bytes(),
                    root: generator.bytes(),
                    path: b"source".to_vec(),
                }),
                disclosure_proof: Some(refs::DisclosureProof {
                    authority_key: "01".repeat(32),
                    source_domain: "public".into(),
                    observed_at: generator.next(),
                    signature: generator.bytes(),
                }),
            }]);
        }
        check_record!(
            "commit and provenance/profile/receipt",
            model.clone(),
            refs::Commit
        );
        let mut unsigned = model.clone();
        unsigned.signature = None;
        let preimage = model.signature_preimage().unwrap();
        assert_eq!(preimage, unsigned.encode().unwrap());
        cbor_properties("unsigned commit preimage", &preimage, |input| {
            refs::Commit::decode(input)?.encode()
        });
        let mut record = head([1, 23, 24, u64::MAX][case % 4]);
        record.commit = generator.bytes();
        record.writer_epoch = generator.next();
        record.candidate_id = (case % 2 == 0).then(|| generator.bytes());
        record.policy = (case % 3 != 0).then(|| refs::RefPolicy {
            multi_writer: Some(case % 2 == 0),
            merge_policies: Some(vec![
                refs::MergePolicy::PreferOurs,
                refs::MergePolicy::PreferTheirs,
                refs::MergePolicy::PreferTrusted,
                refs::MergePolicy::PreferNewer,
                refs::MergePolicy::KeepConflict,
                refs::MergePolicy::Error,
            ]),
            retention: Some(
                [
                    refs::Retention::Gc,
                    refs::Retention::Lease,
                    refs::Retention::Forever,
                    refs::Retention::Ttl(u64::MAX),
                ][case % 4],
            ),
            conflicted: Some(case % 2 == 0),
            snapshot: (case % 2 == 0).then(|| refs::SnapshotEnvelope {
                tag: refs::RefName::parse("refs/tags/_/snapshot").unwrap(),
                commit: record.commit,
                attestation: if case % 4 == 0 {
                    vec![0xa0]
                } else {
                    vec![0xa1, 0x61, b'a', 0xf4]
                },
                signer_key: "key".into(),
                signature: generator.bytes(),
            }),
        });
        if let Some(snapshot) = record
            .policy
            .as_ref()
            .and_then(|policy| policy.snapshot.as_ref())
        {
            let mut expected = vec![];
            terrane_format::cbor::write_map(&mut expected, 4);
            terrane_format::cbor::write_uint(&mut expected, 1);
            terrane_format::cbor::write_text(&mut expected, snapshot.tag.as_str());
            terrane_format::cbor::write_uint(&mut expected, 2);
            terrane_format::cbor::write_bytes(&mut expected, &snapshot.commit);
            terrane_format::cbor::write_uint(&mut expected, 3);
            expected.extend_from_slice(&snapshot.attestation);
            terrane_format::cbor::write_uint(&mut expected, 4);
            terrane_format::cbor::write_text(&mut expected, &snapshot.signer_key);
            assert_eq!(snapshot.signature_preimage().unwrap(), expected);
            let mut changed = snapshot.clone();
            changed.signature = generator.bytes();
            assert_eq!(changed.signature_preimage().unwrap(), expected);
        }
        check_record!("ref and annotation", record.clone(), refs::RefRecord);
        record.candidate_id = None;
        check_record!(
            "reflog",
            refs::RefLogRecord {
                record,
                previous_commit: (case % 2 == 0).then(|| generator.bytes()),
                principal: format!("principal-{case}"),
                reason: [
                    refs::RefLogReason::Commit,
                    refs::RefLogReason::Merge,
                    refs::RefLogReason::Fold,
                    refs::RefLogReason::Rollback,
                    refs::RefLogReason::JobCheckpoint,
                    refs::RefLogReason::Migrate
                ][case % 6],
                timestamp: generator.next(),
                expected_previous: None,
                committed_previous: None
            },
            refs::RefLogRecord
        );
    }
}

#[test]
fn bucket_capabilities_generations_and_tombstones_preserve_known_empty_inventory() {
    let mut generator = Generator::new(0xcd31_2b37_f099_c401);
    for case in 0..24 {
        check_record!(
            "capabilities and store profile",
            bucket::BucketCapabilities {
                layout_version: if case % 2 == 0 { 1 } else { 2 },
                create_if_absent: case % 2 == 0,
                compare_and_swap: case % 3 == 0,
                ranges: case % 4 == 0,
                presign: case % 3 == 0,
                multi_writer: case % 5 == 0,
                probed_at: generator.next(),
                profile: bucket::StoreProfile {
                    identity: "terrane-v1".into(),
                    algorithm: "blake3".into(),
                    chunk: "cdc-1m".into(),
                    seed: generator.bytes()
                },
                generation: (case % 2 == 0).then(|| generator.next()),
                ref_names: match case % 3 {
                    0 => None,
                    1 => Some(vec![]),
                    _ => Some(vec!["refs/heads/_/a".into(), "refs/tags/_/b".into()]),
                },
                publication_protocol: (case % 2 == 0).then_some(1)
            },
            bucket::BucketCapabilities
        );
        let inventory = bucket::PackInventoryEntry {
            pack_id: [1; 16],
            pack_hash: generator.bytes(),
            pack_size: 52,
            index_hash: generator.bytes(),
            index_size: 36,
        };
        check_record!(
            "generation manifest",
            bucket::GenerationManifest {
                generation: generator.next(),
                shards: (0..case % 4)
                    .map(|shard| bucket::GenerationShard {
                        shard: shard as u64,
                        index_hash: generator.bytes(),
                        index_size: generator.next(),
                        filter: (case % 2 == 0).then(|| (generator.bytes(), generator.next()))
                    })
                    .collect(),
                written_at: generator.next(),
                cycle: generator.next(),
                inventory: match case % 3 {
                    0 => None,
                    1 => Some(vec![]),
                    _ => Some(vec![inventory]),
                },
                exclusions: (case % 2 == 0).then(|| vec![bucket::PackExclusion {
                    pack_id: [2; 16],
                    cycle: 3,
                    epoch: 4
                }]),
                burns: (case % 2 == 0).then(|| vec![[3; 16]])
            },
            bucket::GenerationManifest
        );
        let model = bucket::Tombstone {
            pack_id: generator.bytes(),
            cycle: generator.next(),
            tombstoned_at: generator.next(),
            removed_entries: generator.next(),
            epoch: generator.next(),
        };
        let bytes = model.encode();
        assert_eq!(bucket::Tombstone::decode(&bytes).unwrap(), model);
        cbor_properties("bucket tombstone", &bytes, |input| {
            Ok::<_, bucket::RecordError>(bucket::Tombstone::decode(input)?.encode())
        });
    }
}

#[test]
fn collector_lease_roots_marks_and_checkpoint_models_cover_empty_and_context_variants() {
    let mut generator = Generator::new(0xc995_8a60_fd39_45eb);
    let reasons = [
        gc::RootReason::Current,
        gc::RootReason::ReflogGc,
        gc::RootReason::ReflogCount,
        gc::RootReason::ReflogTtl,
        gc::RootReason::Lease,
        gc::RootReason::Forever,
        gc::RootReason::Tag,
        gc::RootReason::Job,
        gc::RootReason::RetentionWitness,
    ];
    for case in 0..12 {
        check_record!(
            "collector lease",
            gc::GcLease {
                holder: format!("collector-{case}"),
                epoch: generator.next(),
                expiry: generator.next()
            },
            gc::GcLease
        );
        let roots = gc::GcRoots {
            cycle: generator.next(),
            epoch: generator.next(),
            timestamp: generator.next(),
            roots: reasons[..case.min(reasons.len())]
                .iter()
                .map(|reason| gc::GcRoot {
                    reference: refs::RefName::parse("refs/heads/_/main").unwrap(),
                    commit: generator.bytes(),
                    parent_cutoff: match case % 3 {
                        0 => gc::ParentCutoff::Unbounded,
                        1 => gc::ParentCutoff::RootsOnly,
                        _ => gc::ParentCutoff::Since(u64::MAX),
                    },
                    reason: *reason,
                })
                .collect(),
        };
        let bytes = roots.encode();
        assert_eq!(gc::GcRoots::decode(&bytes).unwrap(), roots);
        cbor_properties("GC roots", &bytes, |input| {
            Ok::<_, gc::GcError>(gc::GcRoots::decode(input)?.encode())
        });
        let mut hashes: Vec<_> = (0..case)
            .map(|_| {
                let mut hash = generator.bytes::<32>();
                hash[0] = 7;
                hash
            })
            .collect();
        hashes.sort();
        let mark = gc::GcMark::new(generator.next(), generator.next(), 7, hashes).unwrap();
        let bytes = mark.encode();
        assert_eq!(gc::GcMark::decode(&bytes).unwrap(), mark);
        cbor_properties("GC mark and filter", &bytes, |input| {
            Ok::<_, gc::GcError>(gc::GcMark::decode(input)?.encode())
        });
        check_record!(
            "GC checkpoint",
            gc::GcState {
                cycle: generator.next(),
                epoch: generator.next(),
                phase: [
                    gc::Phase::Mark,
                    gc::Phase::Sweep,
                    gc::Phase::Delete,
                    gc::Phase::Done
                ][case % 4],
                snapshot_at: generator.next(),
                checkpoints: (0..case % 4)
                    .map(|shard| gc::CheckpointPointer {
                        shard: shard as u8,
                        revision: generator.next(),
                        hash: generator.bytes()
                    })
                    .collect(),
                pending: vec![
                    gc::Pending {
                        kind: 3,
                        hash: generator.bytes(),
                        parent_cutoff: gc::ParentCutoff::RootsOnly,
                        flags: 1,
                        proof_context: None
                    },
                    gc::Pending {
                        kind: 2,
                        hash: generator.bytes(),
                        parent_cutoff: gc::ParentCutoff::Unbounded,
                        flags: 14,
                        proof_context: None
                    }
                ],
                expanded: vec![],
                progress: vec![],
                objects: vec![]
            },
            gc::GcState
        );
    }
}

#[test]
fn creation_journal_models_cover_all_states_and_opaque_identity_boundaries() {
    let mut generator = Generator::new(0x770d_8841_f256_037b);
    for length in [1, 31, 32, 128] {
        let identity: Vec<_> = (0..length).map(|_| generator.next() as u8).collect();
        for state in [
            gc::JournalState::Pending,
            gc::JournalState::Invalidated,
            gc::JournalState::Committed {
                binding: gc::ArtifactBinding::Pack {
                    digest: generator.bytes(),
                    size: 52,
                },
                file_identity: identity.clone(),
            },
            gc::JournalState::DeleteOwned {
                binding: gc::ArtifactBinding::Pack {
                    digest: generator.bytes(),
                    size: 52,
                },
                file_identity: identity.clone(),
                operation_key: format!("gc/3/delete/{}/{}", "01".repeat(16), "02".repeat(32)),
                authorization: generator.bytes(),
            },
        ] {
            let model = gc::CreationJournal {
                key: format!("objects/pack/01/{}.pack", "01".repeat(16)),
                nonce: generator.bytes(),
                state,
            };
            check_record!("creation journal", model, gc::CreationJournal);
        }
    }
    // Both public tombstone APIs encode the same registered wire format.
    let model = gc::Tombstone {
        pack: [1; 16],
        cycle: u64::MAX,
        timestamp: 0,
        removed: 1,
        epoch: 2,
    };
    let bytes = model.encode();
    assert_eq!(gc::Tombstone::decode(&bytes).unwrap(), model);
    cbor_properties("GC tombstone", &bytes, |input| {
        Ok::<_, gc::GcError>(gc::Tombstone::decode(input)?.encode())
    });
}

#[test]
fn selected_reflogs_and_proof_sensitive_checkpoints_preserve_all_predecessor_forms() {
    let mut generator = Generator::new(0x091f_221b_c790_537d);
    for predecessor_kind in 0..3 {
        let previous = head(23);
        let record = if predecessor_kind == 0 {
            head(1)
        } else {
            head(24)
        };
        check_record!(
            "selected reflog predecessor",
            refs::RefLogRecord {
                record,
                previous_commit: (predecessor_kind != 0).then_some(previous.commit),
                principal: "principal".into(),
                reason: refs::RefLogReason::Commit,
                timestamp: generator.next(),
                expected_previous: Some(if predecessor_kind == 1 {
                    Some(previous.clone())
                } else {
                    None
                }),
                committed_previous: (predecessor_kind == 2).then_some(previous),
            },
            refs::RefLogRecord
        );
    }
    for phase in [
        gc::Phase::Snapshot,
        gc::Phase::Mark,
        gc::Phase::Sweep,
        gc::Phase::Delete,
        gc::Phase::Done,
    ] {
        let mut model = gc::GcState {
            cycle: generator.next(),
            epoch: generator.next(),
            phase,
            snapshot_at: generator.next(),
            checkpoints: vec![],
            pending: vec![],
            expanded: vec![],
            progress: vec![[0; 16], [255; 16]],
            objects: vec![],
        };
        for context in [
            None,
            Some(gc::ProofContext::new([3; 32], [4; 32], b"/aa".to_vec()).unwrap()),
            Some(gc::ProofContext::new([3; 32], [4; 32], b"/z".to_vec()).unwrap()),
        ] {
            model.pending.push(gc::Pending {
                kind: 2,
                hash: [5; 32],
                parent_cutoff: gc::ParentCutoff::Unbounded,
                flags: 14,
                proof_context: context.clone(),
            });
            model.expanded.push(gc::ExpandedContext {
                commit: [6; 32],
                parent_cutoff: gc::ParentCutoff::Since(generator.next()),
                proof_context: context.clone(),
            });
            model.objects.push(gc::ExpandedObject {
                kind: 2,
                hash: [5; 32],
                flags: 14,
                proof_context: context,
            });
        }
        check_record!("proof-sensitive GC state", model.clone(), gc::GcState);
        model.pending[0].flags = 16;
        assert!(model.encode().is_err());
    }
}

#[test]
fn creation_journal_binding_models_cover_pack_index_trash_and_empty_identity_rejection() {
    let mut generator = Generator::new(0x1fc8_392a_bb72_dbe5);
    let pack = [1; 16];
    let tombstone = bucket::Tombstone {
        pack_id: pack,
        cycle: 3,
        tombstoned_at: u64::MAX,
        removed_entries: 0,
        epoch: 2,
    }
    .encode();
    for (key, binding) in [
        (
            format!("objects/pack/01/{}.pack", "01".repeat(16)),
            gc::ArtifactBinding::Pack {
                digest: generator.bytes(),
                size: u64::MAX,
            },
        ),
        (
            format!("objects/pack/01/{}.idx", "01".repeat(16)),
            gc::ArtifactBinding::Index {
                digest: generator.bytes(),
                size: u64::MAX,
            },
        ),
        (
            format!("trash/3/{}", "01".repeat(16)),
            gc::ArtifactBinding::Trash(tombstone),
        ),
    ] {
        for length in [1, 128] {
            let file_identity: Vec<_> = (0..length).map(|_| generator.next() as u8).collect();
            for owned in [false, true] {
                let model = gc::CreationJournal {
                    key: key.clone(),
                    nonce: generator.bytes(),
                    state: if owned {
                        gc::JournalState::DeleteOwned {
                            binding: binding.clone(),
                            file_identity: file_identity.clone(),
                            operation_key: format!(
                                "gc/3/delete/{}/{}",
                                "01".repeat(16),
                                "02".repeat(32)
                            ),
                            authorization: generator.bytes(),
                        }
                    } else {
                        gc::JournalState::Committed {
                            binding: binding.clone(),
                            file_identity: file_identity.clone(),
                        }
                    },
                };
                check_record!("journal binding alternative", model, gc::CreationJournal);
            }
        }
        let invalid = gc::CreationJournal {
            key,
            nonce: generator.bytes(),
            state: gc::JournalState::Committed {
                binding,
                file_identity: vec![],
            },
        };
        assert!(invalid.encode().is_err());
    }
}

#[test]
fn nested_receipt_origins_context_surfaces_and_ref_policy_presence_roundtrip() {
    let mut generator = Generator::new(0x9d40_b8e2_5173_eebb);
    for surface in [
        "sdk",
        "fuse",
        "erofs",
        "block",
        "virtiofs",
        "virtio-pmem",
        "nix-cache",
        "reapi",
        "gha-cache",
        "git",
        "oci",
        "browse",
        "api",
    ] {
        let mut model = commit(&mut generator, 1);
        let locality = refs::Locality {
            region: Some("region".into()),
            zone: Some("zone".into()),
            host: Some("host".into()),
        };
        let context = refs::CommitContext::from_request(&terrane_format::auth::Request {
            reference: b"refs/heads/_/main",
            verb: terrane_format::auth::Verb::Commit,
            roots: &[terrane_format::auth::RequestRoot {
                path: b"/",
                domain: "public",
            }],
            now: 0,
            surface,
            locality: &locality,
            epochs: &[],
        })
        .unwrap();
        model.profile_pair.commit_context = Some(context);
        let source = refs::EntrySource {
            commit: generator.bytes(),
            root: generator.bytes(),
            path: vec![0; 4096],
        };
        for origin in [
            refs::EntryOrigin::Current,
            refs::EntryOrigin::Source(source.clone()),
        ] {
            for attributes in [
                None,
                Some(vec![]),
                Some(vec![
                    ("a".into(), refs::EntryOrigin::Current),
                    ("zz".into(), refs::EntryOrigin::Source(source.clone())),
                ]),
            ] {
                model.profile_pair.entry_receipts = Some(vec![refs::EntryReceipt {
                    root: generator.bytes(),
                    path: vec![0; 4096],
                    origin: origin.clone(),
                    attributes,
                    reintroduced_from: None,
                    disclosure_proof: None,
                }]);
                check_record!(
                    "receipt origin and authoring surface",
                    model.clone(),
                    refs::Commit
                );
            }
        }
    }
    for fields in 0..32 {
        let mut record = head(1);
        record.home = refs::Locality {
            region: (fields & 1 != 0).then(|| "region".into()),
            zone: (fields & 2 != 0).then(|| "zone".into()),
            host: (fields & 4 != 0).then(|| "host".into()),
        };
        record.policy = Some(refs::RefPolicy {
            multi_writer: (fields & 1 != 0).then_some(false),
            merge_policies: (fields & 2 != 0).then(|| vec![refs::MergePolicy::KeepConflict]),
            retention: (fields & 4 != 0).then_some(refs::Retention::Forever),
            conflicted: (fields & 8 != 0).then_some(true),
            snapshot: (fields & 16 != 0).then(|| refs::SnapshotEnvelope {
                tag: refs::RefName::parse("refs/tags/_/tag").unwrap(),
                commit: record.commit,
                attestation: vec![0xa0],
                signer_key: "key".into(),
                signature: generator.bytes(),
            }),
        });
        check_record!("ref policy optional fields", record, refs::RefRecord);
    }
    let mut model = commit(&mut generator, 0);
    model.packs = Some(vec![]);
    assert!(model.encode().is_err());
}

#[test]
fn collector_kind_models_cover_all_registered_tags_and_flag_constraints() {
    let mut generator = Generator::new(0x8e33_290f_b371_045c);
    let mut model = gc::GcState {
        cycle: generator.next(),
        epoch: generator.next(),
        phase: gc::Phase::Mark,
        snapshot_at: generator.next(),
        checkpoints: vec![],
        pending: vec![],
        expanded: vec![],
        progress: vec![],
        objects: vec![],
    };
    for kind in 0..=9 {
        let hash = [kind; 32];
        let flags = if kind == 0 { 0 } else { 8 };
        model.pending.push(gc::Pending {
            kind,
            hash,
            parent_cutoff: gc::ParentCutoff::Unbounded,
            flags,
            proof_context: None,
        });
        model.objects.push(gc::ExpandedObject {
            kind,
            hash,
            flags,
            proof_context: None,
        });
    }
    check_record!("collector registered kinds", model.clone(), gc::GcState);
    for (kind, flags) in [(0, 8), (1, 1), (1, 2), (1, 4), (10, 0)] {
        let mut invalid = model.clone();
        invalid.pending[0].kind = kind;
        invalid.pending[0].flags = flags;
        assert!(invalid.encode().is_err());
    }
}

// The ordinary Commit envelope is independently framed so invalid token counts
// reach the actual decoder without first passing the rejecting Commit encoder.
fn embedded_token_commit_wire(token: &[u8]) -> Vec<u8> {
    use terrane_format::cbor;
    let mut bytes = vec![];
    cbor::write_map(&mut bytes, 6);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_bytes(&mut bytes, &[1; 32]);
    cbor::write_uint(&mut bytes, 2);
    cbor::write_array(&mut bytes, 0);
    cbor::write_uint(&mut bytes, 3);
    cbor::write_map(&mut bytes, 9);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_text(&mut bytes, "issuer");
    cbor::write_uint(&mut bytes, 2);
    cbor::write_bytes(&mut bytes, &[2; 16]);
    cbor::write_uint(&mut bytes, 3);
    cbor::write_text(&mut bytes, "principal");
    cbor::write_uint(&mut bytes, 4);
    cbor::write_uint(&mut bytes, 2);
    cbor::write_uint(&mut bytes, 6);
    cbor::write_text(&mut bytes, "process");
    for (key, value) in [(7, 0), (8, 1), (9, 2)] {
        cbor::write_uint(&mut bytes, key);
        cbor::write_uint(&mut bytes, value);
    }
    cbor::write_uint(&mut bytes, 10);
    bytes.extend_from_slice(token);
    cbor::write_uint(&mut bytes, 4);
    cbor::write_uint(&mut bytes, 0);
    cbor::write_uint(&mut bytes, 5);
    cbor::write_text(&mut bytes, "");
    cbor::write_uint(&mut bytes, 6);
    cbor::write_map(&mut bytes, 2);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_uint(&mut bytes, 1);
    cbor::write_uint(&mut bytes, 2);
    cbor::write_text(&mut bytes, "cdc-1m");
    bytes
}

#[test]
fn embedded_provenance_tokens_reject_block_and_grant_limits() {
    let mut generator = Generator::new(0x6492_d180_eb7c_a921);
    for (grants, blocks) in [(1, 1), (256, 1), (1, 16), (256, 16)] {
        let token = token_bytes(grants, blocks, &mut generator);
        let expected = embedded_token_commit_wire(&token);
        let model = refs::Commit {
            tree: [1; 32],
            parents: vec![],
            provenance: refs::Provenance {
                issuer: "issuer".into(),
                token_id: [2; 16],
                subject: "principal".into(),
                kind: refs::PrincipalKind::Workload,
                workload_identity: None,
                process: "process".into(),
                observed_at: 0,
                writer_epoch: 1,
                source: refs::CommitSource::Uploaded,
                embedded_token: Some(token),
            },
            timestamp: 0,
            message: String::new(),
            profile_pair: refs::ProfilePair {
                tree_format: 1,
                chunk_profile: "cdc-1m".into(),
                recipe: None,
                conflicted: None,
                lease: None,
                required_properties: None,
                entry_receipts: None,
                commit_context: None,
            },
            packs: None,
            signature: None,
        };
        assert_eq!(model.encode().unwrap(), expected);
        assert_eq!(refs::Commit::decode(&expected).unwrap(), model);
        assert_eq!(
            refs::Commit::decode(&expected).unwrap().identity(),
            model.identity()
        );
        if grants == 1 && blocks == 1 {
            cbor_properties("embedded provenance token", &expected, |bytes| {
                refs::Commit::decode(bytes)?.encode()
            });
        }
    }

    // Present canonical token bodies exceed each named nested count. Refusal
    // alone does not observe allocation; borrowed-before-copy source order is
    // the companion evidence for this regression.
    for (grants, blocks) in [(1, 17), (257, 1), (257, 17)] {
        let token = token_bytes(grants, blocks, &mut generator);
        let mut decoder = terrane_format::cbor::Decoder::new(&token);
        decoder.skip_value(token.len()).unwrap();
        decoder.finish().unwrap();
        let wire = embedded_token_commit_wire(&token);
        assert_eq!(
            refs::Commit::decode(&wire),
            Err(refs::RecordError::Cbor(terrane_format::cbor::Error::Limit))
        );
    }
}
