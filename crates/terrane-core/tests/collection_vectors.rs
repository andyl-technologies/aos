//! Checks collection wire witnesses against separately constructed public models.
//!
//! Positive cases compare exact bytes and decoded fields. Negative inputs are
//! reproduced independently by the reference generator. Ordinary record models
//! do not establish verified history, checkpoint integrity or effect authority.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "published fixtures and separately constructed test models must match"
)]

use terrane_core::bucket::{
    GenerationManifest, GenerationShard, PackExclusion, PackInventoryEntry, Tombstone,
};
use terrane_core::gc::{
    CheckpointPointer, ExpandedContext, ExpandedObject, GcLease, GcMark, GcRoot, GcRoots, GcState,
    ParentCutoff, Pending, Phase, ProofContext, RootReason,
};
use terrane_core::refs::RefName;

const REFERENCE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));

fn wire(name: &str) -> Vec<u8> {
    let marker = format!("### {name}\n");
    assert_eq!(REFERENCE.matches(&marker).count(), 1);
    let section = REFERENCE
        .split_once(&marker)
        .expect("published collection witness is required")
        .1
        .split("\n##")
        .next()
        .unwrap();
    let hex = section
        .split_once("```hex\n")
        .unwrap()
        .1
        .split_once("```")
        .unwrap()
        .0;
    let digits: String = hex
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(digits.len() % 2, 0);

    (0..digits.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&digits[offset..offset + 2], 16).unwrap())
        .collect()
}

#[test]
fn published_collection_lease_matches_bytes_and_model() {
    let model = GcLease {
        holder: "collector".into(),
        epoch: 9,
        expiry: 256,
    };
    let published = wire("collection-lease");

    assert_eq!(model.encode().unwrap(), published);
    assert_eq!(GcLease::decode(&published).unwrap(), model);
}

#[test]
fn published_collection_roots_preserve_every_reason_and_cutoff() {
    let mut model = GcRoots {
        cycle: 7,
        epoch: 9,
        timestamp: 24,
        roots: vec![],
    };
    let empty = wire("collection-roots-empty");
    assert_eq!(model.encode(), empty);
    assert_eq!(GcRoots::decode(&empty).unwrap(), model);

    let reasons = [
        RootReason::Current,
        RootReason::ReflogGc,
        RootReason::ReflogCount,
        RootReason::ReflogTtl,
        RootReason::Lease,
        RootReason::Forever,
        RootReason::Tag,
        RootReason::Job,
        RootReason::RetentionWitness,
    ];
    let cutoffs = [
        ParentCutoff::Unbounded,
        ParentCutoff::Since(23),
        ParentCutoff::RootsOnly,
    ];
    for (index, reason) in reasons.into_iter().enumerate() {
        let reference = match reason {
            RootReason::Tag => "refs/tags/_/release",
            RootReason::Job => "refs/jobs/_/classify",
            _ => "refs/heads/_/main",
        };
        model.roots.push(GcRoot {
            reference: RefName::parse(reference).unwrap(),
            commit: [u8::try_from(index + 1).unwrap(); 32],
            parent_cutoff: cutoffs[index % cutoffs.len()],
            reason,
        });
    }
    let published = wire("collection-roots-reasons");

    assert_eq!(model.encode(), published);
    assert_eq!(GcRoots::decode(&published).unwrap(), model);
    assert!(GcRoots::decode(&wire("collection-roots-true-cutoff")).is_err());
}

#[test]
fn published_collection_marks_reconstruct_exact_hints() {
    let mut second = [2; 32];
    second[0] = 1;
    for (name, hashes) in [
        ("collection-mark-empty", vec![]),
        ("collection-mark-two-hashes", vec![[1; 32], second]),
    ] {
        let model = GcMark::new(7, 9, 1, hashes).unwrap();
        let published = wire(name);

        assert_eq!(model.encode(), published);
        assert_eq!(GcMark::decode(&published).unwrap(), model);
    }
    assert!(GcMark::decode(&wire("collection-mark-bad-filter")).is_err());
}

fn empty_state(phase: Phase) -> GcState {
    GcState {
        cycle: 7,
        epoch: 9,
        phase,
        snapshot_at: 24,
        checkpoints: vec![],
        pending: vec![],
        expanded: vec![],
        progress: vec![],
        objects: vec![],
    }
}

#[test]
fn published_collection_states_preserve_phases_and_fieldwise_contexts() {
    for (name, phase) in [
        ("collection-state-snapshot", Phase::Snapshot),
        ("collection-state-mark", Phase::Mark),
        ("collection-state-sweep", Phase::Sweep),
        ("collection-state-delete", Phase::Delete),
        ("collection-state-done", Phase::Done),
    ] {
        let model = empty_state(phase);
        let published = wire(name);

        assert_eq!(model.encode().unwrap(), published);
        assert_eq!(GcState::decode(&published).unwrap(), model);
    }

    let mut model = empty_state(Phase::Mark);
    model.checkpoints = vec![
        CheckpointPointer {
            shard: 1,
            revision: 0,
            hash: [7; 32],
        },
        CheckpointPointer {
            shard: 255,
            revision: 24,
            hash: [8; 32],
        },
    ];
    model.progress = vec![[1; 16], [2; 16]];
    let contexts = [
        None,
        Some(ProofContext::new([3; 32], [4; 32], b"/aa".to_vec()).unwrap()),
        Some(ProofContext::new([3; 32], [4; 32], b"/z".to_vec()).unwrap()),
    ];
    for proof_context in contexts {
        model.pending.push(Pending {
            kind: 2,
            hash: [5; 32],
            parent_cutoff: ParentCutoff::RootsOnly,
            flags: 2,
            proof_context: proof_context.clone(),
        });
        model.expanded.push(ExpandedContext {
            commit: [6; 32],
            parent_cutoff: ParentCutoff::Unbounded,
            proof_context: proof_context.clone(),
        });
        model.objects.push(ExpandedObject {
            kind: 2,
            hash: [5; 32],
            flags: 2,
            proof_context,
        });
    }
    let published = wire("collection-state-proof-contexts");

    assert_eq!(model.encode().unwrap(), published);
    assert_eq!(GcState::decode(&published).unwrap(), model);
    for name in [
        "collection-state-null-context",
        "collection-state-reversed-contexts",
    ] {
        assert!(GcState::decode(&wire(name)).is_err());
    }
}

#[test]
fn published_collection_tombstone_matches_bytes_and_model() {
    let model = Tombstone {
        pack_id: core::array::from_fn(|index| u8::try_from(index).unwrap()),
        cycle: 7,
        tombstoned_at: 24,
        removed_entries: 2,
        epoch: 9,
    };
    let published = wire("collection-tombstone");

    assert_eq!(model.encode(), published);
    assert_eq!(Tombstone::decode(&published).unwrap(), model);
}

#[test]
fn published_collection_generations_distinguish_unknown_and_known_empty() {
    let mut model = GenerationManifest {
        generation: 24,
        shards: vec![],
        written_at: 256,
        cycle: 7,
        inventory: None,
        exclusions: None,
        burns: None,
    };
    let legacy = wire("collection-generation-legacy");
    assert_eq!(model.encode().unwrap(), legacy);
    assert_eq!(GenerationManifest::decode(&legacy).unwrap(), model);

    model.inventory = Some(vec![]);
    model.exclusions = Some(vec![]);
    model.burns = Some(vec![]);
    let empty = wire("collection-generation-known-empty");
    assert_eq!(model.encode().unwrap(), empty);
    assert_eq!(GenerationManifest::decode(&empty).unwrap(), model);
    assert_ne!(legacy, empty);

    model.shards = vec![
        GenerationShard {
            shard: 1,
            index_hash: [3; 32],
            index_size: 256,
            filter: None,
        },
        GenerationShard {
            shard: 255,
            index_hash: [4; 32],
            index_size: 256,
            filter: Some(([5; 32], 24)),
        },
    ];
    model.inventory = Some(vec![PackInventoryEntry {
        pack_id: core::array::from_fn(|index| u8::try_from(index).unwrap()),
        pack_hash: [6; 32],
        pack_size: 262,
        index_hash: [7; 32],
        index_size: 148,
    }]);
    model.exclusions = Some(vec![PackExclusion {
        pack_id: [9; 16],
        cycle: 7,
        epoch: 9,
    }]);
    model.burns = Some(vec![[10; 16]]);
    let published = wire("collection-generation-complete-fields");

    assert_eq!(model.encode().unwrap(), published);
    assert_eq!(GenerationManifest::decode(&published).unwrap(), model);
    assert!(GenerationManifest::decode(&wire("collection-generation-repeated-burn")).is_err());
}
