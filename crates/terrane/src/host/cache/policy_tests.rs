//! Exercises eviction decisions and physical-charge transitions independently.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture setup and expected success assertions intentionally panic on failure."
)]

use super::{CacheEntry, CachePolicy, CircuitBreaker, PolicyConfig};
use std::time::Duration;

#[test]
fn host_cache_pin_preflight_checks_full_snapshot_bytes_before_reserving() {
    use super::{CacheState, LeaseRecord, PinRecord, ReservationRecord, StateLimits};

    let mut reserved = CacheState::default();
    reserved.reservations.push(ReservationRecord {
        id: "a".repeat(32),
        owner: "fixture".into(),
        bytes: 16384,
    });
    let generous = StateLimits {
        bytes: 4096,
        records: 4,
    };
    let reserved_bytes = reserved.encoded_len(generous).unwrap();
    let mut pinned = reserved.clone();
    pinned.leases.push(LeaseRecord {
        owner: "metadata:fixture".into(),
        expires: u64::MAX,
    });
    pinned.pins.push(PinRecord {
        owner: "metadata:fixture".into(),
        hash: "b".repeat(64),
        expires: u64::MAX,
    });
    let exact = StateLimits {
        bytes: reserved_bytes,
        records: 4,
    };

    assert_eq!(reserved.encoded_len(exact).unwrap(), reserved_bytes);
    assert!(pinned.encoded_len(exact).is_err());
    assert!(pinned.encoded_len(generous).unwrap() > reserved_bytes);
}

fn cache() -> CachePolicy {
    CachePolicy::new(PolicyConfig {
        capacity: 100,
        low_watermark: 50,
        probation_bytes: 10,
        release_grace: Duration::from_secs(5),
        scan_limit: 32,
    })
    .unwrap()
}

fn insert(cache: &mut CachePolicy, key: &str, bytes: u64) {
    cache
        .reserve(key.to_owned(), "tenant".to_owned(), bytes)
        .unwrap();
    cache
        .admit(
            key,
            CacheEntry::new(key.to_owned(), bytes, "tenant".to_owned()),
        )
        .unwrap();
}

#[test]
fn host_cache_probation_main_second_chance_and_retirement_charge() {
    let mut cache = cache();
    insert(&mut cache, "hot", 30);
    insert(&mut cache, "cold", 30);
    insert(&mut cache, "warm", 30);
    cache.touch("hot");
    cache.touch("warm");

    let victims = cache.eviction_candidates(Duration::ZERO);

    assert_eq!(victims, ["cold", "hot"]);
    assert_eq!(cache.charged_bytes(), 90);
    assert!(cache.reserve("new".into(), "tenant".into(), 20).is_err());
    cache.finish_retirement("cold").unwrap();
    assert_eq!(cache.charged_bytes(), 60);
    cache.reserve("new".into(), "tenant".into(), 20).unwrap();
    assert_eq!(cache.charged_bytes(), 80);
}

#[test]
fn host_cache_pin_grace_and_read_cancellation_restore_queue_membership() {
    let mut cache = cache();
    insert(&mut cache, "pinned", 60);
    cache.pin("pinned").unwrap();
    assert!(
        cache
            .eviction_candidates(Duration::from_secs(20))
            .is_empty()
    );
    cache.release("pinned", Duration::from_secs(20)).unwrap();
    assert!(
        cache
            .eviction_candidates(Duration::from_secs(24))
            .is_empty()
    );
    assert_eq!(
        cache.eviction_candidates(Duration::from_secs(25)),
        ["pinned"]
    );

    cache.touch("pinned");

    assert!(cache.finish_retirement("pinned").is_err());
    assert_eq!(
        cache.eviction_candidates(Duration::from_secs(26)),
        ["pinned"]
    );
    cache.finish_retirement("pinned").unwrap();
    assert_eq!(cache.charged_bytes(), 0);
}

#[test]
fn host_cache_owner_quota_and_failed_reservation_are_exact() {
    let mut cache = cache();
    cache.set_quota("tenant".into(), 40);
    insert(&mut cache, "one", 30);
    assert!(
        cache
            .reserve("too-large".into(), "tenant".into(), 11)
            .is_err()
    );
    assert_eq!(cache.charged_bytes(), 30);
    cache.reserve("fits".into(), "tenant".into(), 10).unwrap();
    assert_eq!(cache.charged_bytes(), 40);
    cache.cancel_reservation("fits");
    assert_eq!(cache.charged_bytes(), 30);
}

#[test]
fn host_cache_circuit_probes_once_per_interval_and_recovers() {
    let mut circuit = CircuitBreaker::new(2, Duration::from_secs(3)).unwrap();
    circuit.failure(Duration::ZERO);
    assert!(circuit.allow(Duration::ZERO));
    circuit.failure(Duration::ZERO);
    assert!(!circuit.allow(Duration::from_secs(2)));
    assert!(circuit.allow(Duration::from_secs(3)));
    assert!(!circuit.allow(Duration::from_secs(3)));
    circuit.success();
    assert!(circuit.allow(Duration::from_secs(3)));
}

#[test]
fn host_cache_eviction_counts_reservations_and_large_incoming_allocations() {
    let mut cache = cache();
    insert(&mut cache, "resident", 40);
    cache
        .reserve("inflight".into(), "other-owner".into(), 50)
        .unwrap();

    assert_eq!(
        cache.eviction_candidates_for(50, Duration::ZERO),
        ["resident"]
    );
    assert_eq!(cache.charged_bytes(), 90);
    cache.finish_retirement("resident").unwrap();
    assert_eq!(cache.charged_bytes(), 50);
    cache
        .reserve("incoming".into(), "tenant".into(), 50)
        .unwrap();
    assert_eq!(cache.charged_bytes(), 100);
}

#[test]
fn host_cache_external_quota_deficit_does_not_require_fictitious_reservations() {
    let mut cache = cache();
    insert(&mut cache, "resident", 30);

    // Measured project overhead can require reclamation even while the cached
    // body inventory alone lies below its low watermark.
    assert!(cache.eviction_candidates(Duration::ZERO).is_empty());
    assert_eq!(
        cache.eviction_candidates_to_reclaim(25, Duration::ZERO),
        ["resident"]
    );
    assert_eq!(cache.charged_bytes(), 30);
    assert!(
        cache
            .eviction_candidates_to_reclaim(25, Duration::ZERO)
            .is_empty()
    );
    cache.finish_retirement("resident").unwrap();
    assert_eq!(cache.charged_bytes(), 0);
}

#[test]
fn host_cache_external_deficit_preserves_pins_grace_and_main_second_chance() {
    let mut cache = cache();
    insert(&mut cache, "pinned", 20);
    insert(&mut cache, "grace", 20);
    insert(&mut cache, "cold", 20);
    insert(&mut cache, "hot", 20);
    cache.pin("pinned").unwrap();
    cache.pin("grace").unwrap();
    cache.release("grace", Duration::ZERO).unwrap();
    cache.touch("hot");

    assert_eq!(
        cache.eviction_candidates_to_reclaim(u64::MAX, Duration::from_secs(4)),
        ["cold", "hot"]
    );
    assert_eq!(cache.charged_bytes(), 80);
    assert_eq!(
        cache.eviction_candidates_to_reclaim(1, Duration::from_secs(5)),
        ["grace"]
    );
    assert_eq!(cache.charged_bytes(), 80);
    assert!(cache.finish_retirement("pinned").is_err());
}

#[test]
fn host_cache_protected_queue_cannot_starve_the_other_eligible_queue() {
    let mut probation_pinned = cache();
    insert(&mut probation_pinned, "probation", 60);
    insert(&mut probation_pinned, "main", 30);
    probation_pinned.pin("probation").unwrap();
    probation_pinned.touch("main");

    assert_eq!(
        probation_pinned.eviction_candidates(Duration::ZERO),
        ["main"]
    );
    assert_eq!(probation_pinned.charged_bytes(), 90);
    assert!(probation_pinned.finish_retirement("probation").is_err());

    let mut main_pinned = cache();
    insert(&mut main_pinned, "main", 82);
    insert(&mut main_pinned, "probation", 8);
    main_pinned.touch("main");
    main_pinned.pin("main").unwrap();

    assert_eq!(
        main_pinned.eviction_candidates(Duration::ZERO),
        ["probation"]
    );
    assert_eq!(main_pinned.charged_bytes(), 90);
    assert!(main_pinned.finish_retirement("main").is_err());
}

#[test]
fn host_cache_reassembly_never_keeps_multi_chunk_and_still_seals_inline() {
    use super::ReassemblyMode;
    use crate::host::publication::{PublicationClaim, PublicationRecipe};
    use terrane_core::{
        chunking::ChunkProfile,
        identity::{Descriptor, IdentityKind, TERRANE_V1},
        manifest::{ChunkRef, Manifest},
    };
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let inline_id = TERRANE_V1.calculate(IdentityKind::Chunk, b"x").unwrap();
    let inline = PublicationClaim::new(
        "tenant:fixture".into(),
        PublicationRecipe::Inline {
            chunk: Descriptor::from_identity(&TERRANE_V1, &inline_id, b"x").unwrap(),
        },
        &profile,
    )
    .unwrap();
    let mut first = vec![0_u8; profile.maximum()];
    let boundary = profile.first_boundary(&first);
    first.truncate(boundary);
    let first_id = TERRANE_V1.calculate(IdentityKind::Chunk, &first).unwrap();
    let final_id = TERRANE_V1.calculate(IdentityKind::Chunk, b"x").unwrap();
    let mut full = first.clone();
    full.push(b'x');
    let manifest = Manifest {
        size: full.len() as u64,
        chunks: vec![
            ChunkRef {
                digest: first_id.terrane_v1_digest().unwrap(),
                length: first.len() as u64,
            },
            ChunkRef {
                digest: final_id.terrane_v1_digest().unwrap(),
                length: 1,
            },
        ],
        hashes: [("blake3".into(), blake3::hash(&full).as_bytes().to_vec())].into(),
        media_type: None,
    };
    let encoded = manifest.encode(&profile).unwrap();
    let identity = TERRANE_V1
        .calculate(IdentityKind::Manifest, &encoded)
        .unwrap();
    let multi = PublicationClaim::new(
        "tenant:fixture".into(),
        PublicationRecipe::Manifest {
            object: Descriptor::from_identity(&TERRANE_V1, &identity, &encoded).unwrap(),
            canonical_manifest: encoded,
        },
        &profile,
    )
    .unwrap();

    assert!(ReassemblyMode::Never.requires_sealed_file(&inline));
    assert!(!ReassemblyMode::Never.requires_sealed_file(&multi));
    assert!(ReassemblyMode::Always.requires_sealed_file(&multi));
    assert!(ReassemblyMode::try_from("smart").is_err());
}

#[test]
fn host_cache_index_reconstruction_checks_every_body_before_deriving_bytes() {
    use crate::{
        pack::{EntryKind, PackClass, PackId, PackReader, PackWriter},
        repository::MetadataValidator,
    };
    use terrane_core::chunking::ChunkProfile;
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let id = PackId::from_random_bytes([31; 16]);
    let mut writer = PackWriter::new(id, PackClass::Data, false);
    writer
        .append_raw(EntryKind::Chunk, b"first retained body")
        .unwrap();
    writer
        .append_raw(EntryKind::Chunk, b"second retained body")
        .unwrap();
    let pack = writer.seal().unwrap();
    let validator = MetadataValidator::new(profile.clone());
    let dictionaries = Default::default();

    let rebuilt = super::reconstruct_pack_index(
        pack.bytes(),
        id,
        &profile,
        &validator,
        &dictionaries,
        super::HostReadLimits::default(),
    )
    .unwrap();

    assert_eq!(rebuilt.pack_id(), id);
    assert_eq!(rebuilt.bytes(), pack.index_object());
    assert_eq!(
        rebuilt.pack_identity(),
        &terrane_core::identity::TERRANE_V1
            .calculate(terrane_core::identity::IdentityKind::Pack, pack.bytes(),)
            .unwrap()
    );

    let mut damaged = pack.bytes().to_vec();
    let offset = PackReader::open(pack.bytes()).unwrap().entries()[0].offset() as usize;
    damaged[offset + 1] ^= 1;
    assert!(PackReader::open(&damaged).is_ok());
    let failure = super::reconstruct_pack_index(
        &damaged,
        id,
        &profile,
        &validator,
        &dictionaries,
        super::HostReadLimits::default(),
    )
    .err()
    .unwrap();
    assert!(matches!(
        failure.kind(),
        crate::store::StoreErrorKind::Corrupt(_)
    ));
}

#[test]
fn host_cache_index_reconstruction_rejects_wrong_key_and_operator_excess() {
    use crate::{
        pack::{EntryKind, PackClass, PackId, PackWriter},
        repository::MetadataValidator,
    };
    use terrane_core::chunking::ChunkProfile;
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let id = PackId::from_random_bytes([32; 16]);
    let mut writer = PackWriter::new(id, PackClass::Data, false);
    writer
        .append_raw(EntryKind::Chunk, b"retained body")
        .unwrap();
    let pack = writer.seal().unwrap();
    let validator = MetadataValidator::new(profile.clone());
    let dictionaries = Default::default();

    let wrong_key = super::reconstruct_pack_index(
        pack.bytes(),
        PackId::from_random_bytes([33; 16]),
        &profile,
        &validator,
        &dictionaries,
        super::HostReadLimits::default(),
    )
    .err()
    .unwrap();
    assert!(matches!(
        wrong_key.kind(),
        crate::store::StoreErrorKind::Corrupt(_)
    ));

    let over_budget = super::reconstruct_pack_index(
        pack.bytes(),
        id,
        &profile,
        &validator,
        &dictionaries,
        super::HostReadLimits {
            max_allocation_bytes: pack.bytes().len() - 1,
        },
    )
    .err()
    .unwrap();
    assert!(matches!(
        over_budget.kind(),
        crate::store::StoreErrorKind::Capacity
    ));
}

#[test]
fn host_cache_index_reconstruction_distinguishes_dictionary_dependency_failure() {
    use crate::{
        pack::{NativeBodyDecoder, PackClass, PackId, PackWriter},
        repository::MetadataValidator,
        store::{CorruptSubject, StoreErrorKind},
    };
    use terrane_core::{
        chunking::ChunkProfile,
        identity::{IdentityKind, TERRANE_V1},
    };
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let dictionary = b"repeated dictionary content repeated dictionary content";
    let dictionary_identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, dictionary)
        .unwrap();
    let dictionary_digest = dictionary_identity.terrane_v1_digest().unwrap();
    let plaintext = b"repeated dictionary content ".repeat(200);
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &plaintext)
        .unwrap();
    let encoded =
        crate::codec::encode_chunk(&plaintext, profile.maximum(), 3, Some(dictionary)).unwrap();
    assert_eq!(encoded[0], 2);
    let valid = [(dictionary_digest, dictionary.to_vec())].into();
    let id = PackId::from_random_bytes([34; 16]);
    let mut writer = PackWriter::new(id, PackClass::Data, false);
    writer
        .append_chunk(
            identity.terrane_v1_digest().unwrap(),
            &encoded,
            plaintext.len() as u32,
            0,
            &NativeBodyDecoder::new(&profile, &valid),
        )
        .unwrap();
    let pack = writer.seal().unwrap();
    let validator = MetadataValidator::new(profile.clone());
    let limits = super::HostReadLimits::default();

    let missing = super::reconstruct_pack_index(
        pack.bytes(),
        id,
        &profile,
        &validator,
        &Default::default(),
        limits,
    )
    .err()
    .unwrap();
    assert!(
        matches!(missing.kind(), StoreErrorKind::Absent(identity) if identity == &dictionary_identity)
    );

    let invalid = [(dictionary_digest, b"wrong dictionary".to_vec())].into();
    let failure =
        super::reconstruct_pack_index(pack.bytes(), id, &profile, &validator, &invalid, limits)
            .err()
            .unwrap();
    assert!(
        matches!(failure.kind(), StoreErrorKind::Corrupt(CorruptSubject::Identity(identity)) if identity == &dictionary_identity)
    );

    let restored =
        super::reconstruct_pack_index(pack.bytes(), id, &profile, &validator, &valid, limits)
            .unwrap();
    assert_eq!(restored.bytes(), pack.index_object());
}
