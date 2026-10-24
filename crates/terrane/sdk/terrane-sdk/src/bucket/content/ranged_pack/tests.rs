//! Exercises real selected member reads with whole-pack I/O forbidden.
//!
//! Fixtures publish actual canonical packs through native staging and selected
//! catalog publication. Filesystem wrappers observe and forward opaque bounded
//! reads; they cannot construct a retained receipt or a selected completion.

#[path = "tests/support.rs"]
pub(in crate::bucket::content) mod support;

use crate::bucket::FileBucket;
use crate::bucket::tests::{Validator, config};
use crate::pack::PackIndexSnapshot;
use crate::store::{
    ByteRange, ContentStore, CorruptSubject, InvalidReason, StoreErrorKind, TokioClock,
    TokioLocalFs,
};
use std::os::unix::fs::PermissionsExt;
use support::{Fixture, ReadProfile, TestResult};
use terrane_format::identity::{IdentityKind, TERRANE_V1};

#[tokio::test]
async fn ranged_chunk_read_uses_bounded_io_with_whole_pack_reads_rejected() -> TestResult {
    for profile in [
        ReadProfile::Native,
        ReadProfile::UnsupportedHooks,
        ReadProfile::ReadOnly,
        ReadProfile::Legacy,
    ] {
        let fixture = Fixture::raw_with_profile(b"bounded member bytes", profile).await?;
        let expected = &fixture.encoded[1..8];
        // Public modes and hardlinks are valid ordinary payload inputs even
        // though protected publication effects apply stricter policy.
        for (path, alias) in [
            (&fixture.pack_path, "ordinary-pack-hardlink"),
            (&fixture.index_path, "ordinary-index-hardlink"),
        ] {
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).await?;
            tokio::fs::hard_link(path, fixture.bucket.root().join(alias)).await?;
        }

        let actual = fixture
            .bucket
            .get(
                &fixture.identity,
                Some(ByteRange {
                    start: 1,
                    length: 7,
                }),
            )
            .await?;

        assert_eq!(actual, expected, "{profile:?}");
        assert_eq!(fixture.fs.whole_reads(), 0, "{profile:?}");
        assert_eq!(fixture.fs.effects(), 0, "{profile:?}");
        if matches!(profile, ReadProfile::ReadOnly) {
            fixture.fs.check_existing_lock_continuity().await?;
        }
        let ranges = fixture.fs.ranges()?;
        let closing = fixture.fs.closing_ranges()?;
        let body_offset = fixture.body_offset()? as u64;
        let pack_length = tokio::fs::metadata(&fixture.pack_path).await?.len();
        assert!(!ranges.is_empty(), "{profile:?}");
        assert!(
            ranges
                .iter()
                .chain(&closing)
                .all(|(_, range)| range.length < pack_length)
        );
        // Check requests expose their genuine retained replay intent. An early
        // refusal may perform less I/O; these counts do not assert completion.
        assert!(
            ranges
                .iter()
                .chain(&closing)
                .map(|(_, range)| range.length)
                .sum::<u64>()
                < 4096
        );
        if matches!(profile, ReadProfile::Native) {
            assert!(!closing.is_empty());
        }
        assert!(ranges.iter().any(|(path, range)| path == &fixture.pack_path
            && range.start == body_offset
            && range.length == fixture.encoded.len() as u64));

        fixture.remove().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ranged_chunk_read_verifies_bytes_outside_requested_slice() -> TestResult {
    let fixture = Fixture::raw(b"verify all of the requested member").await?;
    let mut pack = tokio::fs::read(&fixture.pack_path).await?;
    let last = fixture.body_offset()? + fixture.encoded.len() - 1;
    pack[last] ^= 1;
    tokio::fs::write(&fixture.pack_path, pack).await?;

    let error = fixture
        .bucket
        .get(
            &fixture.identity,
            Some(ByteRange {
                start: 0,
                length: 1,
            }),
        )
        .await
        .err()
        .ok_or("corrupt complete member was returned")?;

    assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
    assert_eq!(fixture.fs.whole_reads(), 0);
    fixture.remove().await?;
    Ok(())
}

#[tokio::test]
async fn ranged_chunk_read_rejects_wrong_member_and_detached_index() -> TestResult {
    for corrupt_index in [false, true] {
        let fixture = Fixture::raw(b"exact selected member identity").await?;
        let path = if corrupt_index {
            &fixture.index_path
        } else {
            &fixture.pack_path
        };
        let mut bytes = tokio::fs::read(path).await?;
        let offset = if corrupt_index {
            crate::pack::HEADER_SIZE + 12
        } else {
            fixture.body_offset()? + 1
        };
        bytes[offset] ^= 1;
        tokio::fs::write(path, bytes).await?;

        let error = fixture
            .bucket
            .get(
                &fixture.identity,
                Some(ByteRange {
                    start: 1,
                    length: 4,
                }),
            )
            .await
            .err()
            .ok_or("wrong member or detached index was served")?;

        assert!(
            matches!(error.kind(), StoreErrorKind::Corrupt(_)),
            "corrupt_index={corrupt_index}: {error}"
        );
        assert_eq!(fixture.fs.whole_reads(), 0);
        fixture.remove().await?;
    }

    // Legacy generations can omit inventory hashes. Alter one valid detached
    // record while leaving the pack's actual trailing index and CRC intact.
    for shorten_index in [false, true] {
        let fixture =
            Fixture::raw_with_profile(b"authoritative embedded index", ReadProfile::Legacy).await?;
        let generation = fixture
            .bucket
            .catalog()
            .await?
            .capabilities
            .generation
            .ok_or("legacy fixture generation absent")?;
        let manifest_path = fixture
            .bucket
            .root()
            .join(format!("objects/index/{generation}/MANIFEST"));
        let mut manifest = terrane_format::bucket::GenerationManifest::decode(
            &tokio::fs::read(&manifest_path).await?,
        )?;
        manifest.inventory = None;
        tokio::fs::write(manifest_path, manifest.encode()?).await?;
        let mut detached = tokio::fs::read(&fixture.index_path).await?;
        if shorten_index {
            let preamble = crate::pack::HEADER_SIZE;
            let records = preamble + terrane_format::pack_format::PREAMBLE_SIZE;
            drop(detached.drain(records..records + terrane_format::pack_format::RECORD_SIZE));
            detached[preamble + 4..records].copy_from_slice(&1u64.to_le_bytes());
        } else {
            detached[crate::pack::HEADER_SIZE + 12 + 31] ^= 1;
        }
        PackIndexSnapshot::decode(&detached, generation)?;
        let detached_identity = TERRANE_V1.calculate(IdentityKind::Index, &detached)?;
        tokio::fs::write(&fixture.index_path, detached).await?;

        // The ordinary full-body path uses the actual filesystem separately;
        // the ranged fixture's whole-pack trap remains armed throughout.
        let ordinary = FileBucket::open_legacy_read_only(
            config(fixture.bucket.root().to_owned()),
            TokioLocalFs,
            TokioClock,
            Validator,
        )
        .await?;
        let error = ordinary
            .get(&fixture.identity, None)
            .await
            .err()
            .ok_or("legacy full-body read accepted disagreeing detached index")?;
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Corrupt(CorruptSubject::Identity(detached_identity.clone()))
        );

        let error = fixture
            .bucket
            .get(
                &fixture.identity,
                Some(ByteRange {
                    start: 1,
                    length: 4,
                }),
            )
            .await
            .err()
            .ok_or("altered detached index was served without an inventory hash")?;
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Corrupt(CorruptSubject::Identity(detached_identity))
        );
        assert_eq!(fixture.fs.whole_reads(), 0);
        let body_offset = fixture.body_offset()? as u64;
        assert!(
            !fixture
                .fs
                .ranges()?
                .iter()
                .any(|(path, range)| { path == &fixture.pack_path && range.start == body_offset })
        );
        fixture.remove().await?;
    }

    // Exercise the full-container verifier after both full object hashes pass.
    // A separately supplied inventory row binds the altered index's real hash;
    // it grants no publication authority and cannot make the copies agree.
    let fixture = Fixture::raw(b"full container detached-index disagreement").await?;
    let plain = FileBucket::open(
        config(fixture.bucket.root().to_owned()),
        TokioLocalFs,
        TokioClock,
        Validator,
    )
    .await?;
    let mut inventory = plain
        .catalog()
        .await?
        .inventory
        .ok_or("actual inventory absent")?
        .into_iter()
        .find(|entry| entry.pack_id == *fixture.snapshot.header().id().as_bytes())
        .ok_or("actual pack inventory absent")?;
    let mut detached = tokio::fs::read(&fixture.index_path).await?;
    detached[crate::pack::HEADER_SIZE + 12 + 31] ^= 1;
    PackIndexSnapshot::decode(&detached, 1)?;
    let detached_identity = TERRANE_V1.calculate(IdentityKind::Index, &detached)?;
    inventory.index_hash = detached_identity.terrane_v1_digest()?;
    tokio::fs::write(&fixture.index_path, detached).await?;

    let error = plain
        .verified_container(&inventory)
        .await
        .err()
        .ok_or("full container accepted disagreeing detached index")?;
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Corrupt(CorruptSubject::Identity(detached_identity))
    );
    fixture.remove().await?;
    Ok(())
}

#[tokio::test]
async fn ranged_chunk_read_rejects_invalid_bounds_and_overflow() -> TestResult {
    let fixture = Fixture::raw(b"range bounds").await?;
    let empty = fixture
        .bucket
        .get(
            &fixture.identity,
            Some(ByteRange {
                start: fixture.encoded.len() as u64,
                length: 0,
            }),
        )
        .await?;
    assert!(empty.is_empty());

    for range in [
        ByteRange {
            start: 0,
            length: fixture.encoded.len() as u64 + 1,
        },
        ByteRange {
            start: u64::MAX,
            length: 1,
        },
    ] {
        let error = fixture
            .bucket
            .get(&fixture.identity, Some(range))
            .await
            .err()
            .ok_or("invalid range was served")?;
        assert_eq!(
            error.kind(),
            &StoreErrorKind::Invalid(InvalidReason::Range(range))
        );
    }

    let mut pack = tokio::fs::read(&fixture.pack_path).await?;
    let footer = pack.len() - crate::pack::FOOTER_SIZE;
    pack[footer..footer + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    tokio::fs::write(&fixture.pack_path, pack).await?;
    let error = fixture
        .bucket
        .get(
            &fixture.identity,
            Some(ByteRange {
                start: 0,
                length: 1,
            }),
        )
        .await
        .err()
        .ok_or("overflowing body/index boundary was served")?;
    assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
    assert_eq!(fixture.fs.whole_reads(), 0);
    fixture.remove().await?;

    let short =
        Fixture::raw_with_profile(b"exact ordinary range", ReadProfile::UnsupportedHooks).await?;
    short.fs.short_ordinary_read();
    let result = short
        .bucket
        .get(
            &short.identity,
            Some(ByteRange {
                start: 0,
                length: 1,
            }),
        )
        .await;
    assert!(result.is_err(), "short bounded read was served");
    assert_eq!(short.fs.whole_reads(), 0);
    short.remove().await?;
    Ok(())
}

#[tokio::test]
async fn ranged_chunk_read_rejects_header_trailer_and_body_tampering() -> TestResult {
    for case in [
        "header",
        "reserved",
        "footer-magic",
        "footer-crc",
        "index",
        "member-codec",
        "other-codec",
    ] {
        let fixture = Fixture::raw(b"complete pack framing").await?;
        let pack_identity = fixture
            .bucket
            .catalog()
            .await?
            .inventory
            .ok_or("actual inventory absent")?
            .into_iter()
            .find(|entry| entry.pack_id == *fixture.snapshot.header().id().as_bytes())
            .map(|entry| TERRANE_V1.from_digest(IdentityKind::Pack, &entry.pack_hash))
            .ok_or("actual pack inventory absent")??;
        let mut pack = tokio::fs::read(&fixture.pack_path).await?;
        let offset = match case {
            "header" => 0,
            "reserved" => 6,
            "footer-magic" => pack.len() - 1,
            "footer-crc" => pack.len() - 8,
            "index" => pack.len() - crate::pack::FOOTER_SIZE - 1,
            "member-codec" => fixture.body_offset()?,
            "other-codec" => usize::try_from(
                fixture
                    .snapshot
                    .entries()
                    .iter()
                    .find(|entry| entry.hash() != fixture.identity.digest())
                    .ok_or("missing unrelated real member")?
                    .offset(),
            )?,
            _ => return Err("unknown framing fixture".into()),
        };
        pack[offset] ^= if case == "reserved" { 4 } else { 1 };
        tokio::fs::write(&fixture.pack_path, pack).await?;

        let error = fixture
            .bucket
            .get(
                &fixture.identity,
                Some(ByteRange {
                    start: 1,
                    length: 3,
                }),
            )
            .await
            .err()
            .ok_or("tampered framing was served")?;

        assert!(
            matches!(error.kind(), StoreErrorKind::Corrupt(_)),
            "{case}: {error}"
        );
        if matches!(case, "footer-crc" | "index") {
            assert_eq!(
                error.kind(),
                &StoreErrorKind::Corrupt(CorruptSubject::Identity(pack_identity))
            );
            let body_offset = fixture.body_offset()? as u64;
            assert!(
                !fixture.fs.ranges()?.iter().any(|(path, range)| {
                    path == &fixture.pack_path && range.start == body_offset
                })
            );
        }
        assert_eq!(fixture.fs.whole_reads(), 0, "{case}");
        fixture.remove().await?;
    }

    let refused = Fixture::raw(b"native support remains sticky").await?;
    refused.fs.fail_native_read();
    let error = refused
        .bucket
        .get(
            &refused.identity,
            Some(ByteRange {
                start: 0,
                length: 1,
            }),
        )
        .await
        .err()
        .ok_or("failed supported native range was retried")?;
    assert_eq!(error.kind(), &StoreErrorKind::Unsupported);
    assert_eq!(refused.fs.ordinary_range_reads(), 0);
    assert_eq!(refused.fs.whole_reads(), 0);
    refused.remove().await?;
    Ok(())
}

#[tokio::test]
async fn ranged_chunk_read_retains_verified_dictionary_dependencies() -> TestResult {
    for profile in [
        ReadProfile::Native,
        ReadProfile::UnsupportedHooks,
        ReadProfile::ReadOnly,
        ReadProfile::Legacy,
    ] {
        let trace =
            crate::ref_advance::NativeTrace::new(&std::env::temp_dir(), "ranged-dictionary-case");
        trace.mark(&format!("profile-{profile:?}-fixture-start"));
        let fixture = Fixture::dictionary(profile).await?;
        trace.mark("fixture-returned");
        let dictionary = match terrane_format::codec::parse_envelope(&fixture.encoded)?.codec {
            terrane_format::codec::Codec::ZstdDictionary(hash) => hash,
            _ => return Err("actual dictionary fixture was lost".into()),
        };
        trace.mark("dictionary-location-start");
        let dictionary_location = fixture
            .bucket
            .catalog()
            .await?
            .shards
            .into_iter()
            .flat_map(|shard| shard.entries().to_vec())
            .find(|entry| entry.entry().hash() == &dictionary)
            .ok_or("actual dictionary placement absent")?;
        let dictionary_path = fixture
            .bucket
            .root()
            .join(dictionary_location.pack().pack_key());

        trace.mark("verified-range-read-start");
        let actual = fixture
            .bucket
            .get(
                &fixture.identity,
                Some(ByteRange {
                    start: 1,
                    length: 5,
                }),
            )
            .await?;

        trace.mark("verified-range-read-returned");
        assert_eq!(actual, fixture.encoded[1..6]);
        assert!(
            fixture
                .fs
                .ranges()?
                .iter()
                .any(|(path, _)| path == &dictionary_path)
        );
        assert_eq!(fixture.fs.whole_reads(), 0);

        let mut pack = tokio::fs::read(&dictionary_path).await?;
        let last = usize::try_from(dictionary_location.entry().offset())?
            + dictionary_location.entry().body_len() as usize
            - 1;
        pack[last] ^= 1;
        tokio::fs::write(&dictionary_path, pack).await?;
        trace.mark("corrupt-dictionary-read-start");
        let error = fixture
            .bucket
            .get(
                &fixture.identity,
                Some(ByteRange {
                    start: 1,
                    length: 5,
                }),
            )
            .await
            .err()
            .ok_or("corrupt dictionary dependency was served")?;
        trace.mark("corrupt-dictionary-read-returned");
        assert!(matches!(error.kind(), StoreErrorKind::Corrupt(_)));
        assert_eq!(fixture.fs.whole_reads(), 0);
        fixture.remove().await?;
    }
    Ok(())
}

#[tokio::test]
async fn ranged_chunk_read_rejects_original_leaf_and_ancestor_reincarnation() -> TestResult {
    for (profile, directory) in [
        (ReadProfile::Native, false),
        (ReadProfile::Native, true),
        (ReadProfile::UnsupportedHooks, false),
        (ReadProfile::UnsupportedHooks, true),
    ] {
        let fixture =
            Fixture::raw_with_profile(b"same bytes on another physical inode", profile).await?;
        let path = if directory {
            fixture
                .pack_path
                .parent()
                .ok_or("missing actual pack parent")?
                .to_owned()
        } else {
            fixture.pack_path.clone()
        };
        fixture.fs.replace_before_range(path, directory)?;

        let result = fixture
            .bucket
            .get(
                &fixture.identity,
                Some(ByteRange {
                    start: 1,
                    length: 5,
                }),
            )
            .await;

        assert!(
            result.is_err(),
            "directory={directory}: replacement was served"
        );
        assert!(!fixture.fs.ranges()?.is_empty());
        assert_eq!(fixture.fs.whole_reads(), 0);
        fixture.remove().await?;
    }
    Ok(())
}
