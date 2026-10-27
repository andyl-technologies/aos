//! Checks final confirmation against actual published packs and ordinary reads.
//!
//! Fault projections alter only private test catalogs or real artifact files;
//! they neither publish manufactured history nor create effect/read receipts.

use super::verification::Confirmation;
use crate::bucket::catalog::{Catalog, CatalogReads};
use crate::bucket::containers::{admitted_artifacts, inventory_entry};
use crate::bucket::content_observation::ContentObservation;
use crate::bucket::held::SingleHeld;
use crate::bucket::publication::receipts::RecordRead;
use crate::bucket::{FileBucket, tests::config};
use crate::pack::{EntryKind, MergedShard, PackClass, PackId, PackIndexSnapshot, PackWriter};
use crate::repository::MetadataValidator;
use crate::store::{
    ContentValidator, CorruptSubject, LocalFs, StoreErrorKind, StoreFailure, TokioClock,
    TokioLocalFs,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use terrane_format::bucket::{BucketKey, PackInventoryEntry};
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_format::tree_builder::Tree;
use terrane_format::tree_format::{Property, TreeUse};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Bucket = FileBucket<TokioLocalFs, TokioClock, MetadataValidator>;

struct Fixture {
    bucket: Bucket,
    members: Vec<(Identity, Vec<u8>)>,
    packs: Vec<PackId>,
    validation: Arc<ContentObservation>,
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        let entropy = TokioLocalFs.random_bytes(16).await?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = std::env::temp_dir().join(format!("terrane-confirmation-{suffix}"));
        let config = config(root);
        let validator = MetadataValidator::new(config.chunk_profile.clone());
        let validation = Arc::new(ContentObservation::default());
        validator.observe_for_tests(Arc::clone(&validation))?;
        let bucket = FileBucket::open(config, TokioLocalFs, TokioClock, validator).await?;
        let members = [1, 2, 4, 8]
            .into_iter()
            .map(node)
            .collect::<TestResult<Vec<_>>>()?;
        let packs = vec![
            publish(&bucket, &members[..3], PackClass::Meta).await?,
            publish(&bucket, &members[3..], PackClass::Meta).await?,
        ];
        Ok(Self {
            bucket,
            members,
            packs,
            validation,
        })
    }

    async fn cleanup(self) -> TestResult {
        tokio::fs::remove_dir_all(self.bucket.root()).await?;
        let control = crate::bucket::tests::control_path(self.bucket.root());
        tokio::fs::remove_dir_all(control).await?;
        Ok(())
    }
}

fn node(verbs: u8) -> TestResult<(Identity, Vec<u8>)> {
    let acl = [0x81, 0x82, 0x66, b'w', b'r', b'i', b't', b'e', b'r', verbs];
    let tree = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: &acl,
            },
            Property {
                name: "domain",
                value: b"\x66public",
            },
        ]),
        262144,
        TreeUse::Ordinary,
    )?;
    let bytes = tree
        .nodes()
        .next()
        .ok_or("missing canonical root")?
        .encoded()
        .to_vec();
    Ok((TERRANE_V1.calculate(IdentityKind::Node, &bytes)?, bytes))
}

async fn publish(
    bucket: &Bucket,
    members: &[(Identity, Vec<u8>)],
    class: PackClass,
) -> TestResult<PackId> {
    let holder = SingleHeld::acquire(bucket).await?;
    let held = holder.destination();
    let observed = held.observe_publication().await?;
    let catalog = bucket.catalog().await?;
    let generation = bucket.next_generation(&catalog).await?;
    let id = PackId::generate(&bucket.inner.fs).await?;
    let mut writer = PackWriter::new(id, class, false);
    for (identity, bytes) in members {
        let kind = if class == PackClass::Meta {
            EntryKind::Node
        } else {
            EntryKind::Chunk
        };
        let hash = writer.append_raw(kind, bytes)?;
        assert_eq!(hash.as_slice(), identity.digest());
        if class == PackClass::Meta {
            bucket
                .inner
                .validator
                .validate_meta(&crate::store::MetaUpload::new(IdentityKind::Node, bytes)?)?;
        }
    }
    let sealed = writer.seal()?;
    let artifacts = admitted_artifacts(id, sealed.bytes(), sealed.index_object())?;
    crate::store::native_publication_effects::stage_container(held.fs(), &observed, &artifacts)
        .await?;
    bucket.verified_container(artifacts.inventory()).await?;
    let index = PackIndexSnapshot::decode(sealed.index_object(), generation)?;
    bucket
        .publish_pack_catalog(
            &held,
            &observed,
            catalog,
            index,
            artifacts.inventory().clone(),
        )
        .await?;
    Ok(id)
}

/// Counts real forwarded artifact reads; optionally injects a failed read result.
/// The injected availability failure replaces an actual completed physical read,
/// never supplies bytes or a fabricated receipt, and checks read-before-parse order.
struct Reads<'bucket> {
    bucket: &'bucket Bucket,
    calls: AtomicUsize,
    fail_suffix: Option<&'static str>,
}

impl<'bucket> Reads<'bucket> {
    fn new(bucket: &'bucket Bucket) -> Self {
        Self {
            bucket,
            calls: AtomicUsize::new(0),
            fail_suffix: None,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl CatalogReads for Reads<'_> {
    async fn read_artifact(&self, key: &BucketKey) -> Result<RecordRead, StoreFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let read = self.bucket.read_artifact(key).await?;
        if self
            .fail_suffix
            .is_some_and(|suffix| key.as_str().ends_with(suffix))
        {
            return Err(StoreFailure::with_source(
                StoreErrorKind::Unavailable { retry_after: None },
                std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "injected artifact read failure",
                ),
            ));
        }
        Ok(read)
    }
}

fn copy_catalog(catalog: &Catalog) -> Catalog {
    Catalog {
        capabilities: catalog.capabilities.clone(),
        capability_bytes: catalog.capability_bytes.clone(),
        shards: catalog.shards.clone(),
        inventory: catalog.inventory.clone(),
        exclusions: catalog.exclusions.clone(),
        burns: catalog.burns.clone(),
    }
}

fn inventory_mut(catalog: &mut Catalog, pack: PackId) -> TestResult<&mut PackInventoryEntry> {
    catalog
        .inventory
        .as_mut()
        .ok_or("missing inventory")?
        .iter_mut()
        .find(|entry| entry.pack_id == *pack.as_bytes())
        .ok_or_else(|| "missing pack inventory".into())
}

fn change_member(
    catalog: &mut Catalog,
    identity: &Identity,
    change: impl FnOnce(&mut terrane_format::pack_format::MergedRecord),
) -> TestResult {
    let hash = identity.terrane_v1_digest()?;
    let shard = catalog
        .shards
        .iter_mut()
        .find(|shard| shard.shard() == hash[0])
        .ok_or("missing shard")?;
    let mut records = terrane_format::pack_format::decode_shard(&shard.encode(), shard.shard())?;
    let record = records
        .iter_mut()
        .find(|record| record.record.hash == hash)
        .ok_or("missing member")?;
    change(record);
    *shard = MergedShard::decode(
        &terrane_format::pack_format::encode_shard(&records),
        shard.generation(),
        shard.shard(),
    )?;
    Ok(())
}

fn corrupt_kind(identity: &Identity) -> StoreErrorKind {
    StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone()))
}

/// Compares exact typed refusal with both ordinary and disabled-reuse paths.
async fn refuses(
    bucket: &Bucket,
    catalog: &Catalog,
    confirmation: &mut Confirmation<'_>,
    identity: &Identity,
    offered: &[u8],
    expected: &StoreErrorKind,
) -> TestResult {
    let reads = Reads::new(bucket);
    let result = confirmation
        .confirm_member(bucket, catalog, identity, offered, &reads)
        .await;
    assert_eq!(
        result.err().ok_or("confirmation accepted fault")?.kind(),
        expected
    );
    let mut disabled = Confirmation::without_reuse(catalog);
    assert_eq!(
        disabled
            .confirm_member(bucket, catalog, identity, offered, &Reads::new(bucket))
            .await
            .err()
            .ok_or("disabled confirmation accepted fault")?
            .kind(),
        expected
    );
    assert_eq!(
        bucket
            .verified_body(catalog, identity)
            .await
            .err()
            .ok_or("ordinary body accepted fault")?
            .kind(),
        expected
    );
    Ok(())
}

async fn refuses_read_failure(
    bucket: &Bucket,
    catalog: &Catalog,
    confirmation: &mut Confirmation<'_>,
    identity: &Identity,
    offered: &[u8],
    suffix: &'static str,
    attempts: usize,
) -> TestResult {
    let make_reads = || {
        let mut reads = Reads::new(bucket);
        reads.fail_suffix = Some(suffix);
        reads
    };
    let expected = StoreErrorKind::Unavailable { retry_after: None };
    let reads = make_reads();
    assert_eq!(
        confirmation
            .confirm_member(bucket, catalog, identity, offered, &reads)
            .await
            .err()
            .ok_or("failed read accepted")?
            .kind(),
        &expected
    );
    assert_eq!(reads.calls(), attempts);

    let reads = make_reads();
    assert_eq!(
        Confirmation::without_reuse(catalog)
            .confirm_member(bucket, catalog, identity, offered, &reads)
            .await
            .err()
            .ok_or("disabled confirmation accepted failed read")?
            .kind(),
        &expected
    );
    assert_eq!(reads.calls(), attempts);

    let reads = make_reads();
    assert_eq!(
        bucket
            .verified_body_with_reads(catalog, identity, &reads)
            .await
            .err()
            .ok_or("ordinary verification accepted failed read")?
            .kind(),
        &expected
    );
    assert_eq!(reads.calls(), attempts);
    Ok(())
}

#[tokio::test]
async fn metadata_confirmation_reuses_only_identical_pack_parsing() -> TestResult {
    let fixture = Fixture::new().await?;
    let catalog = fixture.bucket.catalog().await?;
    let mut enabled = Confirmation::new(&catalog);
    let mut disabled = Confirmation::without_reuse(&catalog);
    let enabled_reads = Reads::new(&fixture.bucket);
    let disabled_reads = Reads::new(&fixture.bucket);
    let before = fixture.validation.snapshot().node_decodes;

    // Include a genuine duplicate offer. All three paths validate every body.
    for member in [0, 1, 2, 0] {
        let (identity, bytes) = &fixture.members[member];
        enabled
            .confirm_member(&fixture.bucket, &catalog, identity, bytes, &enabled_reads)
            .await?;
        disabled
            .confirm_member(&fixture.bucket, &catalog, identity, bytes, &disabled_reads)
            .await?;
        assert_eq!(
            fixture.bucket.verified_body(&catalog, identity).await?,
            *bytes
        );
    }
    assert_eq!(enabled.parses(), 1);
    // Disabled confirmation extracts once per member. The unchanged ordinary
    // control above has its original two opens; this counter does not count it.
    assert_eq!(disabled.parses(), 4);
    assert_eq!(enabled_reads.calls(), 8);
    assert_eq!(disabled_reads.calls(), 8);
    assert_eq!(fixture.validation.snapshot().node_decodes - before, 12);
    fixture.cleanup().await
}

#[tokio::test]
async fn metadata_confirmation_rechecks_each_member_and_physical_read() -> TestResult {
    let fixture = Fixture::new().await?;
    let catalog = fixture.bucket.catalog().await?;
    let (first, first_bytes) = &fixture.members[0];
    let (second, second_bytes) = &fixture.members[1];
    let pack = fixture.packs[0];
    let pack_path = fixture.bucket.root().join(pack.pack_key());
    let index_path = fixture.bucket.root().join(pack.index_key());
    let pack_bytes = tokio::fs::read(&pack_path).await?;
    let index_bytes = tokio::fs::read(&index_path).await?;
    let inventory = catalog
        .inventory
        .as_ref()
        .ok_or("missing inventory")?
        .iter()
        .find(|entry| entry.pack_id == *pack.as_bytes())
        .ok_or("missing pack")?;
    let pack_identity = TERRANE_V1.from_digest(IdentityKind::Pack, &inventory.pack_hash)?;
    let index_identity = TERRANE_V1.from_digest(IdentityKind::Index, &inventory.index_hash)?;
    let mut confirmation = Confirmation::new(&catalog);
    confirmation
        .confirm_member(
            &fixture.bucket,
            &catalog,
            first,
            first_bytes,
            &Reads::new(&fixture.bucket),
        )
        .await?;

    // A hit still checks the exact offer and clears the slot on mismatch.
    let before = fixture.validation.snapshot().node_decodes;
    assert_eq!(
        confirmation
            .confirm_member(
                &fixture.bucket,
                &catalog,
                first,
                second_bytes,
                &Reads::new(&fixture.bucket)
            )
            .await
            .err()
            .ok_or("different offer accepted")?
            .kind(),
        &corrupt_kind(first)
    );
    assert_eq!(
        fixture.bucket.verified_body(&catalog, first).await?,
        *first_bytes
    );
    assert_eq!(fixture.validation.snapshot().node_decodes - before, 2);
    confirmation
        .confirm_member(
            &fixture.bucket,
            &catalog,
            first,
            first_bytes,
            &Reads::new(&fixture.bucket),
        )
        .await?;
    assert_eq!(confirmation.parses(), 2);

    for (path, original, expected) in [
        (&pack_path, &pack_bytes, &pack_identity),
        (&index_path, &index_bytes, &index_identity),
    ] {
        let mut changed = original.clone();
        changed[0] ^= 1;
        tokio::fs::write(path, &changed).await?;
        refuses(
            &fixture.bucket,
            &catalog,
            &mut confirmation,
            first,
            first_bytes,
            &corrupt_kind(expected),
        )
        .await?;
        tokio::fs::write(path, original).await?;
        confirmation
            .confirm_member(
                &fixture.bucket,
                &catalog,
                first,
                first_bytes,
                &Reads::new(&fixture.bucket),
            )
            .await?;

        // Missing either member of the pair retains the pack subject.
        tokio::fs::remove_file(path).await?;
        refuses(
            &fixture.bucket,
            &catalog,
            &mut confirmation,
            first,
            first_bytes,
            &corrupt_kind(&pack_identity),
        )
        .await?;
        tokio::fs::write(path, original).await?;
        confirmation
            .confirm_member(
                &fixture.bucket,
                &catalog,
                first,
                first_bytes,
                &Reads::new(&fixture.bucket),
            )
            .await?;
    }

    // Index I/O failure wins over a pack hash failure: both reads precede hashing.
    let mut changed = pack_bytes.clone();
    changed[0] ^= 1;
    tokio::fs::write(&pack_path, &changed).await?;
    refuses_read_failure(
        &fixture.bucket,
        &catalog,
        &mut confirmation,
        first,
        first_bytes,
        ".idx",
        2,
    )
    .await?;
    tokio::fs::write(&pack_path, &pack_bytes).await?;
    refuses_read_failure(
        &fixture.bucket,
        &catalog,
        &mut confirmation,
        first,
        first_bytes,
        ".pack",
        1,
    )
    .await?;

    // Rehashed format faults reach the actual parser, not merely identity checks.
    for byte in [0, 4, 8, pack_bytes.len() - 1] {
        let mut damaged = pack_bytes.clone();
        damaged[byte] ^= 1;
        tokio::fs::write(&pack_path, &damaged).await?;
        let mut projected = copy_catalog(&catalog);
        *inventory_mut(&mut projected, pack)? = inventory_entry(pack, &damaged, &index_bytes)?;
        let expected = TERRANE_V1.calculate(IdentityKind::Pack, &damaged)?;
        let mut projected_confirmation = Confirmation::new(&projected);
        refuses(
            &fixture.bucket,
            &projected,
            &mut projected_confirmation,
            first,
            first_bytes,
            &corrupt_kind(&expected),
        )
        .await?;
        assert_eq!(projected_confirmation.parses(), 1);
        refuses(
            &fixture.bucket,
            &projected,
            &mut projected_confirmation,
            first,
            first_bytes,
            &corrupt_kind(&expected),
        )
        .await?;
        assert_eq!(projected_confirmation.parses(), 2);
        tokio::fs::write(&pack_path, &pack_bytes).await?;
    }

    // A detached index with a valid declared hash still disagrees with the pack.
    let mut detached = index_bytes.clone();
    detached[32] ^= 1;
    tokio::fs::write(&index_path, &detached).await?;
    let mut projected = copy_catalog(&catalog);
    *inventory_mut(&mut projected, pack)? = inventory_entry(pack, &pack_bytes, &detached)?;
    let expected = TERRANE_V1.calculate(IdentityKind::Index, &detached)?;
    refuses(
        &fixture.bucket,
        &projected,
        &mut Confirmation::new(&projected),
        first,
        first_bytes,
        &corrupt_kind(&expected),
    )
    .await?;
    tokio::fs::write(&index_path, &index_bytes).await?;

    // Valid first member warms the parsed pair; an unvalidated corrupt bystander
    // must still fail the real schema decoder on the subsequent cache hit.
    let location = fixture.bucket.location(&catalog, second)?;
    let mut malformed = pack_bytes.clone();
    malformed[usize::try_from(location.entry().offset())?] = 0;
    tokio::fs::write(&pack_path, &malformed).await?;
    let mut projected = copy_catalog(&catalog);
    *inventory_mut(&mut projected, pack)? = inventory_entry(pack, &malformed, &index_bytes)?;
    let mut hit = Confirmation::new(&projected);
    hit.confirm_member(
        &fixture.bucket,
        &projected,
        first,
        first_bytes,
        &Reads::new(&fixture.bucket),
    )
    .await?;
    refuses(
        &fixture.bucket,
        &projected,
        &mut hit,
        second,
        second_bytes,
        &corrupt_kind(second),
    )
    .await?;
    assert_eq!(hit.parses(), 1);
    hit.confirm_member(
        &fixture.bucket,
        &projected,
        first,
        first_bytes,
        &Reads::new(&fixture.bucket),
    )
    .await?;
    assert_eq!(hit.parses(), 2);
    tokio::fs::write(&pack_path, &pack_bytes).await?;

    // A schema-valid bystander with another member's bytes still fails its own
    // identity check after a hit. The complete container hash proves no body's
    // declared member identity without its independent per-member validation.
    let start = usize::try_from(location.entry().offset())?;
    let end = start + usize::try_from(location.entry().body_len())?;
    assert_eq!(end - start, first_bytes.len());
    let mut wrong_body = pack_bytes.clone();
    wrong_body[start..end].copy_from_slice(first_bytes);
    tokio::fs::write(&pack_path, &wrong_body).await?;
    let mut projected = copy_catalog(&catalog);
    *inventory_mut(&mut projected, pack)? = inventory_entry(pack, &wrong_body, &index_bytes)?;
    let mut hit = Confirmation::new(&projected);
    hit.confirm_member(
        &fixture.bucket,
        &projected,
        first,
        first_bytes,
        &Reads::new(&fixture.bucket),
    )
    .await?;
    let before = fixture.validation.snapshot().node_decodes;
    refuses(
        &fixture.bucket,
        &projected,
        &mut hit,
        second,
        second_bytes,
        &corrupt_kind(second),
    )
    .await?;
    assert_eq!(fixture.validation.snapshot().node_decodes - before, 3);
    assert_eq!(hit.parses(), 1);
    hit.confirm_member(
        &fixture.bucket,
        &projected,
        first,
        first_bytes,
        &Reads::new(&fixture.bucket),
    )
    .await?;
    assert_eq!(hit.parses(), 2);
    tokio::fs::write(&pack_path, &pack_bytes).await?;

    // A real immutable catalog's selected member row is compared on every call.
    for change in 0..6 {
        let mut projected = copy_catalog(&catalog);
        change_member(&mut projected, second, |record| match change {
            0 => record.record.offset += 1,
            1 => {
                record.record.body_len -= 1;
                record.record.plaintext_len -= 1;
            }
            2 => {
                record.record.body_len += 1;
                record.record.plaintext_len += 1;
            }
            3 => record.record.kind = EntryKind::Commit as u8,
            4 => record.state = 2,
            _ => record.state = 1,
        })?;
        let requested = if change == 3 {
            TERRANE_V1.from_digest(IdentityKind::Commit, second.digest())?
        } else {
            second.clone()
        };
        let expected = if change >= 4 {
            StoreErrorKind::Absent(requested.clone())
        } else {
            corrupt_kind(&requested)
        };
        refuses(
            &fixture.bucket,
            &projected,
            &mut Confirmation::new(&projected),
            &requested,
            second_bytes,
            &expected,
        )
        .await?;
    }
    fixture.cleanup().await
}

#[tokio::test]
async fn metadata_confirmation_reuse_never_crosses_batches_or_catalog_geometry() -> TestResult {
    let fixture = Fixture::new().await?;
    let catalog = fixture.bucket.catalog().await?;
    let (first, bytes) = &fixture.members[0];
    let (other, other_bytes) = &fixture.members[3];
    let reads = Reads::new(&fixture.bucket);
    let mut confirmation = Confirmation::new(&catalog);
    for (identity, offered) in [(first, bytes), (other, other_bytes), (first, bytes)] {
        confirmation
            .confirm_member(&fixture.bucket, &catalog, identity, offered, &reads)
            .await?;
    }
    assert_eq!(confirmation.parses(), 3);
    assert_eq!(reads.calls(), 6);
    let mut next_batch = Confirmation::new(&catalog);
    next_batch
        .confirm_member(&fixture.bucket, &catalog, first, bytes, &reads)
        .await?;
    assert_eq!(next_batch.parses(), 1);

    // Equal bytes and identities in another catalog do not retain a prior slot.
    let mut changed = copy_catalog(&catalog);
    changed.capabilities.generation = catalog.capabilities.generation.map(|value| value + 1);
    confirmation
        .confirm_member(&fixture.bucket, &changed, first, bytes, &reads)
        .await?;
    confirmation
        .confirm_member(&fixture.bucket, &catalog, first, bytes, &reads)
        .await?;
    assert_eq!(confirmation.parses(), 5);

    for field in 0..4 {
        let mut changed = copy_catalog(&catalog);
        let inventory = inventory_mut(&mut changed, fixture.packs[0])?;
        let expected = if field == 3 {
            inventory.index_hash[0] ^= 1;
            TERRANE_V1.from_digest(IdentityKind::Index, &inventory.index_hash)?
        } else {
            match field {
                0 => inventory.pack_size += 1,
                1 => inventory.index_size += 1,
                _ => inventory.pack_hash[0] ^= 1,
            }
            TERRANE_V1.from_digest(IdentityKind::Pack, &inventory.pack_hash)?
        };
        refuses(
            &fixture.bucket,
            &changed,
            &mut confirmation,
            first,
            bytes,
            &corrupt_kind(&expected),
        )
        .await?;
    }

    // A cached pair cannot serve a selected row whose member is absent inside it.
    let mut wrong = copy_catalog(&catalog);
    change_member(&mut wrong, other, |record| {
        record.pack = *fixture.packs[0].as_bytes()
    })?;
    let mut missing = Confirmation::new(&wrong);
    missing
        .confirm_member(&fixture.bucket, &wrong, first, bytes, &reads)
        .await?;
    refuses(
        &fixture.bucket,
        &wrong,
        &mut missing,
        other,
        other_bytes,
        &corrupt_kind(other),
    )
    .await?;
    assert_eq!(missing.parses(), 1);
    missing
        .confirm_member(&fixture.bucket, &wrong, first, bytes, &reads)
        .await?;
    assert_eq!(missing.parses(), 2);

    // Omitted optional inventory retains the complete legacy verification path.
    let mut legacy = copy_catalog(&catalog);
    legacy.inventory = None;
    let mut fallback = Confirmation::new(&legacy);
    fallback
        .confirm_member(&fixture.bucket, &legacy, first, bytes, &reads)
        .await?;
    assert_eq!(fallback.parses(), 0);
    assert_eq!(fixture.bucket.verified_body(&legacy, first).await?, *bytes);

    let mut retired = copy_catalog(&catalog);
    retired.burns = Some(vec![*fixture.packs[0].as_bytes()]);
    refuses(
        &fixture.bucket,
        &retired,
        &mut confirmation,
        first,
        bytes,
        &StoreErrorKind::Absent(first.clone()),
    )
    .await?;

    // Actual durable identity quarantine is independently selected again; the
    // prior preparation cannot override the new catalog's refusal.
    fixture.bucket.exclude(other).await?;
    let quarantined = fixture.bucket.catalog().await?;
    refuses(
        &fixture.bucket,
        &quarantined,
        &mut confirmation,
        other,
        other_bytes,
        &StoreErrorKind::Absent(other.clone()),
    )
    .await?;

    let plaintext = b"final data member".to_vec();
    let chunk = TERRANE_V1.calculate(IdentityKind::Chunk, &plaintext)?;
    publish(
        &fixture.bucket,
        &[(chunk.clone(), plaintext.clone())],
        PackClass::Data,
    )
    .await?;
    let data_catalog = fixture.bucket.catalog().await?;
    let mut data = Confirmation::new(&data_catalog);
    let data_reads = Reads::new(&fixture.bucket);
    let mut encoded = vec![0];
    encoded.extend_from_slice(&plaintext);
    data.confirm_member(
        &fixture.bucket,
        &data_catalog,
        &chunk,
        &encoded,
        &data_reads,
    )
    .await?;
    assert_eq!(data.parses(), 0);
    assert_eq!(data_reads.calls(), 2);
    assert_eq!(
        fixture.bucket.verified_body(&data_catalog, &chunk).await?,
        encoded
    );

    fixture.cleanup().await
}
