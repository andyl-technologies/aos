//! Verifies every metadata body before publishing a complete pack/index pair.

use super::{
    super::retention::Custody,
    Input,
    backing::{self, AdmissionJob},
    io as native, reconcile, state,
};
use std::{
    collections::BTreeMap,
    io,
    sync::{Arc, Mutex},
};
use terrane_sdk::{
    host::cache::reconstruct_pack_index,
    pack::{PackClass, PackReader},
    repository::MetadataValidator,
};

/// Verifies and synchronizes an exact metadata pack and detached index pair.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) async fn run(
    executor: &super::super::retention::NativeOwnerExecutor,
    custody: &Arc<Mutex<Custody>>,
    resource: &Arc<Mutex<AdmissionJob>>,
) -> io::Result<(u64, u64)> {
    let (expected_id, pack, index, reservation) = {
        let mut job = backing::lock(resource)?;
        let (expected_id, pack, index) = match &job.input {
            Input::Metadata {
                expected_id,
                pack,
                index,
            } => (*expected_id, Arc::clone(pack), Arc::clone(index)),
            _ => return Err(io::Error::other("metadata admission received chunk input")),
        };
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("admission custody poisoned"))?;
        owner.check_current()?;
        let config = &owner.preparation.config;
        super::AdmissionBounds::new(config)?.check(pack.len(), index.len())?;
        super::AdmissionBounds::new(config)?.check(pack.capacity(), index.capacity())?;
        let hashes = verify(
            &pack,
            &index,
            expected_id,
            config.location.chunk_profile(),
            config.reads,
            config.inventory_entries.min(config.state.records),
        )?;
        let payload = pack
            .len()
            .checked_add(index.len())
            .ok_or_else(|| io::Error::other("metadata payload overlap overflow"))?;
        let prepared = state::begin(executor, &mut owner, &mut job, payload, &hashes)?;
        (expected_id, pack, index, prepared)
    };
    super::super::snapshot::persist(executor, reservation).await?;
    let completion = {
        let mut job = backing::lock(resource)?;
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("admission custody poisoned"))?;
        owner.check_current()?;
        state::check_registration(&owner, &job)?;
        let shard = format!("{:02x}", expected_id.as_bytes()[0]);
        let parent = native::parent(
            &owner,
            "objects",
            &["pack", &shard],
            &mut job.directory_progress,
        )?;
        let index_name = format!("{expected_id}.idx");
        let pack_name = format!("{expected_id}.pack");
        native::refuse_existing(&parent, &index_name)?;
        native::refuse_existing(&parent, &pack_name)?;
        let index_member = native::pending(parent.try_clone()?, index_name)?;
        let pack_member = native::pending(parent, pack_name)?;
        job.files.push(index_member);
        job.files.push(pack_member);
        native::write(&owner, &mut job.files[0], &index)?;
        native::write(&owner, &mut job.files[1], &pack)?;
        // Readers discover packs, so publish its verified index first. No receipt is
        // issued until both no-replace names and their parent are actually durable.
        native::publish(&owner, &mut job.files[0], &index)?;
        native::publish(&owner, &mut job.files[1], &pack)?;
        super::super::snapshot::prepare(executor, &mut owner)?
    };
    super::super::snapshot::persist(executor, completion).await?;
    let mut job = backing::lock(resource)?;
    let mut owner = custody
        .lock()
        .map_err(|_| io::Error::other("admission custody poisoned"))?;
    reconcile::finish(&mut owner, &mut job)
}

/// Verifies bounded real bytes without minting filesystem or retention authority.
fn verify(
    pack: &[u8],
    index: &[u8],
    expected_id: terrane_sdk::pack::PackId,
    profile: &terrane_format::chunking::ChunkProfile,
    limits: terrane_sdk::host::cache::HostReadLimits,
    max_entries: usize,
) -> io::Result<Vec<String>> {
    let verified = reconstruct_pack_index(
        pack,
        expected_id,
        profile,
        &MetadataValidator::new(profile.clone()),
        &BTreeMap::new(),
        limits,
    )
    .map_err(io::Error::other)?;
    if verified.bytes() != index {
        return Err(io::Error::other(
            "detached metadata index differs from verified pack",
        ));
    }
    let reader = PackReader::open(pack).map_err(io::Error::other)?;
    if reader.header().class() != PackClass::Meta || reader.header().id() != expected_id {
        return Err(io::Error::other(
            "metadata admission requires the exact metadata-class pack",
        ));
    }
    if reader.entries().len() > max_entries {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "metadata pin closure exceeds configured record bound",
        ));
    }
    let mut hashes = Vec::new();
    hashes
        .try_reserve(
            reader
                .entries()
                .len()
                .checked_add(1)
                .ok_or_else(|| io::Error::other("metadata identity count overflow"))?,
        )
        .map_err(io::Error::other)?;
    hashes.push(state::hex(verified.pack_identity().digest()));
    for entry in reader.entries() {
        hashes.push(state::hex(entry.hash()));
    }
    Ok(hashes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use terrane_format::chunking::ChunkProfile;
    use terrane_sdk::host::cache::HostReadLimits;
    use terrane_sdk::pack::{PackId, PackWriter};

    #[test]
    fn actual_metadata_pair_rejects_wrong_index_key_class_and_window() {
        let profile = ChunkProfile::cdc_1m([0; 32]);
        let id = PackId::from_random_bytes([29; 16]);
        let plaintext = vec![61; profile.minimum() + 1];
        let chunks = plaintext
            .chunks(profile.minimum())
            .map(|bytes| terrane_format::manifest::ChunkRef {
                digest: terrane_format::identity::TERRANE_V1
                    .calculate(terrane_format::identity::IdentityKind::Chunk, bytes)
                    .unwrap()
                    .terrane_v1_digest()
                    .unwrap(),
                length: bytes.len() as u64,
            })
            .collect();
        let manifest = terrane_format::manifest::Manifest {
            size: plaintext.len() as u64,
            chunks,
            hashes: BTreeMap::from([(
                "blake3".into(),
                blake3::hash(&plaintext).as_bytes().to_vec(),
            )]),
            media_type: None,
        }
        .encode(&profile)
        .unwrap();
        let mut writer = PackWriter::new(id, PackClass::Meta, false);
        writer
            .append_raw(terrane_sdk::pack::EntryKind::Manifest, &manifest)
            .unwrap();
        let pack = writer.seal().unwrap();
        let limits = HostReadLimits {
            max_allocation_bytes: 4096,
        };

        let identities =
            verify(pack.bytes(), pack.index_object(), id, &profile, limits, 4).unwrap();
        assert_eq!(identities.len(), 2);
        let mut damaged = pack.bytes().to_vec();
        let body = PackReader::open(pack.bytes()).unwrap().entries()[0].offset() as usize;
        damaged[body] ^= 1;
        assert!(verify(&damaged, pack.index_object(), id, &profile, limits, 4).is_err());

        let mut index = pack.index_object().to_vec();
        index[0] ^= 1;
        assert!(verify(pack.bytes(), &index, id, &profile, limits, 4).is_err());
        assert!(
            verify(
                pack.bytes(),
                pack.index_object(),
                PackId::from_random_bytes([30; 16]),
                &profile,
                limits,
                4
            )
            .is_err()
        );
        assert!(
            verify(
                pack.bytes(),
                pack.index_object(),
                id,
                &profile,
                HostReadLimits {
                    max_allocation_bytes: 1
                },
                4
            )
            .is_err()
        );
        let data = PackWriter::new(id, PackClass::Data, false).seal().unwrap();
        assert!(verify(data.bytes(), data.index_object(), id, &profile, limits, 4).is_err());
    }
}
