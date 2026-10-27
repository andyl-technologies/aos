//! Verifies every body before publishing a complete data or metadata pair.

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

/// Verifies and synchronizes the input's exact pack class and detached index.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) async fn run(
    executor: &mut super::super::retention::NativeOwnerExecutor,
    custody: &Arc<Mutex<Custody>>,
    resource: &Arc<Mutex<AdmissionJob>>,
) -> io::Result<(u64, u64)> {
    let (expected_id, pack, index, payload, hashes) = {
        let mut job = backing::lock(resource)?;
        let (expected_id, pack, index, data) = match &job.input {
            Input::Metadata {
                expected_id,
                pack,
                index,
            } => (*expected_id, Arc::clone(pack), Arc::clone(index), false),
            Input::DataPack {
                expected_id,
                pack,
                index,
            } => (*expected_id, Arc::clone(pack), Arc::clone(index), true),
            _ => return Err(io::Error::other("pack admission received chunk input")),
        };
        let owner = custody
            .lock()
            .map_err(|_| io::Error::other("admission custody poisoned"))?;
        owner.check_current()?;
        let config = &owner.preparation.config;
        super::AdmissionBounds::new(config)?.check(pack.len(), index.len())?;
        super::AdmissionBounds::new(config)?.check(pack.capacity(), index.capacity())?;
        let hashes = if data {
            let verified = verify_data(executor, &owner, Some(resource), &job.input)?;
            job.dependencies = verified.dependencies;
            job.dictionary_edges = verified.edges;
            verified.hashes
        } else {
            verify(
                &pack,
                &index,
                expected_id,
                config.location.chunk_profile(),
                config.reads,
                config.inventory_entries.min(config.state.records),
            )?
        };
        let payload = pack
            .len()
            .checked_add(index.len())
            .ok_or_else(|| io::Error::other("metadata payload overlap overflow"))?;
        super::refuse_completed(executor, &owner, resource, &job.input)?;
        (expected_id, pack, index, payload, hashes)
    };
    super::pressure::prepare(executor, payload).await?;
    let reservation = {
        let mut job = backing::lock(resource)?;
        let mut owner = custody
            .lock()
            .map_err(|_| io::Error::other("admission custody poisoned"))?;
        owner.check_current()?;
        state::begin(executor, &mut owner, &mut job, payload, &hashes)?
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

/// Retains verified data identities and their genuine direct external source jobs.
pub(super) struct VerifiedData {
    /// Includes the pack, its records and directly retained external dictionaries.
    pub(super) hashes: Vec<String>,
    /// Retains actual completed dictionary admissions rather than digest claims.
    pub(super) dependencies: Vec<Arc<Mutex<AdmissionJob>>>,
    /// Records exact selected dictionary edges despite overlapping pack contents.
    pub(super) edges: Vec<(terrane_format::identity::Digest, u64)>,
}

/// Verifies every data body using only original admitted dictionary sources.
///
/// # Errors
/// Refuses unavailable or changed original custody, invalid content or bounds.
pub(super) fn verify_data(
    executor: &super::super::retention::NativeOwnerExecutor,
    owner: &Custody,
    current: Option<&Arc<Mutex<AdmissionJob>>>,
    input: &Input,
) -> io::Result<VerifiedData> {
    let Input::DataPack {
        expected_id,
        pack,
        index,
    } = input
    else {
        return Err(io::Error::other(
            "data verification received another input class",
        ));
    };
    let config = &owner.preparation.config;
    let mut dependencies = Vec::new();
    let mut external_hashes = Vec::new();
    let mut edges = Vec::new();
    let mut hashes = super::packed_body::verify_with_dictionaries(
        pack,
        index,
        *expected_id,
        config.location.chunk_profile(),
        config.reads,
        config.inventory_entries.min(config.state.records),
        |digest| {
            let (plaintext, source) =
                super::dictionary_read::verify(executor, current, owner, digest)?;
            external_hashes
                .try_reserve_exact(2)
                .map_err(io::Error::other)?;
            external_hashes.push(state::hex(digest));
            {
                let dependency = backing::lock(&source)?;
                if let Some((_, order)) = edges.iter().find(|(edge, _)| edge == digest) {
                    if *order != dependency.order {
                        return Err(io::Error::other(
                            "dictionary changed its original selected source",
                        ));
                    }
                } else {
                    edges.try_reserve_exact(1).map_err(io::Error::other)?;
                    edges.push((*digest, dependency.order));
                }
                if let Input::DataPack { pack, .. } = &dependency.input {
                    let identity = terrane_format::identity::TERRANE_V1
                        .calculate(terrane_format::identity::IdentityKind::Pack, pack)
                        .map_err(io::Error::other)?;
                    external_hashes.push(state::hex(identity.digest()));
                }
            }
            if !dependencies
                .iter()
                .any(|original| Arc::ptr_eq(original, &source))
            {
                dependencies
                    .try_reserve_exact(1)
                    .map_err(io::Error::other)?;
                dependencies.push(source);
            }
            Ok(plaintext)
        },
    )?;
    hashes.extend(external_hashes);
    hashes.sort();
    hashes.dedup();
    Ok(VerifiedData {
        hashes,
        dependencies,
        edges,
    })
}

/// Verifies bounded real bytes without minting filesystem or retention authority.
pub(in crate::host_cache::owner) fn verify(
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
