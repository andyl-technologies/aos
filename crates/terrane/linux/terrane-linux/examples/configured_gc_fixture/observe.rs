//! Checks selected records and exact native absence without granting authority.

use std::{collections::BTreeMap, os::unix::ffi::OsStrExt, path::Path};

use terrane_format::gc::{
    DeleteOperation, DeletePhase, GcLease, GcRoots, GcState,
    publication::{
        Activation, BackendRegistration, PortableCurrent, PortableSnapshot, PredecessorSlot,
        PublicationCommit, PublicationState, PublicationTransaction,
    },
};
use terrane_sdk::pack::PackId;

use super::{FixtureResult, fs};

pub(super) fn find_pack(bucket: &Path, hash: [u8; 32]) -> FixtureResult<PackId> {
    let mut selected = None;
    for shard in fs::read_dir(bucket.join("objects/pack"))? {
        for entry in fs::read_dir(shard?.path())? {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "idx") {
                continue;
            }
            let (header, records) =
                terrane_format::pack_format::decode_detached_index(&fs::read(path)?)?;
            if records.iter().any(|record| record.hash == hash)
                && selected
                    .replace(PackId::from_random_bytes(*header.id()))
                    .is_some()
            {
                return Err("orphan identity appears in multiple physical packs".into());
            }
        }
    }
    selected.ok_or_else(|| "native orphan pack missing".into())
}

/// Observes the contiguous committed prefix, including nonportable GC changes.
///
/// Immutable slots select transactions; PORTABLE is only a cache of a subset of
/// their payloads. These independent checks grant no native effect authority.
fn projection(bucket: &Path, control: &Path) -> FixtureResult<BTreeMap<String, Option<Vec<u8>>>> {
    let registration_bytes = fs::read(control.join("backend-registration.cbor"))?;
    let registration = BackendRegistration::decode(&registration_bytes)?;
    if registration.activation != Activation::Active || registration.genesis.is_none() {
        return Err("native publication registration is not active".into());
    }

    let mut selected = BTreeMap::new();
    let mut state: Option<PublicationState> = None;
    let mut previous_slot = None;
    let mut previous_snapshot: Option<(PortableCurrent, Vec<u8>)> = None;
    let mut revision = 0_u64;
    loop {
        let key = format!("publication/commits/{revision}");
        let bytes = match fs::read(control.join(&key)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        };
        let digest = *blake3::hash(&bytes).as_bytes();
        if revision == 0 && registration.genesis != Some(digest) {
            return Err("native publication genesis digest disagrees".into());
        }
        let commit = PublicationCommit::decode(&bytes)?;
        let transaction_bytes = fs::read(control.join(&commit.transaction_key))?;
        commit.check_transaction(&key, &transaction_bytes)?;
        let transaction = PublicationTransaction::decode(&transaction_bytes)?;
        if transaction.old != state
            || transaction.predecessor != previous_slot
            || transaction.new.binding != registration.binding
        {
            return Err("native publication predecessor or binding disagrees".into());
        }
        for change in &transaction.changes {
            if selected.get(&change.key).and_then(Option::as_ref) != change.expected.as_ref() {
                return Err("native publication whole-value expectation disagrees".into());
            }
            selected.insert(change.key.clone(), change.new.clone());
        }

        let snapshot_bytes = fs::read(bucket.join(&transaction.snapshot.key))?;
        transaction.check_snapshot(&snapshot_bytes)?;
        let snapshot = PortableSnapshot::decode(&snapshot_bytes)?;
        if let Some((pointer, bytes)) = &previous_snapshot {
            // A full portable checkpoint has no predecessor, while a delta
            // must name precisely the preceding committed transaction's bytes.
            if snapshot.predecessor.is_some() {
                snapshot.check_predecessor(pointer, bytes)?;
            }
        }
        previous_snapshot = Some((transaction.snapshot, snapshot_bytes));
        state = Some(transaction.new);
        previous_slot = Some(PredecessorSlot { revision, digest });
        revision = revision
            .checked_add(1)
            .ok_or("publication revision overflow")?;
    }
    if state.is_none() || fs::read(control.join("backend-registration.cbor"))? != registration_bytes
    {
        return Err("native committed prefix missing or registration changed".into());
    }
    Ok(selected)
}

pub(super) fn verify_deletion(root: &Path) -> FixtureResult<()> {
    let bucket = root.join("bucket");
    let pack: [u8; 16] = fs::read(root.join("expected.pack"))?
        .try_into()
        .map_err(|_| "invalid saved native pack identity")?;
    let id = PackId::from_random_bytes(pack);
    for key in [id.pack_key(), id.index_key()] {
        if bucket.join(key).try_exists()? {
            return Err("native orphan pair still present".into());
        }
    }
    let digest = blake3::hash(bucket.as_os_str().as_bytes()).to_hex();
    let control = bucket.with_file_name(format!(".terrane-control:{digest}"));
    let selected = projection(&bucket, &control)?;
    let lease = GcLease::decode(
        selected
            .get("gc/lease")
            .and_then(Option::as_deref)
            .ok_or("missing selected collector lease")?,
    )?;
    let mut cycles = Vec::new();
    for (key, value) in &selected {
        if !key.starts_with("gc/") || !key.ends_with("/roots") {
            continue;
        }
        let roots = GcRoots::decode(value.as_deref().ok_or("absent registered root snapshot")?)?;
        let state = GcState::decode(
            selected
                .get(&format!("gc/{}/state", roots.cycle))
                .and_then(Option::as_deref)
                .ok_or("missing selected traversal checkpoint")?,
        )?;
        if roots.epoch != lease.epoch || state.epoch != lease.epoch {
            return Err("fresh cycles did not retain their original whole lease".into());
        }
        cycles.push(roots.cycle);
    }
    if cycles.len() < 2 {
        return Err("collector did not start a fresh second cycle".into());
    }

    let mut matching = 0;
    for cycle in fs::read_dir(control.join("gc"))? {
        let directory = cycle?.path().join("delete").join(id.to_string());
        if !directory.try_exists()? {
            continue;
        }
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let key = path
                .strip_prefix(&control)?
                .to_str()
                .ok_or("non-UTF-8 operation key")?;
            let operation = DeleteOperation::decode(&fs::read(&path)?, key)?;
            if operation.authorization.pack_id != pack {
                return Err("another pack in exact native intent directory".into());
            }
            if operation.phase != DeletePhase::Done
                || operation.authorization.deletion_seconds != 60
                || operation.authorization.elapsed_ns < 60_000_000_000
                || operation.authorization.original_lease.holder != lease.holder
                || operation.authorization.original_lease.epoch != lease.epoch
                || operation.current_lease.holder != lease.holder
                || operation.current_lease.epoch != lease.epoch
                || operation.current_lease.expiry > lease.expiry
                || bucket
                    .join(format!("trash/{}/{id}", operation.authorization.cycle))
                    .try_exists()?
            {
                return Err("exact native Done or full-D witness missing".into());
            }
            matching += 1;
        }
    }
    if matching != 1 {
        return Err("expected exactly one genuine native deletion operation".into());
    }
    Ok(())
}
