//! Checks inline publication retaining the original packed dictionary sources.
//!
//! The supervisor observes the real publisher, original native files and synced
//! policy. Cancellation drops only a response waiter, never physical custody.

use super::*;
use std::os::unix::fs::FileExt;

/// Publishes against an original dictionary pair through handoff or cancellation.
///
/// # Errors
/// Refuses incorrect original files, descriptors, funding, native publication or
/// consumer reads, and any unexpected supervisor control.
pub(super) fn run(
    cancelled: bool,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let (_, chunks) = fixture()?;
    let pair = cross_pack::dictionary_pair(&chunks)?;
    let id = PackId::from_random_bytes([122; 16]);
    let container = TERRANE_V1
        .calculate(IdentityKind::Pack, pair.bytes())
        .map_err(io::Error::other)?;
    let source_hashes = BTreeSet::from([
        hex(descriptor(&chunks[0].plaintext)?.digest()),
        hex(descriptor(&chunks[1].plaintext)?.digest()),
        hex(container.digest()),
    ]);
    let source = runtime
        .block_on(owner.admit_data_pack(id, pair.bytes().to_vec(), pair.index_object().to_vec()))
        .map_err(io::Error::other)?;
    check_state(
        runtime,
        inputs,
        &[hold(
            pair.bytes().len() + pair.index_object().len(),
            source_hashes.iter().cloned(),
        )?],
    )?;
    let pack = PathBuf::from(format!("objects/pack/7a/{id}.pack"));
    let index = PathBuf::from(format!("objects/pack/7a/{id}.idx"));
    let (pack_bytes, _) = canonical(inputs, &pack, pair.bytes())?;
    let (index_bytes, _) = canonical(inputs, &index, pair.index_object())?;
    if source.synchronized_pair_bytes() != pack_bytes + index_bytes {
        return Err(invalid("publication dictionary pair allocation differs"));
    }
    let root = descriptor(&chunks[2].plaintext)?;
    let mut protected = source_hashes;
    protected.insert(hex(root.digest()));
    emit("READY inline packed dictionaries retain original funded pair")?;
    control("publish-packed")?;

    let publication = if cancelled {
        let mut pending = Box::pin(owner.publish_inline(root.clone(), chunks[2].encoded.clone()));
        if !matches!(
            pending
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return Err(invalid(
                "stopped publisher did not retain packed dictionary waiter",
            ));
        }
        emit("QUEUED inline packed dictionary publication")?;
        control("cancel-packed")?;
        drop(pending);
        emit("CANCELLED inline packed dictionary waiter; physical custody retained")?;
        control("resumed-packed")?;
        None
    } else {
        let result = runtime
            .block_on(owner.publish_inline(root.clone(), chunks[2].encoded.clone()))
            .map_err(io::Error::other)?;
        let metadata = result.handle().metadata()?;
        let mut plaintext = vec![0; chunks[2].plaintext.len()];
        result.handle().read_exact_at(&mut plaintext, 0)?;
        if plaintext != chunks[2].plaintext
            || result.claim().descriptor() != &root
            || result.claim().domain() != inputs.domain
            || metadata.uid() != 841
            || metadata.gid() != 841
            || metadata.mode() & 0o7777 != 0o400
            || metadata.nlink() != 1
            || NativeProject::inspect(result.handle())?.project_id != inputs.project
            || synchronized_allocated_bytes(result.handle())?
                != result.synchronized_sealed_inode_bytes()
        {
            return Err(invalid(
                "packed dictionary publication changed sealed native backing",
            ));
        }
        let flags = native::fcntl_getfl(result.handle())?;
        if flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH) {
            return Err(invalid("packed publication descriptor is not read-only"));
        }
        terrane_linux::verity::measure(result.handle())?;
        Some(result)
    };

    // This genuine owner command is serialized after the publication even when
    // its waiter was dropped. The original dictionary plan must survive it.
    runtime
        .block_on(source.into_cache(owner))
        .map_err(io::Error::other)?;
    check_descriptors(inputs, [&pack, &index], 2)?;
    check_policy(runtime, inputs, &protected, true)?;
    canonical(inputs, &pack, pair.bytes())?;
    canonical(inputs, &index, pair.index_object())?;
    emit("READY inline packed publication retains original descriptors and four pins")?;
    control("handoff-packed-publication")?;

    if let Some(publication) = publication {
        let report = runtime
            .block_on(publication.into_cache(owner))
            .map_err(io::Error::other)?;
        if report.future_hold_bytes != HOLD || report.released_source_admissions != 0 {
            return Err(invalid(
                "packed publication handoff changed independent source funding",
            ));
        }
        check_descriptors(inputs, [&pack, &index], 1)?;
        check_policy(runtime, inputs, &protected, false)?;
    } else {
        // No receipt is fabricated for the abandoned physical job. Its producer
        // promise and original read descriptions remain owned by the executor.
        check_descriptors(inputs, [&pack, &index], 2)?;
        check_policy(runtime, inputs, &protected, true)?;
    }
    let identity = TERRANE_V1
        .from_digest(IdentityKind::Chunk, root.digest())
        .map_err(io::Error::other)?;
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("packed publication consumer expiry overflow"))?;
    let lease = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
    if lease.read_verified()? != chunks[2].plaintext
        || lease.read_encoded()? != raw(&chunks[2].plaintext)
    {
        return Err(invalid(
            "packed publication consumer lost original sealed plaintext",
        ));
    }
    runtime.block_on(owner.release_consumer_lease(&lease))?;
    drop(lease);
    canonical(inputs, &pack, pair.bytes())?;
    canonical(inputs, &index, pair.index_object())?;
    if fs::read_dir(inputs.root.join("chunks"))?.next().is_some()
        || fs::read_dir(inputs.root.join("pending-delete"))?
            .next()
            .is_some()
    {
        return Err(invalid(
            "packed inline publication extracted or retired dictionaries",
        ));
    }
    emit("READY inline packed publication consumer and original custody verified")?;
    control("packed-publication-observed")?;
    emit(
        "PASS actual inline publication retains original packed dictionary closure through cancellation or synchronized cache handoff; no Ready",
    )
}

/// Counts real owner-process descriptions of each original pair member.
fn check_descriptors(inputs: &Inputs, paths: [&PathBuf; 2], expected: usize) -> io::Result<()> {
    for relative in paths {
        let original = fs::metadata(inputs.root.join(relative))?;
        let mut count = 0;
        for entry in fs::read_dir("/proc/self/fd")? {
            match fs::metadata(entry?.path()) {
                Ok(value) if (value.dev(), value.ino()) == (original.dev(), original.ino()) => {
                    count += 1;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if count != expected {
            return Err(invalid(
                "packed publication changed original read descriptor custody",
            ));
        }
    }
    Ok(())
}

/// Checks the original publication's complete dictionary and container promise.
fn check_policy(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    protected: &BTreeSet<String>,
    producer: bool,
) -> io::Result<()> {
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("packed publication snapshot absent"))?;
    let prefix = if producer {
        "publication:"
    } else {
        "publication-grace:"
    };
    let leases = state
        .leases
        .iter()
        .filter(|row| row.owner.starts_with(prefix))
        .collect::<Vec<_>>();
    if leases.len() != 1
        || (producer && leases[0].expires != RETAINED_LEASE_DEADLINE)
        || (!producer && leases[0].expires >= RETAINED_LEASE_DEADLINE)
    {
        return Err(invalid("packed publication lease closure differs"));
    }
    let lease = leases[0];
    let pins = state
        .pins
        .iter()
        .filter(|row| row.owner == lease.owner)
        .collect::<Vec<_>>();
    if pins.len() != protected.len()
        || pins.iter().any(|row| row.expires != lease.expires)
        || pins
            .iter()
            .map(|row| row.hash.clone())
            .collect::<BTreeSet<_>>()
            != *protected
        || state.reservations.len() != 1 + usize::from(producer)
        || state
            .reservations
            .iter()
            .any(|row| row.owner != inputs.owner || row.bytes != HOLD)
        || state.residences.len() != 1
        || state
            .pins
            .iter()
            .any(|row| row.owner.starts_with("admission:"))
    {
        return Err(invalid(
            "packed publication pins, residence or settled funding differ",
        ));
    }
    let future = state.reservations.iter().map(|row| row.bytes).sum::<u64>();
    if quota(inputs)?
        .checked_add(future)
        .is_none_or(|total| total > CAPACITY)
    {
        return Err(invalid(
            "packed publication exceeds actual charge plus future holds",
        ));
    }
    Ok(())
}
