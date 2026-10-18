//! Exercises a second assembly using actual pinned ranges from the first one.
//!
//! Both objects, original admissions, metadata pairs and retired inodes come
//! from the real native owner. No source descriptor or residence is fabricated.

use super::*;

/// Publishes two actual manifests sharing a repeated nonfinal chunk.
///
/// # Errors
/// Refuses stale fixture state, missing original pins, changed residence or
/// backing, duplicate standalone copies, and incomplete actual source retirement.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if !matches!(
        inputs.domain.as_str(),
        "tenant:publication-manifest-reuse" | "tenant:publication-manifest-reuse-bad-whole"
    ) || original.is_some()
    {
        return Err(invalid("range reuse requires its fresh dedicated domain"));
    }
    let first = data(false, false)?;
    let bad = inputs.domain.ends_with("-bad-whole");
    let second = data_with_tail(bad, false, 100)?;
    if first.first != second.first || first.identity == second.identity {
        return Err(invalid(
            "range reuse fixtures lack distinct honest manifests",
        ));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    admit(
        owner,
        runtime,
        &first.first,
        ChunkPosition::NonFinal,
        first.encoded_first.clone(),
    )?;
    admit(
        owner,
        runtime,
        &first.tail,
        ChunkPosition::Final,
        [vec![0], first.tail.clone()].concat(),
    )?;
    let (first_pack_identity, first_pack, first_index) = admit_manifest(owner, runtime, &first)?;
    let published = runtime.block_on(owner.publish_manifest(first.identity.clone()))?;
    check_receipt(&published, &first, first_pack.len() + first_index.len())?;
    drop(published);

    let retained = runtime.block_on(owner.retain_manifest(first.identity.clone()))?;
    retained.check_current()?;
    check_state(
        runtime,
        inputs,
        &first,
        &first_pack_identity,
        first_pack.len() + first_index.len(),
        true,
    )?;
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    if runtime
        .block_on(owner.admit_chunk(
            descriptor(&first.first, IdentityKind::Chunk)?,
            ChunkPosition::NonFinal,
            first.encoded_first.clone(),
        ))
        .is_ok()
        || fs::read(inputs.root.join("state/cache/records.toml"))? != before
    {
        return Err(invalid(
            "a sealed resident gained another standalone admission",
        ));
    }
    admit(
        owner,
        runtime,
        &second.tail,
        ChunkPosition::Final,
        [vec![0], second.tail.clone()].concat(),
    )?;
    let (_, second_pack, second_index) = admit_manifest(owner, runtime, &second)?;
    let first_identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &first.first)
        .map_err(io::Error::other)?;
    let retained_first = runtime.block_on(owner.retain_resident_chunk(first_identity))?;
    emit(
        "READY original manifest backing and new standalone tail retained; wait for range reuse control",
    )?;
    control("publish")?;

    if bad {
        if runtime
            .block_on(owner.publish_manifest(second.identity.clone()))
            .is_ok()
            || runtime
                .block_on(owner.retain_manifest(second.identity.clone()))
                .is_ok()
        {
            return Err(invalid(
                "wrong whole hash on resident inputs gained publication or owner reuse",
            ));
        }
        check_completed_state(runtime, inputs, &first, &second, false)?;
        let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
        let actual = retained_first.read_verified()?;
        drop(stalled);
        if actual != first.first {
            return Err(invalid(
                "failed later assembly invalidated the retained original source",
            ));
        }
        emit(
            "REFUSED resident reassembly whole hash; original source still readable and anonymous output retained; no Ready",
        )?;
        control("finish")?;
        return emit(
            "PASS actual resident reassembly rejected the wrong whole hash, retained anonymous output and preserved original backing, ranges and sources; no Ready",
        );
    }
    let published = runtime.block_on(owner.publish_manifest(second.identity.clone()))?;
    check_second_receipt(
        &published,
        &first,
        &second,
        first_pack.len() + first_index.len() + second_pack.len() + second_index.len(),
    )?;
    drop(published);
    check_completed_state(runtime, inputs, &first, &second, true)?;
    for (data, bytes) in [
        (&first, first.first.as_slice()),
        (&first, first.tail.as_slice()),
        (&second, second.tail.as_slice()),
    ] {
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, bytes)
            .map_err(io::Error::other)?;
        let source = runtime.block_on(owner.retain_resident_chunk(identity))?;
        let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
        let actual = source.read_verified()?;
        drop(stalled);
        if actual != bytes
            || source.span().length != bytes.len()
            || (data.identity == first.identity
                && bytes == first.first
                && source.span().offset != 0)
        {
            return Err(invalid(
                "range reuse changed an original or newly published chunk",
            ));
        }
    }
    emit(
        "PASS actual manifest reassembly reused pinned sealed ranges, retained original residences and retired only its new standalone source; no Ready",
    )
}

fn check_second_receipt(
    receipt: &NativeManifestPublication,
    first: &Data,
    second: &Data,
    metadata_bytes: usize,
) -> io::Result<()> {
    let mut actual = vec![0; second.plaintext.len()];
    receipt.handle().read_exact_at(&mut actual, 0)?;
    let expected_hold = 11 * HOLD
        + admission_bytes(first) as u64
        + second.tail.len() as u64
        + 1
        + metadata_bytes as u64
        + 2 * (first.plaintext.len() + second.plaintext.len()) as u64;
    if actual != second.plaintext
        || receipt.claim().descriptor().digest() != second.identity.digest()
        || receipt.claim().canonical_manifest() != Some(second.canonical.as_slice())
        || receipt.future_hold_bytes() != expected_hold
        || receipt.synchronized_sealed_inode_bytes()
            != synchronized_allocated_bytes(receipt.handle())?
        || receipt.charged_reserved_bytes() == 0
    {
        return Err(invalid(
            "second manifest receipt lost actual backing or distinct exact funding",
        ));
    }
    Ok(())
}

fn check_completed_state(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    first: &Data,
    second: &Data,
    success: bool,
) -> io::Result<()> {
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("range reuse snapshot absent"))?;
    if state.reservations.len() != 11
        || state.leases.len() != 10
        || state.pins.len() != 15
        || state.residences.len() != if success { 3 } else { 2 }
    {
        return Err(invalid(
            "range reuse lost exact original and new policy closure",
        ));
    }
    for (bytes, object, offset) in [
        (first.first.as_slice(), &first.identity, 0),
        (
            first.tail.as_slice(),
            &first.identity,
            2 * first.first.len(),
        ),
        (
            second.tail.as_slice(),
            &second.identity,
            2 * second.first.len(),
        ),
    ] {
        if !success && object == &second.identity {
            continue;
        }
        let hash = hex(descriptor(bytes, IdentityKind::Chunk)?.digest());
        if !state.residences.iter().any(|row| {
            row.chunk == hash
                && row.object == hex(object.digest())
                && row.offset == offset as u64
                && row.length == bytes.len() as u64
        }) {
            return Err(invalid("shared chunk lost its original single residence"));
        }
    }
    Ok(())
}
