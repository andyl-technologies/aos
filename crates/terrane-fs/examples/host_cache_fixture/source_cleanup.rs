//! Exercises real pending-source cleanup, grace refusal and abandoned waiters.
//!
//! Raw files below are observations of genuinely admitted inodes. They cannot
//! construct publisher claims, cleanup turns or native serving authority.

use super::{config::Inputs, manifest_publication};
use std::{
    fs::{self, File},
    future::Future,
    io::{self, BufRead, Write},
    os::unix::fs::{FileExt, MetadataExt},
    sync::Arc,
    task::{Context, Poll, Waker},
    time::UNIX_EPOCH,
};
use terrane::{
    host::cache::CacheState,
    store::{ChunkPosition, Clock, TokioClock, TokioLocalFs},
};
use terrane_core::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_fs::{
    host_cache::{
        NativeCachePreparation, NativeInlinePublication, NativeMetadataOwner,
        NativeSourceCleanupReport,
    },
    publisher_local::{Error as PublisherError, wire::ResultCode},
    quota_confinement,
};

const INLINE: &[u8] = b"original retired inline cleanup source";

/// Runs actual cleanup in a separately provisioned finite native domain.
///
/// # Errors
/// Refuses incorrect native results, changed funding/backing, lost cancellation
/// custody, false quota reclamation or an early operation that escapes recovery.
pub(super) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    confinement: Arc<quota_confinement::Installed>,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    let domain = match mode {
        "source-cleanup" => "tenant:source-cleanup",
        "source-cleanup-early" => "tenant:source-cleanup-early",
        _ => return Err(invalid("unknown source cleanup selector")),
    };
    if inputs.domain != domain || original.is_some() {
        return Err(invalid("source cleanup requires a fresh dedicated domain"));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let (descriptor, inline_source) = admit(owner, runtime, inputs, INLINE, ChunkPosition::Final)?;
    let inline = runtime
        .block_on(owner.publish_inline(descriptor, encoded(INLINE)))
        .map_err(io::Error::other)?;
    if mode == "source-cleanup-early" {
        return early(owner, runtime, inputs, &inline, &inline_source);
    }

    let data = manifest_publication::data(false, false)?;
    let (_, first_source) = admit(owner, runtime, inputs, &data.first, ChunkPosition::NonFinal)?;
    let (_, tail_source) = admit(owner, runtime, inputs, &data.tail, ChunkPosition::Final)?;
    manifest_publication::admit_manifest(owner, runtime, &data)?;
    let manifest = runtime.block_on(owner.publish_manifest(data.identity.clone()))?;
    // Advance actual policy after both original publications. Cleanup cannot
    // borrow an obsolete snapshot generation as its authority.
    admit(
        owner,
        runtime,
        inputs,
        b"later source cleanup generation",
        ChunkPosition::Final,
    )?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, &data.first)
        .map_err(io::Error::other)?;
    let resident = runtime.block_on(owner.retain_resident_chunk(identity.clone()))?;
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(120)
        .ok_or_else(|| invalid("cleanup consumer deadline overflow"))?;
    let lease = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
    foreign(runtime, inputs, confinement, &inline)?;
    let before = fs::read(policy(inputs))?;
    let sources = [inline_source, first_source, tail_source];
    for source in &sources {
        if source.metadata()?.nlink() != 1 {
            return Err(invalid(
                "pending source lost its native link before cleanup",
            ));
        }
    }
    emit("READY actual inline and manifest retired sources; retain original native grace")?;
    control("start")?;
    let mut pending = Box::pin(inline.finish_retired_sources(owner));
    if !matches!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ) {
        return Err(invalid(
            "stopped publisher did not retain the cleanup waiter",
        ));
    }
    drop(pending);
    emit("CANCELLED accepted source cleanup waiter; physical owner retained")?;
    control("complete")?;

    let inline_report = runtime.block_on(inline.finish_retired_sources(owner))?;
    if inline_report.completed_sources != 1 {
        return Err(invalid(
            "inline cleanup lacks its actual original source acknowledgement",
        ));
    }
    let manifest_report = runtime.block_on(manifest.finish_retired_sources(owner))?;
    if manifest_report.completed_sources != 2 {
        return Err(invalid(
            "manifest cleanup did not deduplicate its repeated source",
        ));
    }
    let repeated = runtime.block_on(manifest.finish_retired_sources(owner))?;
    if repeated.completed_sources != 2 || fs::read(policy(inputs))? != before {
        return Err(invalid(
            "repeated cleanup lost acknowledgement or altered durable funding",
        ));
    }
    let observed = [encoded(INLINE), data.encoded_first, encoded(&data.tail)];
    let mut retained = 0_u64;
    for (source, expected) in sources.iter().zip(observed) {
        let metadata = source.metadata()?;
        let mut bytes = vec![0; expected.len()];
        source.read_exact_at(&mut bytes, 0)?;
        if metadata.nlink() != 0 || bytes != expected {
            return Err(invalid(
                "cleanup changed retained source bytes or kept its pending name",
            ));
        }
        retained = retained
            .checked_add(
                metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or_else(|| invalid("source allocation overflow"))?,
            )
            .ok_or_else(|| invalid("retained allocation overflow"))?;
    }
    let mut plaintext = vec![0; data.plaintext.len()];
    manifest.handle().read_exact_at(&mut plaintext, 0)?;
    let mut inline_bytes = vec![0; INLINE.len()];
    inline.handle().read_exact_at(&mut inline_bytes, 0)?;
    if plaintext != data.plaintext || inline_bytes != INLINE {
        return Err(invalid("source cleanup changed original immutable output"));
    }
    let stall = runtime.block_on(owner.stall_policy_for_fixture())?;
    if resident.read_verified()? != data.first || lease.read_verified()? != data.first {
        return Err(invalid(
            "source cleanup invalidated original resident or live consumer reads",
        ));
    }
    drop(stall);
    let known = retained
        .checked_add(
            inline
                .handle()
                .metadata()?
                .blocks()
                .checked_mul(512)
                .ok_or_else(|| invalid("inline allocation overflow"))?,
        )
        .and_then(|bytes| bytes.checked_add(repeated.synchronized_sealed_inode_bytes))
        .ok_or_else(|| invalid("known actual allocation overflow"))?;
    check_report(runtime, inputs, &repeated, known)?;
    emit(&format!(
        "SOURCE_CLEANUP_MEASUREMENT charged_reserved_bytes={} future_hold_bytes={} retained_source_bytes={} sealed_bytes={}",
        repeated.charged_reserved_bytes,
        repeated.future_hold_bytes,
        retained,
        known - retained
    ))?;
    emit("READY actual cleanup accounting retains open source descriptions")?;
    // The independent root controller queries actual quota while all original
    // unlinked descriptions remain open, then observes reclamation after exit.
    control("release")?;
    emit(
        "PASS actual inline and repeated-manifest source cleanup retained pins, live reads, holds and charged unlinked inodes after cancellation; no Ready",
    )
}

fn early(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    publication: &NativeInlinePublication,
    source: &File,
) -> io::Result<()> {
    let before = fs::read(policy(inputs))?;
    let error = runtime
        .block_on(publication.finish_retired_sources(owner))
        .err()
        .ok_or_else(|| invalid("active native grace acknowledged source cleanup"))?;
    if !matches!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<PublisherError>()),
        Some(PublisherError::Remote(ResultCode::Unavailable))
    ) {
        return Err(error);
    }
    if source.metadata()?.nlink() != 1 || fs::read(policy(inputs))? != before {
        return Err(invalid(
            "active native grace allowed cleanup or lost funding",
        ));
    }
    let descriptor = descriptor(b"refused after uncertain cleanup")?;
    if runtime
        .block_on(owner.publish_inline(descriptor, encoded(b"refused after uncertain cleanup")))
        .is_ok()
        || fs::read(policy(inputs))? != before
    {
        return Err(invalid(
            "unavailable cleanup did not require actual owner recovery",
        ));
    }
    emit(
        "PASS actual early source cleanup refused with original pending inode and funding retained; unavailable requires recovery",
    )
}

fn foreign(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    confinement: Arc<quota_confinement::Installed>,
    publication: &NativeInlinePublication,
) -> io::Result<()> {
    let foreign = Inputs {
        root: std::env::var("TERRANE_CLEANUP_FOREIGN_ROOT")
            .map_err(io::Error::other)?
            .into(),
        domain: "tenant:source-cleanup-foreign".into(),
        owner: "native-cache-source-cleanup-foreign".into(),
        project: std::env::var("TERRANE_CLEANUP_FOREIGN_PROJECT")
            .map_err(io::Error::other)?
            .parse()
            .map_err(io::Error::other)?,
        quota: inputs.quota.clone(),
        publisher: inputs.publisher.clone(),
        budget: inputs.budget,
        uuid: inputs.uuid,
    };
    let preparation = NativeCachePreparation::inspect(foreign.owner_config()?, confinement)?;
    let foreign_owner = NativeMetadataOwner::start(preparation)?;
    let completed = runtime.block_on(foreign_owner.recover())?;
    runtime
        .block_on(foreign_owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let original = fs::read(policy(inputs))?;
    let other = fs::read(policy(&foreign))?;
    if runtime
        .block_on(publication.finish_retired_sources(&foreign_owner))
        .is_ok()
        || fs::read(policy(inputs))? != original
        || fs::read(policy(&foreign))? != other
    {
        return Err(invalid("foreign cleanup changed original physical custody"));
    }
    // A valid subsequent mutation proves the refused owner was not faulted.
    admit(
        &foreign_owner,
        runtime,
        &foreign,
        b"foreign cleanup positive control",
        ChunkPosition::Final,
    )?;
    if fs::read(policy(inputs))? != original {
        return Err(invalid("foreign positive control altered original policy"));
    }
    emit("PASS actual foreign physical owner refused source cleanup and remained usable")
}

fn admit(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    plaintext: &[u8],
    position: ChunkPosition,
) -> io::Result<(Descriptor, File)> {
    let descriptor = descriptor(plaintext)?;
    let admitted = runtime
        .block_on(owner.admit_chunk(descriptor.clone(), position, encoded(plaintext)))
        .map_err(io::Error::other)?;
    if admitted.descriptor() != &descriptor || admitted.synchronized_chunk_bytes() == 0 {
        return Err(invalid("cleanup fixture lacks actual source admission"));
    }
    let hash: String = descriptor
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let file = File::open(
        inputs
            .root
            .join("chunks")
            .join(&hash[..2])
            .join(format!("{hash}.0")),
    )?;
    Ok((descriptor, file))
}

fn check_report(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    report: &NativeSourceCleanupReport,
    known_allocation: u64,
) -> io::Result<()> {
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root,
            super::config::STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("source cleanup policy disappeared"))?;
    let future = state.reservations.iter().try_fold(0_u64, |sum, row| {
        sum.checked_add(row.bytes)
            .ok_or_else(|| invalid("cleanup policy hold overflow"))
    })?;
    if report.future_hold_bytes != future || report.charged_reserved_bytes < known_allocation {
        return Err(invalid(
            "cleanup report inferred freed source allocation or lost future holds",
        ));
    }
    Ok(())
}

fn descriptor(bytes: &[u8]) -> io::Result<Descriptor> {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, bytes)
        .map_err(io::Error::other)?;
    Descriptor::from_identity(&TERRANE_V1, &identity, bytes).map_err(io::Error::other)
}

fn encoded(bytes: &[u8]) -> Vec<u8> {
    [vec![0], bytes.to_vec()].concat()
}
fn policy(inputs: &Inputs) -> std::path::PathBuf {
    inputs.root.join("state/cache/records.toml")
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn emit(message: &str) -> io::Result<()> {
    let mut output = io::stdout().lock();
    writeln!(output, "{message}")?;
    output.flush()
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim() != expected {
        return Err(invalid("unexpected source cleanup control"));
    }
    Ok(())
}
