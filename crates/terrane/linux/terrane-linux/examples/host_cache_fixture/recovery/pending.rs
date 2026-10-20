//! Checks actual conservative retirement deadlines across physical owner restarts.

use super::{
    HARD_LIMIT, HOLD, INLINE_BYTES, Inputs, STATE, directory, hex, invalid,
    require_seed_capabilities, write,
};
use std::{
    fs::{self, File},
    io,
};
use terrane_format::{
    chunking::ChunkProfile,
    codec::{Codec, EncodedChunk, encode_envelope},
    identity::{IdentityKind, TERRANE_V1},
};
use terrane_linux::{
    host_cache::NativeMetadataOwner,
    publisher_local::{Error as PublisherError, wire::ResultCode},
};
use terrane_sdk::{host::cache::CacheState, store::TokioLocalFs};

/// Seeds one actual sealed pending chunk without forging retirement metadata.
///
/// # Errors
/// Refuses unexpected administration, domain, project inheritance or seal failure.
pub(crate) fn seed() -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid("pending seed requires root administration"));
    }
    require_seed_capabilities()?;
    let inputs = Inputs::load()?;
    require_domain(&inputs)?;
    let path = inputs
        .root
        .join("pending-delete")
        .join(super::inline_hash()?);
    write(&inputs, &path, INLINE_BYTES, 841, 841, 0o400)?;
    let file = File::open(path)?;
    terrane_linux::verity::enable(&file)?;
    file.sync_all()?;
    File::open(inputs.root.join("pending-delete"))?.sync_all()?;
    println!("SEEDED actual sealed pending inode without a retirement deadline");
    Ok(())
}

/// Seeds an actual raw, zstd or dictionary frame without content or lease authority.
///
/// Dictionary data is deliberately absent: expired removal needs actual typed
/// inode custody, while decoding and serving would require that dependency.
///
/// # Errors
/// Refuses unexpected administration, domain, codec output, project inheritance
/// or native namespace durability failures.
pub(crate) fn seed_encoded(mode: &str) -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid("pending seed requires root administration"));
    }
    require_seed_capabilities()?;
    let inputs = Inputs::load()?;
    let profile = ChunkProfile::cdc_1m([0; 32]);
    let repeated = vec![b'P'; 65536];
    let dictionary = vec![b'P'; 4096];
    let (prefix, codec, plaintext, encoded) = match mode {
        "seed-pending-raw" => (
            "tenant:pending-raw-",
            0,
            INLINE_BYTES,
            encode_envelope(EncodedChunk {
                codec: Codec::Raw,
                body: INLINE_BYTES,
            }),
        ),
        "seed-pending-zstd" => (
            "tenant:pending-zstd-",
            1,
            repeated.as_slice(),
            terrane_sdk::codec::encode_chunk(&repeated, profile.maximum(), 3, None)
                .map_err(io::Error::other)?,
        ),
        "seed-pending-dictionary" => (
            "tenant:pending-dictionary-",
            2,
            repeated.as_slice(),
            terrane_sdk::codec::encode_chunk(&repeated, profile.maximum(), 3, Some(&dictionary))
                .map_err(io::Error::other)?,
        ),
        _ => return Err(invalid("unknown pending encoded seed")),
    };
    if !matches!(
        inputs.domain.strip_prefix(prefix),
        Some("expired" | "unknown")
    ) || encoded.first() != Some(&codec)
    {
        return Err(invalid("pending encoded seed has another domain or codec"));
    }
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .map_err(io::Error::other)?;
    let digest = hex(identity.digest());
    let parent = inputs.root.join("chunks").join(&digest[..2]);
    directory(&parent, 840, 845, 0o2770)?;
    File::open(&parent)?.sync_all()?;
    File::open(inputs.root.join("chunks"))?.sync_all()?;
    let path = inputs.root.join("pending-delete").join(digest);
    write(&inputs, &path, &encoded, 840, 845, 0o640)?;
    File::open(inputs.root.join("pending-delete"))?.sync_all()?;
    println!("SEEDED actual encoded pending inode without a retirement deadline");
    Ok(())
}

/// Exercises genuine recovery refusal or completion on the physical owner.
///
/// # Errors
/// Refuses an unexpected result, lost original holds, premature Resume,
/// policy mutation after a fault or incorrect measured accounting.
pub(crate) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    if matches!(
        mode,
        "refuse-pending-pack" | "recover-pending-pack" | "refuse-pending-pack-foreign"
    ) {
        super::pending_packs::require_domain(inputs)?;
    } else {
        require_domain(inputs)?;
    }
    let load = || {
        runtime
            .block_on(CacheState::load(
                &TokioLocalFs,
                &inputs.root.join("state/cache"),
                STATE,
            ))
            .map_err(io::Error::other)
    };
    let before = load()?.unwrap_or_default();
    let result = runtime.block_on(owner.recover());
    let after = load()?.ok_or_else(|| invalid("pending recovery lost bootstrap"))?;
    if after.reservations.len() != before.reservations.len() + 1
        || before.reservations.iter().any(|old| {
            !after
                .reservations
                .iter()
                .any(|new| new.id == old.id && new.owner == old.owner && new.bytes == old.bytes)
        })
        || after
            .reservations
            .iter()
            .any(|hold| hold.owner != inputs.owner || hold.bytes != HOLD)
        || !after.pins.is_empty()
        || !after.leases.is_empty()
        || !after.residences.is_empty()
    {
        return Err(invalid("pending recovery changed original policy holds"));
    }
    if matches!(
        mode,
        "refuse-pending-inline"
            | "refuse-pending-chunk"
            | "refuse-pending-pack"
            | "refuse-pending-pack-foreign"
    ) {
        let error = result
            .err()
            .ok_or_else(|| invalid("unexpired pending inode was removed"))?;
        let expected = if mode == "refuse-pending-pack-foreign" {
            ResultCode::Invalid
        } else {
            ResultCode::Unavailable
        };
        if !matches!(
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<PublisherError>()),
            Some(PublisherError::Remote(code)) if *code == expected
        ) {
            return Err(io::Error::other(format!(
                "unexpected pending refusal: {error}"
            )));
        }
        let path = inputs.root.join("state/cache/records.toml");
        let bytes = fs::read(&path)?;
        let retry = runtime
            .block_on(owner.recover())
            .err()
            .ok_or_else(|| invalid("faulted pending owner completed recovery"))?;
        if retry.kind() != io::ErrorKind::WouldBlock || fs::read(path)? != bytes {
            return Err(invalid("pending refusal lost faulted bootstrap custody"));
        }
        if mode == "refuse-pending-pack-foreign" {
            println!(
                "PASS actual foreign-project pending pack refused before namespace mutation; original bootstrap holds retained; no Resume"
            );
        } else if mode == "refuse-pending-pack" {
            println!(
                "PASS actual unexpired pending pack unit refused; original bootstrap holds retained; no Resume"
            );
        } else if mode == "refuse-pending-chunk" {
            println!(
                "PASS actual unexpired encoded pending inode refused; original bootstrap holds retained; no Resume"
            );
        } else {
            println!(
                "PASS actual unexpired pending inode refused; original bootstrap holds retained; no Resume"
            );
        }
        return Ok(());
    }
    if !matches!(
        mode,
        "recover-pending-inline" | "recover-pending-chunk" | "recover-pending-pack"
    ) {
        return Err(invalid("unknown pending recovery selector"));
    }
    let completed = result?;
    completed.check_current()?;
    if completed.future_hold_bytes() != after.reservations.len() as u64 * HOLD
        || completed.charged_reserved_bytes() > HARD_LIMIT
        || completed.synchronized_retained_inode_bytes() == 0
    {
        return Err(invalid(
            "pending recovery confused holds and native charges",
        ));
    }
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    if mode == "recover-pending-pack" {
        println!(
            "PASS actual expired pending pack unit removed before completed recovery and acknowledged Resume; original holds retained; no Ready"
        );
    } else if mode == "recover-pending-chunk" {
        println!(
            "PASS actual expired encoded pending inode removed before completed recovery and acknowledged Resume; original holds retained; no Ready"
        );
    } else {
        println!(
            "PASS actual expired pending inode removed before completed recovery and acknowledged Resume; original holds retained; no Ready"
        );
    }
    Ok(())
}

fn require_domain(inputs: &Inputs) -> io::Result<()> {
    if matches!(
        inputs.domain.as_str(),
        "tenant:pending-expired"
            | "tenant:pending-unknown"
            | "tenant:pending-raw-expired"
            | "tenant:pending-raw-unknown"
            | "tenant:pending-zstd-expired"
            | "tenant:pending-zstd-unknown"
            | "tenant:pending-dictionary-expired"
            | "tenant:pending-dictionary-unknown"
    ) {
        Ok(())
    } else {
        Err(invalid(
            "pending fixture requires its isolated native domain",
        ))
    }
}
