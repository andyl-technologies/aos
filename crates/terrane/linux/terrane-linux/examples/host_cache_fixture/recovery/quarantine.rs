//! Checks cold quarantine accounting without treating opaque bytes as content.

use super::{IdentityKind, Inputs, NativeMetadataOwner, STATE, TERRANE_V1, invalid};
use std::{fs, io, os::unix::fs::MetadataExt, time::UNIX_EPOCH};
use terrane_sdk::{
    host::cache::CacheState,
    store::{Clock, TokioClock, TokioLocalFs},
};

const ORIGINAL: &[u8] = b"expected original quarantine plaintext";
const CORRUPT: &[u8] = b"damaged retained quarantine plaintext";

fn name() -> io::Result<String> {
    Ok(TERRANE_V1
        .calculate(IdentityKind::Chunk, ORIGINAL)
        .map_err(io::Error::other)?
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Seeds untrusted original quarantine candidates before native roles start.
///
/// # Errors
/// Refuses unsupported domains, failed project inheritance or native durability.
pub(crate) fn seed() -> io::Result<()> {
    let inputs = Inputs::load()?;
    let encoded = inputs.domain.starts_with("tenant:quarantine-encoded-");
    let names = candidate_names(&inputs)?;
    let (uid, gid, mode) = if encoded {
        let uid = if inputs.domain == "tenant:quarantine-encoded-foreign" {
            842
        } else {
            840
        };
        let mode = match inputs.domain.as_str() {
            "tenant:quarantine-encoded-private" => 0o600,
            "tenant:quarantine-encoded-readonly" => 0o400,
            "tenant:quarantine-encoded-shared-metadata" => 0o660,
            _ => 0o640,
        };
        (uid, 845, mode)
    } else {
        let uid = if inputs.domain == "tenant:quarantine-foreign" {
            842
        } else {
            841
        };
        (uid, uid, 0o600)
    };
    for filename in names {
        super::write(
            &inputs,
            &inputs.root.join("quarantine").join(filename),
            CORRUPT,
            uid,
            gid,
            mode,
        )?;
    }
    fs::File::open(inputs.root.join("quarantine"))?.sync_all()?;
    println!("SEEDED opaque quarantine candidate; no content or recovery authority");
    Ok(())
}

/// Reconciles actual opaque custody or refuses unsupported original candidates.
///
/// # Errors
/// Refuses lost original bytes, allocation or project custody, any valid-content
/// claim over quarantine, missing genuine Resume or changed rejected policy.
pub(crate) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if original.is_some() {
        return Err(invalid(
            "quarantine fixture must begin without decoded policy",
        ));
    }
    let policy = inputs.root.join("state/cache/records.toml");
    let result = runtime.block_on(owner.recover());
    if mode == "refuse-quarantine" {
        let error = result
            .err()
            .ok_or_else(|| invalid("unsafe quarantine completed recovery"))?;
        if policy.exists() {
            return Err(invalid(
                "unsafe quarantine created a funded recovery snapshot",
            ));
        }
        println!("PASS unsafe original quarantine refused before funding or Resume: {error}");
        return Ok(());
    }
    let completed = result?;
    completed.check_current()?;
    let names = candidate_names(inputs)?;
    let mut originals = Vec::new();
    let mut allocation = 0_u64;
    for filename in names {
        let path = inputs.root.join("quarantine").join(filename);
        let before = fs::metadata(&path)?;
        let bytes = before
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| invalid("quarantine allocation overflow"))?;
        if bytes == 0 {
            return Err(invalid("quarantine candidate lacks original allocation"));
        }
        allocation = allocation
            .checked_add(bytes)
            .ok_or_else(|| invalid("quarantine allocation sum overflow"))?;
        originals.push((path, before));
    }
    if completed.synchronized_quarantined_inode_bytes() != allocation
        || completed.synchronized_quarantined_inodes() != originals.len()
        || completed.synchronized_retained_inode_bytes() < allocation
        || completed.charged_reserved_bytes() < allocation
    {
        return Err(invalid(
            "quarantine inode omitted from synchronized allocation",
        ));
    }
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("completed recovery omitted durable policy"))?;
    if !state.pins.is_empty() || !state.leases.is_empty() || !state.residences.is_empty() {
        return Err(invalid("opaque quarantine bytes became verified backing"));
    }
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, ORIGINAL)
        .map_err(io::Error::other)?;
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(30)
        .ok_or_else(|| invalid("consumer expiry overflow"))?;
    let error = runtime
        .block_on(owner.pin_resident_chunk(identity, expires))
        .err()
        .ok_or_else(|| invalid("quarantine supplied a consumer source"))?;
    if error.kind() != io::ErrorKind::NotFound {
        return Err(invalid(
            "quarantine was served or lost original native custody",
        ));
    }
    for (path, before) in originals {
        let after = fs::metadata(&path)?;
        if (after.dev(), after.ino(), after.blocks())
            != (before.dev(), before.ino(), before.blocks())
        {
            return Err(invalid(
                "original quarantine allocation changed across Resume",
            ));
        }
    }
    if inputs.domain == "tenant:quarantine-tagged" {
        println!(
            "PASS actual cold recovery retains both tagged original quarantine allocations of one hash without serving either"
        );
    }
    if inputs.domain.starts_with("tenant:quarantine-encoded-") {
        println!(
            "PASS actual cold encoded quarantine retained every original charged member across recovery and Resume without content, pins or residences"
        );
    } else {
        println!(
            "PASS actual cold quarantine retained charged original inode across recovery and Resume without content, pins or residences"
        );
    }
    Ok(())
}

/// Generates untrusted names only; native recovery must authenticate every inode.
fn candidate_names(inputs: &Inputs) -> io::Result<Vec<String>> {
    let digest = name()?;
    let tag = "35".repeat(32);
    Ok(match inputs.domain.as_str() {
        "tenant:quarantine-only" | "tenant:quarantine-foreign" => vec![digest],
        "tenant:quarantine-unknown" => vec!["unrecognized-name".to_owned()],
        "tenant:quarantine-tagged" => vec![
            format!("{digest}.{}", "13".repeat(32)),
            format!("{digest}.{}", "24".repeat(32)),
        ],
        "tenant:quarantine-encoded-chunk"
        | "tenant:quarantine-encoded-foreign"
        | "tenant:quarantine-encoded-private"
        | "tenant:quarantine-encoded-readonly" => {
            vec![format!("encoded.{digest}.0.{tag}")]
        }
        "tenant:quarantine-encoded-pack" | "tenant:quarantine-encoded-shared-metadata" => vec![
            format!("encoded.{digest}.pack.{tag}"),
            format!("encoded.{digest}.idx.{tag}"),
        ],
        "tenant:quarantine-encoded-partial" => vec![format!("encoded.{digest}.idx.{tag}")],
        "tenant:quarantine-encoded-malformed" => vec![format!("encoded.{digest}.3.{tag}")],
        _ => return Err(invalid("unknown quarantine seed domain")),
    })
}
