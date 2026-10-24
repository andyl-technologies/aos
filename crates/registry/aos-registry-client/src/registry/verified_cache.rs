//! Local graph-verification receipts bound to the complete object database.
//!
//! The JSON receipt contains a format version, decoder identity, database digest,
//! verified object IDs, and a checksum of those fields. It is an optimization of
//! local integrity checks, never an authority for signatures or release freshness.
//! Any unreadable, unsupported, or changed database requires ordinary verification.
//!
//! ```json
//! {"proof":{"version":1,"decoder":"version:libgit2","database":"sha256",
//!           "objects":["object-id"]},"checksum":"sha256-of-proof-json"}
//! ```

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RECEIPT: &str = "apm-verified-objects-v1.json";
const MAX_RECEIPT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Proof {
    version: u32,
    decoder: String,
    database: String,
    objects: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Receipt {
    proof: Proof,
    checksum: String,
}

fn decoder() -> String {
    // Include the application version as well as the underlying object decoder.
    format!(
        "{}:{:?}",
        env!("CARGO_PKG_VERSION"),
        git2::Version::get().libgit2_version()
    )
}

/// Hashes database bytes and lookup configuration, declining external object stores.
///
/// # Errors
/// Returns an error for inaccessible files, symlinks, or alternate object stores.
pub(super) fn fingerprint(repo_dir: &Path) -> Result<String> {
    ensure!(
        std::env::var_os("GIT_OBJECT_DIRECTORY").is_none(),
        "external object directory"
    );
    ensure!(
        std::env::var_os("GIT_ALTERNATE_OBJECT_DIRECTORIES").is_none(),
        "external alternates"
    );
    let objects = super::repo::objects_dir(repo_dir)?;
    ensure!(
        !objects.join("info/alternates").exists(),
        "alternate object database"
    );
    ensure!(
        !objects.join("info/http-alternates").exists(),
        "HTTP alternate object database"
    );
    let mut digest = Sha256::new();
    hash_entry(&objects, &mut digest)?;
    hash_entry(&repo_dir.join("config"), &mut digest)?;
    Ok(format!("{:x}", digest.finalize()))
}

fn hash_entry(path: &Path, digest: &mut Sha256) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "symlink in object database"
    );
    if metadata.is_dir() {
        digest.update(b"directory");
        let mut entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        digest.update((entries.len() as u64).to_le_bytes());
        for entry in entries {
            let name = entry.file_name();
            let name = name.as_bytes();
            digest.update((name.len() as u64).to_le_bytes());
            digest.update(name);
            hash_entry(&entry.path(), digest)?;
        }
    } else {
        ensure!(metadata.is_file(), "nonregular object database entry");
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        ensure!(
            file.metadata()?.is_file(),
            "nonregular object database entry"
        );
        digest.update(b"file");
        digest.update(metadata.len().to_le_bytes());
        let mut buffer = [0; 65536];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
    }
    Ok(())
}

/// Loads a receipt only when its owner, decoder, checksum, and database match.
///
/// # Errors
/// Returns an error for missing, corrupt, or stale receipts; callers must rescan.
pub(super) fn load(repo_dir: &Path, database: &str) -> Result<HashSet<git2::Oid>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(repo_dir.join(RECEIPT))?;
    let metadata = file.metadata()?;
    let directory = fs::metadata(repo_dir)?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_RECEIPT_BYTES,
        "invalid receipt file"
    );
    ensure!(
        metadata.uid() == directory.uid()
            && metadata.mode() & 0o022 == 0
            && directory.mode() & 0o022 == 0,
        "unprotected verification receipt"
    );
    let receipt: Receipt =
        serde_json::from_reader(BufReader::new(file.take(MAX_RECEIPT_BYTES + 1)))?;
    ensure!(
        receipt.proof.version == 1
            && receipt.proof.decoder == decoder()
            && receipt.proof.database == database,
        "stale verification receipt"
    );
    let bytes = serde_json::to_vec(&receipt.proof)?;
    ensure!(
        receipt.checksum == format!("{:x}", Sha256::digest(bytes)),
        "damaged verification receipt"
    );
    receipt
        .proof
        .objects
        .iter()
        .map(|id| {
            let format = match id.len() {
                40 => git2::ObjectFormat::Sha1,
                64 => git2::ObjectFormat::Sha256,
                _ => anyhow::bail!("invalid cached object ID"),
            };
            Ok(git2::Oid::from_str_ext(id, format)?)
        })
        .collect()
}

/// Atomically saves a proof after the caller rechecks the database fingerprint.
///
/// # Errors
/// Returns an error if serialization or atomic receipt replacement fails.
pub(super) fn save(repo_dir: &Path, database: String, verified: &HashSet<git2::Oid>) -> Result<()> {
    let mut objects: Vec<_> = verified.iter().map(ToString::to_string).collect();
    objects.sort();
    let proof = Proof {
        version: 1,
        decoder: decoder(),
        database,
        objects,
    };
    let checksum = format!("{:x}", Sha256::digest(serde_json::to_vec(&proof)?));
    let mut temporary = tempfile::NamedTempFile::new_in(repo_dir)?;
    {
        let mut writer = BufWriter::new(temporary.as_file_mut());
        serde_json::to_writer(&mut writer, &Receipt { proof, checksum })?;
        writer.flush()?;
    }
    temporary.persist(repo_dir.join(RECEIPT))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn damaged_and_unsupported_receipts_are_ignored() {
        let temporary = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init_bare(temporary.path()).unwrap();
        let blob = repo.blob(b"payload").unwrap();
        let verified = HashSet::from([blob]);
        let database = fingerprint(temporary.path()).unwrap();
        save(temporary.path(), database.clone(), &verified).unwrap();
        assert_eq!(load(temporary.path(), &database).unwrap(), verified);

        let path = temporary.path().join(RECEIPT);
        let original = fs::read(&path).unwrap();
        let mut receipt: Receipt = serde_json::from_slice(&original).unwrap();
        receipt.proof.objects.clear();
        fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(load(temporary.path(), &database).is_err());

        receipt.proof.decoder = "different decoder".to_owned();
        receipt.checksum = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&receipt.proof).unwrap())
        );
        fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        assert!(load(temporary.path(), &database).is_err());

        fs::write(&path, b"incomplete JSON").unwrap();
        assert!(load(temporary.path(), &database).is_err());
    }

    #[test]
    fn pack_indices_configuration_and_alternates_invalidate_fingerprint() {
        let temporary = tempfile::tempdir().unwrap();
        git2::Repository::init_bare(temporary.path()).unwrap();
        let pack = temporary.path().join("objects/pack/example.pack");
        let index = pack.with_extension("idx");
        fs::write(&pack, b"pack bytes").unwrap();
        fs::write(&index, b"index bytes").unwrap();
        let before = fingerprint(temporary.path()).unwrap();

        fs::write(&index, b"other bytes").unwrap();
        assert_ne!(fingerprint(temporary.path()).unwrap(), before);
        fs::write(&index, b"index bytes").unwrap();
        assert_eq!(fingerprint(temporary.path()).unwrap(), before);
        fs::write(&pack, b"changed pack").unwrap();
        assert_ne!(fingerprint(temporary.path()).unwrap(), before);
        fs::write(&pack, b"pack bytes").unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(temporary.path().join("config"))
            .unwrap()
            .write_all(b"\n# changed\n")
            .unwrap();
        assert_ne!(fingerprint(temporary.path()).unwrap(), before);

        fs::write(
            temporary.path().join("objects/info/alternates"),
            b"/external",
        )
        .unwrap();
        assert!(fingerprint(temporary.path()).is_err());
    }
}
