//! Reads exact registered closure inventories from immutable initrds and UKIs.
//!
//! Only the newc registration member is buffered. Other archive members are
//! scanned without extraction, retaining the PE and compressed input unchanged.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use aos_release::artifact::require_store_path;

const MAX_REGISTRATION_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const REGISTRATION_MEMBER: &str = "lib/aos/initrd/registration";

/// Returns registered roots from the UKI's selected initrd.
///
/// The archive is read without extraction or target execution. Malformed PE,
/// compressed data, newc records, or registration records are refused before
/// the inventory can be used as evidence of candidate closure membership.
/// Signature and candidate identity verification belong to the calling stage.
///
/// # Errors
/// Returns an error for unreadable or malformed inputs, exceeded scan or
/// document bounds, missing registration, or invalid registration records.
pub(crate) fn registered_roots(uki: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut file = File::open(uki).context("opening immutable candidate UKI")?;
    let range = aos_boot_identity::pe::section_range(&mut file, "initrd")?
        .context("candidate UKI has no initrd section")?;
    ensure!(
        range.length != 0,
        "candidate UKI has an empty initrd section"
    );
    file.seek(SeekFrom::Start(range.offset))?;

    let decoder = zstd::stream::read::Decoder::new(file.take(range.length))
        .context("opening candidate initrd zstd stream")?;
    registration_from_archive(decoder)
}

/// Returns registered roots from an immutable compressed initrd.
///
/// This uses the same bounded archive and registration validation as the UKI
/// reader, without requiring bootstrap evidence to duplicate UKI metadata.
/// Authentication of the selected running toplevel belongs to the caller.
///
/// # Errors
/// Returns an error for unreadable or malformed inputs, exceeded scan or
/// document bounds, missing registration, or invalid registration records.
pub(crate) fn registered_initrd_roots(initrd: &Path) -> Result<BTreeSet<PathBuf>> {
    let file = File::open(initrd).context("opening immutable running initrd")?;
    let decoder =
        zstd::stream::read::Decoder::new(file).context("opening running initrd zstd stream")?;
    registration_from_archive(decoder)
}

struct ArchiveReader<R> {
    input: R,
    scanned: u64,
}

impl<R: Read> ArchiveReader<R> {
    fn read_exact(&mut self, bytes: &mut [u8]) -> Result<()> {
        let length = u64::try_from(bytes.len())?;
        ensure!(
            length <= MAX_ARCHIVE_BYTES.saturating_sub(self.scanned),
            "candidate initrd exceeds archive scan bound"
        );
        self.input
            .read_exact(bytes)
            .context("truncated candidate initrd archive")?;
        self.scanned += length;
        Ok(())
    }

    fn padding(&mut self, length: u64) -> Result<()> {
        let count = usize::try_from((4 - length % 4) % 4)?;
        let mut bytes = [0_u8; 3];
        self.read_exact(&mut bytes[..count])?;
        ensure!(
            bytes[..count].iter().all(|byte| *byte == 0),
            "candidate initrd has nonzero newc padding"
        );
        Ok(())
    }

    fn skip(&mut self, mut length: u64) -> Result<()> {
        let mut bytes = [0_u8; 64 * 1024];
        while length != 0 {
            let count = usize::try_from(length.min(bytes.len() as u64))?;
            self.read_exact(&mut bytes[..count])?;
            length -= count as u64;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        let mut bytes = [0_u8; 4096];
        loop {
            let count = self.input.read(&mut bytes)?;
            if count == 0 {
                return Ok(());
            }
            ensure!(
                count as u64 <= MAX_ARCHIVE_BYTES.saturating_sub(self.scanned),
                "candidate initrd exceeds archive scan bound"
            );
            self.scanned += count as u64;
            ensure!(
                bytes[..count].iter().all(|byte| *byte == 0),
                "candidate initrd has data after its newc trailer"
            );
        }
    }
}

fn registration_from_archive(input: impl Read) -> Result<BTreeSet<PathBuf>> {
    let mut archive = ArchiveReader { input, scanned: 0 };
    let mut registration = None;
    loop {
        let mut header = [0_u8; 110];
        archive.read_exact(&mut header)?;
        ensure!(&header[..6] == b"070701", "candidate initrd is not newc");
        let mut fields = [0_u32; 13];
        for (index, field) in fields.iter_mut().enumerate() {
            let start = 6 + index * 8;
            let value = std::str::from_utf8(&header[start..start + 8])?;
            ensure!(
                value.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "candidate initrd has a malformed newc header"
            );
            *field = u32::from_str_radix(value, 16)?;
        }
        ensure!(fields[12] == 0, "newc checksum must be zero");
        let size = u64::from(fields[6]);
        let name_size = usize::try_from(fields[11])?;
        ensure!(
            (2..=4096).contains(&name_size),
            "candidate initrd has an invalid member name size"
        );
        let mut name = vec![0_u8; name_size];
        archive.read_exact(&mut name)?;
        ensure!(name.pop() == Some(0), "newc member name lacks terminator");
        ensure!(!name.contains(&0), "newc member name contains NUL");
        let name = std::str::from_utf8(&name)?;
        archive.padding(110 + name_size as u64)?;
        ensure!(
            size <= MAX_ARCHIVE_BYTES.saturating_sub(archive.scanned),
            "candidate initrd member exceeds archive scan bound"
        );

        if name == "TRAILER!!!" {
            ensure!(size == 0, "newc trailer contains payload");
            archive.finish()?;
            break;
        }
        let normalized = name.strip_prefix("./").unwrap_or(name);
        ensure!(
            normalized == "."
                || (!normalized.is_empty()
                    && normalized
                        .split('/')
                        .all(|part| { !part.is_empty() && !matches!(part, "." | "..") })),
            "candidate initrd member name is not confined"
        );
        if normalized == REGISTRATION_MEMBER {
            ensure!(
                registration.is_none(),
                "duplicate initrd registration member"
            );
            ensure!(
                fields[1] & 0o170000 == 0o100000 && fields[4] == 1,
                "initrd registration member is not an independent regular file"
            );
            ensure!(
                size <= MAX_REGISTRATION_BYTES,
                "initrd registration exceeds document bound"
            );
            let mut bytes = vec![0_u8; usize::try_from(size)?];
            archive.read_exact(&mut bytes)?;
            registration = Some(bytes);
        } else {
            archive.skip(size)?;
        }
        archive.padding(size)?;
    }
    parse_registration(&registration.context("initrd registration member is missing")?)
}

fn unsigned_decimal(value: &str) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "registration integer is not unsigned decimal"
    );
    Ok(value.parse()?)
}

fn parse_registration(bytes: &[u8]) -> Result<BTreeSet<PathBuf>> {
    let text = std::str::from_utf8(bytes).context("registration is not UTF-8")?;
    ensure!(
        !text.contains('\r'),
        "registration uses noncanonical line endings"
    );
    ensure!(
        text.ends_with('\n'),
        "registration lacks final line terminator"
    );
    let mut lines = text.lines();
    let mut roots = BTreeSet::new();
    let mut records = BTreeSet::new();
    let mut references = BTreeSet::new();
    while let Some(root) = lines.next() {
        require_store_path(root, false).context("invalid registered store root")?;
        ensure!(records.insert(root), "duplicate registered store root");
        roots.insert(PathBuf::from(root));
        let hash = lines.next().context("registration lacks NAR hash")?;
        let encoded = hash
            .strip_prefix("sha256:")
            .context("invalid NAR hash algorithm")?;
        const BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
        ensure!(
            (encoded.len() == 52 && encoded.bytes().all(|byte| BASE32.contains(&byte)))
                || (encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit())),
            "invalid registration NAR hash"
        );
        let size = unsigned_decimal(lines.next().context("registration lacks NAR size")?)?;
        ensure!(size != 0, "registration has an empty NAR");
        let deriver = lines.next().context("registration lacks deriver field")?;
        if !deriver.is_empty() {
            require_store_path(deriver, true).context("invalid registration deriver")?;
        }
        let count = unsigned_decimal(lines.next().context("registration lacks reference count")?)?;
        ensure!(
            count <= MAX_REGISTRATION_BYTES,
            "registration reference count is excessive"
        );
        for _ in 0..count {
            let reference = lines
                .next()
                .context("registration lacks declared reference")?;
            require_store_path(reference, false).context("invalid registered reference")?;
            references.insert(PathBuf::from(reference));
        }
    }
    if records.is_empty() {
        bail!("initrd registration inventory is empty");
    }
    ensure!(
        references.is_subset(&roots),
        "initrd registration contains an unregistered reference"
    );
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/nix/store/00000000000000000000000000000000-root";
    const REFERENCE: &str = "/nix/store/11111111111111111111111111111111-reference";

    fn registration() -> Vec<u8> {
        format!(
            "{ROOT}\nsha256:{hash}\n123\n\n1\n{REFERENCE}\n{REFERENCE}\nsha256:{hash}\n456\n\n0\n",
            hash = "0".repeat(52)
        )
        .into_bytes()
    }

    fn member(archive: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
        archive.extend_from_slice(b"070701");
        for field in [
            1,
            mode,
            0,
            0,
            1,
            0,
            data.len() as u32,
            0,
            0,
            0,
            0,
            name.len() as u32 + 1,
            0,
        ] {
            archive.extend_from_slice(format!("{field:08x}").as_bytes());
        }
        archive.extend_from_slice(name.as_bytes());
        archive.push(0);
        while archive.len() % 4 != 0 {
            archive.push(0);
        }
        archive.extend_from_slice(data);
        while archive.len() % 4 != 0 {
            archive.push(0);
        }
    }

    fn archive() -> Vec<u8> {
        let mut bytes = Vec::new();
        member(
            &mut bytes,
            "./etc/unselected",
            0o100444,
            b"not registration",
        );
        member(
            &mut bytes,
            "./lib/aos/initrd/registration",
            0o100444,
            &registration(),
        );
        member(&mut bytes, "TRAILER!!!", 0, b"");
        bytes
    }

    #[test]
    fn selects_registration_and_collects_exact_roots_and_references() {
        let compressed = zstd::stream::encode_all(&archive()[..], 1).unwrap();
        let decoder = zstd::stream::read::Decoder::new(&compressed[..]).unwrap();
        assert_eq!(
            registration_from_archive(decoder).unwrap(),
            BTreeSet::from([PathBuf::from(ROOT), PathBuf::from(REFERENCE)])
        );
    }

    #[test]
    fn reads_direct_initrd_without_changing_input() {
        let compressed = zstd::stream::encode_all(&archive()[..], 1).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("initrd");
        std::fs::write(&path, &compressed).unwrap();

        let roots = registered_initrd_roots(&path).unwrap();

        assert_eq!(
            roots,
            BTreeSet::from([PathBuf::from(ROOT), PathBuf::from(REFERENCE)])
        );
        assert_eq!(std::fs::read(&path).unwrap(), compressed);
    }

    #[test]
    fn reads_only_selected_uki_section_without_changing_signed_input() {
        let compressed = zstd::stream::encode_all(&archive()[..], 1).unwrap();
        let offset = 128_usize;
        let mut image = vec![0_u8; offset];
        image[..2].copy_from_slice(b"MZ");
        image[60..64].copy_from_slice(&64_u32.to_le_bytes());
        image[64..68].copy_from_slice(b"PE\0\0");
        image[70..72].copy_from_slice(&1_u16.to_le_bytes());
        image[88..95].copy_from_slice(b".initrd");
        image[96..100].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
        image[104..108].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
        image[108..112].copy_from_slice(&(offset as u32).to_le_bytes());
        image.extend_from_slice(&compressed);
        image.extend_from_slice(b"signature-sentinel-outside-section");
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.efi");
        std::fs::write(&path, &image).unwrap();

        let roots = registered_roots(&path).unwrap();

        assert_eq!(
            roots,
            BTreeSet::from([PathBuf::from(ROOT), PathBuf::from(REFERENCE)])
        );
        assert_eq!(std::fs::read(&path).unwrap(), image);
    }

    #[test]
    fn refuses_missing_duplicate_and_nonregular_registration() {
        let mut missing = Vec::new();
        member(&mut missing, "TRAILER!!!", 0, b"");
        assert!(registration_from_archive(&missing[..]).is_err());

        let mut duplicate = Vec::new();
        for _ in 0..2 {
            member(
                &mut duplicate,
                REGISTRATION_MEMBER,
                0o100444,
                &registration(),
            );
        }
        member(&mut duplicate, "TRAILER!!!", 0, b"");
        assert!(registration_from_archive(&duplicate[..]).is_err());

        let mut symlink = Vec::new();
        member(&mut symlink, REGISTRATION_MEMBER, 0o120777, b"elsewhere");
        member(&mut symlink, "TRAILER!!!", 0, b"");
        assert!(registration_from_archive(&symlink[..]).is_err());
    }

    #[test]
    fn refuses_malformed_truncated_names_and_padding() {
        let valid = archive();
        for length in [0, 5, 109, valid.len() - 1] {
            assert!(registration_from_archive(&valid[..length]).is_err());
        }
        let mut invalid = valid.clone();
        invalid[6] = b'g';
        assert!(registration_from_archive(&invalid[..]).is_err());

        let mut traversal = Vec::new();
        member(&mut traversal, "../outside", 0o100444, b"");
        assert!(registration_from_archive(&traversal[..]).is_err());

        let mut padding = Vec::new();
        member(&mut padding, "a", 0o100444, b"x");
        *padding.last_mut().unwrap() = 1;
        member(&mut padding, "TRAILER!!!", 0, b"");
        assert!(registration_from_archive(&padding[..]).is_err());
    }

    #[test]
    fn refuses_invalid_registration_records() {
        for data in [
            Vec::new(),
            registration().strip_suffix(b"\n").unwrap().to_vec(),
            format!("{ROOT}\nsha256:{}\n123\n\n1\n", "0".repeat(52)).into_bytes(),
            String::from_utf8(registration())
                .unwrap()
                .replace(REFERENCE, "/etc/foreign")
                .into_bytes(),
            String::from_utf8(registration())
                .unwrap()
                .replace("sha256:", "sha1:")
                .into_bytes(),
            String::from_utf8(registration())
                .unwrap()
                .replace("123", "-1")
                .into_bytes(),
        ] {
            assert!(parse_registration(&data).is_err());
        }
    }

    #[test]
    fn refuses_registration_bound_and_duplicate_records() {
        let mut oversized = Vec::new();
        member(&mut oversized, REGISTRATION_MEMBER, 0o100444, b"");
        oversized[54..62].copy_from_slice(format!("{:08x}", MAX_REGISTRATION_BYTES + 1).as_bytes());
        assert!(registration_from_archive(&oversized[..]).is_err());

        let mut duplicate = registration();
        duplicate.extend_from_slice(&registration());
        assert!(parse_registration(&duplicate).is_err());
    }

    #[test]
    fn refuses_dangling_references_but_accepts_registered_self_reference() {
        let dangling = format!("{ROOT}\nsha256:{}\n123\n\n1\n{REFERENCE}\n", "0".repeat(52));
        assert!(parse_registration(dangling.as_bytes()).is_err());

        let self_reference = dangling.replace(REFERENCE, ROOT);
        assert_eq!(
            parse_registration(self_reference.as_bytes()).unwrap(),
            BTreeSet::from([PathBuf::from(ROOT)])
        );
    }
}
