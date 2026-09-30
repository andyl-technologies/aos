//! Renders native configuration trees through descriptor-relative writes.
//!
//! Destination parent directories are opened without following symlinks. Store
//! directory sources are expanded so a unit directory remains mergeable in the
//! configuration overlay. Public certificate streams reject private key data.

use std::fs;
use std::io::Read as _;
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, fchmod, mkdirat, mknodat, openat, symlinkat, unlinkat,
};

use crate::model::{CertificatePart, Entry, Input};

pub(crate) fn render(input: &Input, tree: &Path) -> Result<()> {
    input.validate()?;
    let root = openat(
        rustix::fs::CWD,
        tree,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for source in &input.etc_trees {
        let directory = fs::canonicalize(&source.source)?;
        input.validate_source(
            directory
                .to_str()
                .context("source tree path is not UTF-8")?,
        )?;
        ensure!(
            directory.is_dir(),
            "configuration tree source is not a directory"
        );
        expand_directory(input, &root, &source.target, &directory)?;
    }
    let mut placeholders = Vec::new();
    for (key, script) in &input.job_scripts {
        write_file_beneath(
            &root,
            &format!("aos-job-scripts/{key}"),
            script.text.as_bytes(),
            &script.mode,
        )?;
        placeholders.push((
            format!("#aos-jobscript:{key}#"),
            format!("/etc/aos-job-scripts/{key}"),
        ));
    }
    for (target, entry) in &input.files {
        match entry {
            Entry::Text { text, mode } => write_file_beneath(
                &root,
                target,
                substitute_placeholders(text, &placeholders).as_bytes(),
                mode,
            )?,
            Entry::Symlink { target: source } => write_symlink_beneath(&root, target, source)?,
            Entry::StoreSymlink { target: source } => {
                let resolved =
                    fs::canonicalize(source).context("resolving immutable configuration source")?;
                input.validate_source(resolved.to_str().context("source path is not UTF-8")?)?;
                if resolved.is_dir() {
                    expand_directory(input, &root, target, &resolved)?;
                } else {
                    write_symlink_beneath(&root, target, source)?;
                }
            }
            Entry::StoreFile { path, mode } => {
                let resolved = fs::canonicalize(path)?;
                input.validate_source(resolved.to_str().context("source path is not UTF-8")?)?;
                ensure!(
                    resolved.is_file(),
                    "configuration source is not a regular file"
                );
                write_file_beneath(&root, target, &fs::read(resolved)?, mode)?;
            }
            Entry::CertificateBundle { parts, mode } => {
                let bundle = certificate_bundle(parts)?;
                write_file_beneath(&root, target, &bundle, mode)?;
            }
        }
    }
    for target in &input.removed_paths {
        ensure!(
            !input.files.contains_key(target),
            "removed path also has desired content"
        );
        let (parent, name) = open_parent_beneath(&root, target)?;
        unlink_file_if_present(&parent, &name)?;
        // Overlayfs interprets a character-device 0:0 lower entry as a whiteout.
        // It keeps an image-owned file absent without mutating that image.
        mknodat(
            &parent,
            name,
            FileType::CharacterDevice,
            Mode::from_raw_mode(0o000),
            0,
        )?;
    }
    Ok(())
}

fn expand_directory(input: &Input, root: &OwnedFd, target: &str, source: &Path) -> Result<()> {
    expand_directory_at(input, root, target, source, &mut Vec::new())
}

fn expand_directory_at(
    input: &Input,
    root: &OwnedFd,
    target: &str,
    source: &Path,
    ancestors: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    let canonical = fs::canonicalize(source)?;
    ensure!(
        ancestors.len() < 64 && !ancestors.contains(&canonical),
        "configuration source contains a directory cycle"
    );
    input.validate_source(canonical.to_str().context("source path is not UTF-8")?)?;
    ancestors.push(canonical);
    let (parent, name) = open_parent_beneath(root, target)?;
    match mkdirat(&parent, &name, Mode::from_raw_mode(0o755)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    let _directory = openat(
        &parent,
        &name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("configuration source name is not UTF-8"))?;
        let destination = format!("{target}/{name}");
        crate::model::validate_relative(&destination)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            expand_directory_at(input, root, &destination, &path, ancestors)?;
        } else if metadata.file_type().is_symlink()
            && fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir())
        {
            let resolved = fs::canonicalize(&path)?;
            input.validate_source(
                resolved
                    .to_str()
                    .context("source directory path is not UTF-8")?,
            )?;
            expand_directory_at(input, root, &destination, &resolved, ancestors)?;
        } else if metadata.is_file() || metadata.file_type().is_symlink() {
            // The admitted source object owns this member and its references.
            // Linking its member preserves that authority instead of adopting
            // a foreign canonical target from an embedded leaf symlink.
            write_symlink_beneath(
                root,
                &destination,
                path.to_str().context("source member path is not UTF-8")?,
            )?;
        } else {
            bail!("configuration source contains a special file");
        }
    }
    ancestors.pop();
    Ok(())
}

fn substitute_placeholders(body: &str, replacements: &[(String, String)]) -> String {
    let mut out = body.to_string();
    for (placeholder, path) in replacements {
        if out.contains(placeholder.as_str()) {
            out = out.replace(placeholder.as_str(), path);
        }
    }
    out
}

/// Writes `contents` to `dest` with octal `mode`, creating parent directories.
/// Overwrites any existing file (idempotent re-materialization).
///
/// # Errors
///
/// Returns an error if `mode` is not a valid octal string or any filesystem
/// operation fails.
fn write_file_beneath(root: &OwnedFd, path: &str, contents: &[u8], mode: &str) -> Result<()> {
    let perm = parse_octal_mode(mode)?;
    let (parent, name) = open_parent_beneath(root, path)?;
    unlink_file_if_present(&parent, &name)?;
    let fd = openat(
        &parent,
        &name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(perm as _),
    )
    .with_context(|| format!("creating {path:?} beneath materialization root"))?;
    let mut file = std::fs::File::from(fd);
    file.write_all(contents)
        .with_context(|| format!("writing {path:?} beneath materialization root"))?;
    fchmod(&file, Mode::from_raw_mode(perm as _))
        .with_context(|| format!("chmod {perm:o} {path:?}"))?;
    Ok(())
}

fn write_symlink_beneath(root: &OwnedFd, path: &str, target: &str) -> Result<()> {
    let (parent, name) = open_parent_beneath(root, path)?;
    unlink_file_if_present(&parent, &name)?;
    symlinkat(target, &parent, &name)
        .with_context(|| format!("symlink {path:?} -> {target:?} beneath materialization root"))?;
    Ok(())
}

fn open_parent_beneath(root: &OwnedFd, path: &str) -> Result<(OwnedFd, String)> {
    let mut components = path.split('/').collect::<Vec<_>>();
    let name = components
        .pop()
        .context("materialization path has no final component")?
        .to_string();
    let mut directory = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for component in components {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        match openat(&directory, component, flags, Mode::empty()) {
            Ok(next) => directory = next,
            Err(error) if error == rustix::io::Errno::NOENT => {
                match mkdirat(&directory, component, Mode::from_raw_mode(0o755)) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(error.into()),
                }
                directory = openat(&directory, component, flags, Mode::empty())
                    .with_context(|| format!("opening materialization directory {component:?}"))?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("refusing non-directory or symlink component {component:?}")
                });
            }
        }
    }
    Ok((directory, name))
}

fn unlink_file_if_present(parent: &OwnedFd, name: &str) -> Result<()> {
    match unlinkat(parent, name, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::NOENT => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Parses a 3- or 4-digit octal mode string (e.g. `"0644"`) into a `u32`.
///
/// # Errors
///
/// Returns an error if `mode` is not valid octal.
fn parse_octal_mode(mode: &str) -> Result<u32> {
    u32::from_str_radix(mode, 8).with_context(|| format!("invalid octal mode {mode:?}"))
}

/// Assembles an ordered certificate-only PEM bundle for image and native use.
///
/// Preserves duplicate certificates and source bytes. File sources must be
/// regular files beneath an immutable store root; callers authenticate these
/// roots before invoking the renderer.
///
/// # Errors
/// Returns an error for an empty or oversized source list, non-store or unsafe
/// file paths, unreadable files, oversized content, or invalid certificate PEM.
pub fn certificate_bundle(parts: &[CertificatePart]) -> Result<Vec<u8>> {
    const MAX_BYTES: usize = 16 * 1024 * 1024;
    ensure!(
        !parts.is_empty() && parts.len() <= 4096,
        "certificate source count is outside its bound"
    );
    let mut bundle = Vec::new();
    for part in parts {
        let bytes = match part {
            CertificatePart::Text { text } => {
                ensure!(
                    text.len() <= MAX_BYTES,
                    "certificate source exceeds its byte bound"
                );
                text.as_bytes().to_vec()
            }
            CertificatePart::StoreFile { path } => {
                ensure!(
                    path.starts_with("/nix/store/")
                        && path
                            .split('/')
                            .skip(1)
                            .all(|part| !matches!(part, "" | "." | "..")),
                    "certificate source is not a normalized store path"
                );
                let metadata = fs::symlink_metadata(path)?;
                ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "certificate source is not a regular retained file"
                );
                let mut bytes = Vec::new();
                fs::File::open(path)?
                    .take(MAX_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)?;
                bytes
            }
        };
        ensure!(
            bytes.len() <= MAX_BYTES - bundle.len(),
            "certificate bundle exceeds its byte bound"
        );
        validate_certificate_pem(&bytes)?;
        bundle.extend_from_slice(&bytes);
    }
    Ok(bundle)
}

fn validate_certificate_pem(bytes: &[u8]) -> Result<()> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";

    let mut rest = trim_ascii_whitespace(bytes);
    let mut count = 0usize;
    while !rest.is_empty() {
        let encoded = rest
            .strip_prefix(BEGIN)
            .context("certificate PEM input contains non-certificate data")?;
        let end = find_bytes(encoded, END).context("certificate PEM input has no end marker")?;
        let body = &encoded[..end];
        let body = body
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        if body.is_empty()
            || !body
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            bail!("certificate PEM input has invalid base64 data");
        }
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .context("decoding certificate PEM input")?;
        validate_der_certificate(&der)?;
        count = count.saturating_add(1);
        rest = trim_ascii_whitespace(&encoded[end + END.len()..]);
    }
    if count == 0 {
        bail!("certificate PEM input has no certificates");
    }
    Ok(())
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

/// Checks the outer X.509 DER shape: `SEQUENCE { SEQUENCE, SEQUENCE,
/// BIT STRING }`. Signature verification is deliberately left to TLS clients;
/// this boundary only ensures the public certificate channel cannot carry an
/// unrelated plaintext or private-key payload.
fn validate_der_certificate(der: &[u8]) -> Result<()> {
    let (tag, certificate, rest) = der_tlv(der)?;
    if tag != 0x30 || !rest.is_empty() {
        bail!("certificate PEM input is not one DER certificate");
    }
    let (tbs_tag, _, certificate) = der_tlv(certificate)?;
    let (algorithm_tag, _, certificate) = der_tlv(certificate)?;
    let (signature_tag, signature, certificate) = der_tlv(certificate)?;
    if tbs_tag != 0x30
        || algorithm_tag != 0x30
        || signature_tag != 0x03
        || signature.is_empty()
        || signature[0] > 7
        || !certificate.is_empty()
    {
        bail!("certificate PEM input has an invalid X.509 DER shape");
    }
    Ok(())
}

fn der_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, after_tag) = input
        .split_first()
        .context("certificate DER is truncated before its tag")?;
    let (&first_length, after_length) = after_tag
        .split_first()
        .context("certificate DER is truncated before its length")?;
    let (length, body) = if first_length & 0x80 == 0 {
        (usize::from(first_length), after_length)
    } else {
        let width = usize::from(first_length & 0x7f);
        if width == 0 || width > std::mem::size_of::<usize>() || after_length.len() < width {
            bail!("certificate DER has an invalid length");
        }
        let mut length = 0usize;
        for byte in &after_length[..width] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .context("certificate DER length overflows")?;
        }
        (length, &after_length[width..])
    };
    if body.len() < length {
        bail!("certificate DER body is truncated");
    }
    Ok((tag, &body[..length], &body[length..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{JobScript, Ownership};
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;

    fn input() -> Input {
        Input {
            etc_trees: Vec::new(),
            files: BTreeMap::from([(
                "app/config".into(),
                Entry::Text {
                    text: "Exec=#aos-jobscript:start#".into(),
                    mode: "0444".into(),
                },
            )]),
            job_scripts: BTreeMap::from([(
                "start".into(),
                JobScript {
                    text: "immutable interpreter".into(),
                    mode: "0555".into(),
                    name: None,
                },
            )]),
            removed_paths: Vec::new(),
            baseline_paths: Vec::new(),
            baseline_inventory: None,
            ownership: Ownership {
                etc_trees: BTreeMap::new(),
                files: BTreeMap::from([("app/config".into(), "app".into())]),
                job_scripts: BTreeMap::from([("start".into(), "app".into())]),
            },
            store_paths: Vec::new(),
            retained_root: "/var/lib/aos/configuration-lowers".into(),
        }
    }

    #[test]
    fn renders_owned_files_and_retained_script_references() {
        let tree = tempfile::tempdir().unwrap();
        render(&input(), tree.path()).unwrap();

        assert_eq!(
            fs::read_to_string(tree.path().join("app/config")).unwrap(),
            "Exec=/etc/aos-job-scripts/start"
        );
        assert_eq!(
            fs::metadata(tree.path().join("aos-job-scripts/start"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
    }

    #[test]
    fn refuses_destination_symlink_escape() {
        let tree = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), tree.path().join("app")).unwrap();

        assert!(render(&input(), tree.path()).is_err());
        assert!(!outside.path().join("config").exists());
    }

    #[test]
    fn rejects_private_key_certificate_stream() {
        let tree = tempfile::tempdir().unwrap();
        let mut input = input();
        input.files.insert(
            "app/config".into(),
            Entry::CertificateBundle {
                parts: vec![CertificatePart::Text {
                    text: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n".into(),
                }],
                mode: "0444".into(),
            },
        );

        assert!(render(&input, tree.path()).is_err());
    }

    #[test]
    fn image_and_native_bundles_preserve_order_and_duplicates() {
        let certificate = "-----BEGIN CERTIFICATE-----\nMAcwADAAAwEA\n-----END CERTIFICATE-----\n";
        let parts = vec![
            CertificatePart::Text {
                text: certificate.into(),
            },
            CertificatePart::Text {
                text: format!("\n{certificate}"),
            },
        ];
        let expected = format!("{certificate}\n{certificate}").into_bytes();
        let mut input = input();
        input.files.insert(
            "app/config".into(),
            Entry::CertificateBundle {
                parts: parts.clone(),
                mode: "0444".into(),
            },
        );
        let tree = tempfile::tempdir().unwrap();

        render(&input, tree.path()).unwrap();

        assert_eq!(certificate_bundle(&parts).unwrap(), expected);
        assert_eq!(fs::read(tree.path().join("app/config")).unwrap(), expected);
    }

    #[test]
    fn certificate_bundle_rejects_empty_unsafe_and_malformed_inputs() {
        assert!(certificate_bundle(&[]).is_err());
        assert!(
            certificate_bundle(&[CertificatePart::StoreFile {
                path: "/etc/ssl/cert.pem".into()
            }])
            .is_err()
        );
        assert!(
            certificate_bundle(&[CertificatePart::Text {
                text: "-----BEGIN CERTIFICATE-----\ntruncated\n".into()
            }])
            .is_err()
        );
    }
}
