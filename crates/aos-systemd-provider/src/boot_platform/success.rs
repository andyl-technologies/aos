//! Marks counted boots and authenticates stable boots before publishing their default.
//!
//! Systemd reports `clean` for uncounted boots and rejects `good` for them. A
//! missing counter variable also produces `clean`, so that status needs separate
//! physical identity and retained-payload checks before any default is changed.

use std::fs;
use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail, ensure};
use aos_contract::Sha256Digest;

const STATUS_BYTES: u64 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BootStatus {
    Clean,
    Counted,
}

fn parse_status(bytes: &[u8]) -> Result<BootStatus> {
    match bytes {
        b"clean\n" => Ok(BootStatus::Clean),
        b"good\n" | b"bad\n" | b"dirty\n" | b"indeterminate\n" => Ok(BootStatus::Counted),
        _ => bail!("systemd boot status is not a recognized single status"),
    }
}

pub(super) fn query_status(executable: &Path, boot_root: &str) -> Result<BootStatus> {
    let mut child = Command::new(executable)
        .env_clear()
        .args(["--path", boot_root, "status"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("observing the running boot status")?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .context("boot status has no output channel")?
        .take(STATUS_BYTES + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > STATUS_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        read.context("reading the running boot status")?;
        bail!("systemd boot status exceeds its output bound");
    }
    let status = child
        .wait()
        .context("waiting for the running boot status")?;
    ensure!(
        status.success(),
        "observing the running boot status failed with {status}"
    );
    parse_status(&bytes)
}

pub(super) fn mark(
    status: BootStatus,
    verify_clean: impl FnOnce() -> Result<()>,
    bless_counted: impl FnOnce() -> Result<()>,
    publish_default: impl FnOnce() -> Result<()>,
) -> Result<()> {
    match status {
        BootStatus::Clean => verify_clean()?,
        BootStatus::Counted => bless_counted()?,
    }
    publish_default()
}

pub(super) fn validate_identity(
    expected_entry: &str,
    selected_entry: Option<&str>,
    expected_root: &Path,
    current_root: &Path,
    expected_slot: Option<&str>,
    current_slot: &str,
) -> Result<()> {
    ensure!(
        selected_entry == Some(expected_entry),
        "clean boot selected a different entry"
    );
    ensure!(
        current_root == expected_root,
        "clean boot immutable root differs from the running generation"
    );
    ensure!(
        expected_slot == Some(current_slot),
        "clean boot slot differs from the running generation"
    );
    Ok(())
}

pub(super) fn validate_clean_payload(
    directory: &Path,
    stable: &str,
    expected: Sha256Digest,
) -> Result<()> {
    ensure!(
        super::stable_entry(stable)? == stable,
        "clean boot entry still has a counter"
    );
    let stem = stable
        .strip_suffix(".efi")
        .context("stable entry has no suffix")?;
    let mut found = false;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .context("boot payload filename is not UTF-8")?;
        if name == stable {
            ensure!(
                entry.file_type()?.is_file(),
                "clean boot payload is not a regular file"
            );
            ensure!(
                Sha256Digest::of_bytes(&fs::read(entry.path())?) == expected,
                "clean boot payload differs from authenticated retention"
            );
            found = true;
        } else if name.starts_with(&format!("{stem}+")) && name.ends_with(".efi") {
            bail!("clean boot has a competing counted payload");
        }
    }
    ensure!(found, "clean boot has no stable payload");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn status_parser_accepts_only_systemd_statuses() {
        assert_eq!(parse_status(b"clean\n").unwrap(), BootStatus::Clean);
        for bytes in [
            b"good\n".as_slice(),
            b"bad\n",
            b"dirty\n",
            b"indeterminate\n",
        ] {
            assert_eq!(parse_status(bytes).unwrap(), BootStatus::Counted);
        }
        for bytes in [
            b"".as_slice(),
            b"clean",
            b" clean\n",
            b"clean\ngood\n",
            b"unknown\n",
            &[255],
        ] {
            assert!(parse_status(bytes).is_err());
        }
    }

    #[test]
    fn clean_boot_verifies_before_publishing_without_blessing() {
        let calls = RefCell::new(Vec::new());
        mark(
            BootStatus::Clean,
            || {
                calls.borrow_mut().push("verify");
                Ok(())
            },
            || bail!("an uncounted boot must not be blessed"),
            || {
                calls.borrow_mut().push("default");
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(*calls.borrow(), ["verify", "default"]);
    }

    #[test]
    fn counted_boot_blesses_before_publishing() {
        let calls = RefCell::new(Vec::new());
        mark(
            BootStatus::Counted,
            || bail!("clean verification must not replace counted blessing"),
            || {
                calls.borrow_mut().push("good");
                Ok(())
            },
            || {
                calls.borrow_mut().push("default");
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(*calls.borrow(), ["good", "default"]);
    }

    #[test]
    fn failed_verification_or_blessing_never_publishes() {
        for status in [BootStatus::Clean, BootStatus::Counted] {
            let published = RefCell::new(false);
            let result = mark(
                status,
                || bail!("identity mismatch"),
                || bail!("blessing failed"),
                || {
                    *published.borrow_mut() = true;
                    Ok(())
                },
            );

            assert!(result.is_err());
            assert!(!*published.borrow());
        }
    }

    #[test]
    fn default_publication_failure_is_propagated() {
        for status in [BootStatus::Clean, BootStatus::Counted] {
            assert!(mark(status, || Ok(()), || Ok(()), || bail!("default failed")).is_err());
        }
    }

    #[test]
    fn clean_identity_requires_exact_entry_root_and_slot() {
        let root = Path::new("/nix/store/running-toplevel");
        validate_identity(
            "running.efi",
            Some("running.efi"),
            root,
            root,
            Some("A"),
            "A",
        )
        .unwrap();

        for selected in [None, Some("other.efi")] {
            assert!(
                validate_identity("running.efi", selected, root, root, Some("A"), "A").is_err()
            );
        }
        assert!(
            validate_identity(
                "running.efi",
                Some("running.efi"),
                root,
                Path::new("/nix/store/other-toplevel"),
                Some("A"),
                "A"
            )
            .is_err()
        );
        for slot in [None, Some("B")] {
            assert!(
                validate_identity("running.efi", Some("running.efi"), root, root, slot, "A")
                    .is_err()
            );
        }
    }

    #[test]
    fn clean_payload_requires_retained_stable_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let digest = Sha256Digest::of_bytes(b"retained UKI");
        fs::write(directory.path().join("running.efi"), b"retained UKI").unwrap();

        validate_clean_payload(directory.path(), "running.efi", digest).unwrap();
        fs::write(directory.path().join("running.efi"), b"changed UKI").unwrap();
        assert!(validate_clean_payload(directory.path(), "running.efi", digest).is_err());
        assert!(validate_clean_payload(directory.path(), "missing.efi", digest).is_err());
        assert!(validate_clean_payload(directory.path(), "running+1-2.efi", digest).is_err());
    }

    #[test]
    fn clean_payload_rejects_counted_or_ambiguous_entries() {
        let directory = tempfile::tempdir().unwrap();
        let digest = Sha256Digest::of_bytes(b"retained UKI");
        fs::write(directory.path().join("running+2-1.efi"), b"retained UKI").unwrap();

        assert!(validate_clean_payload(directory.path(), "running.efi", digest).is_err());
        fs::write(directory.path().join("running.efi"), b"retained UKI").unwrap();
        assert!(validate_clean_payload(directory.path(), "running.efi", digest).is_err());
    }

    #[test]
    fn clean_payload_rejects_symlink_substitution() {
        let directory = tempfile::tempdir().unwrap();
        let digest = Sha256Digest::of_bytes(b"retained UKI");
        fs::write(directory.path().join("other.efi"), b"retained UKI").unwrap();
        symlink("other.efi", directory.path().join("running.efi")).unwrap();

        assert!(validate_clean_payload(directory.path(), "running.efi", digest).is_err());
    }
}
