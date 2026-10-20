//! Exercises the installed boot-identity command surface with real PE files.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use aos_boot_identity::pe::{MAX_IDENTITY_TEXT_BYTES, copy_section};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "aos-boot-identity-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn write(&self, payload: &[u8], machine: u16, section: &str) -> PathBuf {
        let offset = 512_usize;
        let mut bytes = vec![0_u8; offset + payload.len()];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64_u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[68..70].copy_from_slice(&machine.to_le_bytes());
        bytes[70..72].copy_from_slice(&1_u16.to_le_bytes());
        bytes[84..86].copy_from_slice(&240_u16.to_le_bytes());
        bytes[88..90].copy_from_slice(&0x20b_u16.to_le_bytes());
        let header = 328;
        bytes[header..header + section.len()].copy_from_slice(section.as_bytes());
        bytes[header + 8..header + 12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[header + 16..header + 20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[header + 20..header + 24].copy_from_slice(&(offset as u32).to_le_bytes());
        bytes[offset..].copy_from_slice(payload);
        let path = self.0.join("test.efi");
        fs::write(&path, bytes).unwrap();
        path
    }

    fn read(&self, section: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_aos-boot-identity"))
            .args(["read-uki-section", "--uki"])
            .arg(self.0.join("test.efi"))
            .args(["--section", section])
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn both_efi_architectures_emit_exact_required_text_without_added_newline() {
    for machine in [0x8664, 0xaa64] {
        for (section, payload, expected) in [
            (
                ".cmdline",
                &b"console=ttyS0 aos.recovery=1\0\0"[..],
                &b"console=ttyS0 aos.recovery=1"[..],
            ),
            (
                ".osrel",
                &b"VERSION_ID=1\nAOS_RECOVERY_COPY=a\n\0"[..],
                &b"VERSION_ID=1\nAOS_RECOVERY_COPY=a\n"[..],
            ),
        ] {
            let fixture = Fixture::new();
            fixture.write(payload, machine, section);

            let result = fixture.read(&section[1..]);

            assert!(result.status.success(), "{:?}", result.stderr);
            assert_eq!(result.stdout, expected);
            assert!(result.stderr.is_empty());
        }
    }
}

#[test]
fn required_text_rejects_missing_empty_invalid_utf8_nul_and_oversized_payloads() {
    let oversized = vec![b'x'; MAX_IDENTITY_TEXT_BYTES as usize + 1];
    for payload in [
        &b""[..],
        &b"\0\0"[..],
        &b"a\0b"[..],
        &b"\xff"[..],
        oversized.as_slice(),
    ] {
        let fixture = Fixture::new();
        fixture.write(payload, 0x8664, ".cmdline");

        let result = fixture.read("cmdline");

        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!result.stderr.is_empty());
    }
    let fixture = Fixture::new();
    fixture.write(b"data", 0x8664, ".osrel");
    assert!(!fixture.read("cmdline").status.success());
    assert_eq!(fixture.read("sbat").status.code(), Some(2));
}

#[test]
fn exact_size_limit_is_accepted_and_text_symlinks_are_refused() {
    let fixture = Fixture::new();
    let payload = vec![b'x'; MAX_IDENTITY_TEXT_BYTES as usize];
    let path = fixture.write(&payload, 0xaa64, ".cmdline");

    let result = fixture.read("cmdline");

    assert!(result.status.success());
    assert_eq!(result.stdout, payload);
    let actual = fixture.0.join("actual.efi");
    fs::rename(&path, &actual).unwrap();
    std::os::unix::fs::symlink(&actual, &path).unwrap();
    assert!(!fixture.read("cmdline").status.success());
}

#[test]
fn binary_copy_preserves_nuls_optional_empty_and_source_symlink_behavior() {
    let fixture = Fixture::new();
    let input = fixture.write(b"a\0b\0", 0x8664, ".osrel");
    let alias = fixture.0.join("alias.efi");
    std::os::unix::fs::symlink(&input, &alias).unwrap();
    let output = fixture.0.join("payload");

    copy_section(&alias, "osrel", &output).unwrap();

    assert_eq!(fs::read(&output).unwrap(), b"a\0b\0");
    assert!(copy_section(&input, "osrel", &output).is_err());
    let missing = fixture.0.join("missing");
    copy_section(&input, "cmdline", &missing).unwrap();
    assert!(fs::read(&missing).unwrap().is_empty());
}

#[test]
fn original_single_path_normal_boot_validation_is_preserved() {
    let fixture = Fixture::new();
    let path = fixture.0.join("cmdline");
    fs::write(
        &path,
        concat!(
            "root=/dev/mapper/root ",
            "roothash=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ",
            "systemd.verity_root_data=/dev/disk/by-partlabel/root-a ",
            "systemd.verity_root_hash=/dev/disk/by-partlabel/root-a-hash ",
            "systemd.verity=yes rd.luks=0\n"
        ),
    )
    .unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_aos-boot-identity"))
        .arg(path)
        .output()
        .unwrap();

    assert!(result.status.success(), "{:?}", result.stderr);
    assert!(result.stdout.is_empty());
}

#[test]
fn cli_refuses_malformed_ranges_duplicate_sections_and_truncation() {
    for mutation in ["range", "duplicate", "truncated"] {
        let fixture = Fixture::new();
        let path = fixture.write(b"recovery", 0x8664, ".cmdline");
        let mut bytes = fs::read(&path).unwrap();
        match mutation {
            "range" => bytes[348..352].copy_from_slice(&u32::MAX.to_le_bytes()),
            "duplicate" => {
                bytes[70..72].copy_from_slice(&2_u16.to_le_bytes());
                let header = bytes[328..368].to_vec();
                bytes[368..408].copy_from_slice(&header);
            }
            "truncated" => bytes.truncate(350),
            _ => unreachable!(),
        }
        fs::write(path, bytes).unwrap();

        let result = fixture.read("cmdline");

        assert!(!result.status.success(), "accepted {mutation}");
        assert!(result.stdout.is_empty());
    }
}
