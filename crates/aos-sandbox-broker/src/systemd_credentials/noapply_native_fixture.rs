//! Exercises both unchanged fixed80 wrappers in an isolated privileged child.
//!
//! The ignored test requires UID0 and CAP_SYS_CHROOT. Foreign-owner cases also
//! require mapped UID/GID1 and CAP_CHOWN. It creates no mounts or Source grant,
//! changes no production path, and does not establish PID1 credential delivery.
//! All keys and files belong to a transient fixture root removed by its parent.

use super::*;
use aos_sandbox_protocol::host_execution_no_apply::root_attestation::RootNoApplyPublicPinDataV2;
use ed25519_dalek::SigningKey;
use std::error::Error;
use std::os::unix::fs::{PermissionsExt as _, chown, chroot, symlink};
use std::process::Command;

const TEST: &str =
    "systemd_credentials::noapply_native_fixture::fixed_root_and_host_wrappers_native";
const CHILD_ROOT: &str = "AOS_NOAPPLY_NATIVE_FIXTURE_ROOT";
const CHILD_CASE: &str = "AOS_NOAPPLY_NATIVE_FIXTURE_CASE";
const CHILD_KIND: &str = "AOS_NOAPPLY_NATIVE_FIXTURE_KIND";
const ROOT_NAME: &str = "root-noapply-floor-signing";
const HOST_NAME: &str = "root-noapply-floor-public";
const ROOT_SERVICE: &str = "/run/credentials/aos-sandbox-policy-authorityd.service";
const HOST_SERVICE: &str = "/run/credentials/aos-sandbox-hostd.service";

enum Original {
    Root(RootNoApplySigningCredentialOriginalV2),
    Host(HostNoApplyRootPublicCredentialOriginalV2),
}

impl Original {
    fn new(kind: &str) -> Self {
        match kind {
            "root" => Self::Root(RootNoApplySigningCredentialOriginalV2::new()),
            "host" => Self::Host(HostNoApplyRootPublicCredentialOriginalV2::new()),
            _ => panic!("unknown native fixture kind"),
        }
    }

    fn capture(&mut self) -> bool {
        match self {
            Self::Root(value) => value.capture_once_v2().is_ok(),
            Self::Host(value) => value.capture_once_v2().is_ok(),
        }
    }

    fn before(&mut self) -> bool {
        match self {
            Self::Root(value) => value.before_sign_once_v2().is_ok(),
            Self::Host(value) => value.preliminary_before_once_v2().is_ok(),
        }
    }

    fn owed_after(&mut self) -> bool {
        match self {
            Self::Root(value) => value.finish_posts_once_v2().is_ok(),
            Self::Host(value) => value.preliminary_after_once_v2().is_ok(),
        }
    }

    fn after_entered(&self) -> bool {
        match self {
            Self::Root(value) => value.fixture_owed_after_entered_v2(),
            Self::Host(value) => value.fixture_owed_after_entered_v2(),
        }
    }

    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Root(value) => value.bytes_v2(),
            Self::Host(value) => value.bytes_v2(),
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Root(value) => value.failure().map(|cause| cause as _),
            Self::Host(value) => value.failure(),
        }
    }
}

fn directory(kind: &str) -> &'static Path {
    Path::new(if kind == "root" {
        ROOT_SERVICE
    } else {
        HOST_SERVICE
    })
}

fn credential(kind: &str) -> PathBuf {
    directory(kind).join(if kind == "root" { ROOT_NAME } else { HOST_NAME })
}

fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
}

fn replace_same_bytes(path: &Path, bytes: &[u8]) {
    let replacement = path.with_extension("replacement");
    write_private(&replacement, bytes);
    std::fs::rename(replacement, path).unwrap();
}

fn prepare_root(root: &Path) {
    for relative in [
        "run",
        "run/credentials",
        "run/credentials/aos-sandbox-policy-authorityd.service",
        "run/credentials/aos-sandbox-hostd.service",
    ] {
        let path = root.join(relative);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    let mut seed = Zeroizing::new([0; 32]);
    File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut seed[..])
        .unwrap();
    let signer = SigningKey::from_bytes(&seed);
    let mut secret = Zeroizing::new([0; 80]);
    secret[..8].copy_from_slice(b"AOSRNK02");
    secret[8..16].copy_from_slice(&7_u64.to_be_bytes());
    secret[16..48].copy_from_slice(&seed[..]);
    let checksum = Sha256::new()
        .chain_update(b"aos.sandbox.root.execution-no-apply-signing-key.v2\0")
        .chain_update(&secret[..48])
        .finalize();
    secret[48..].copy_from_slice(&checksum);

    let pin = RootNoApplyPublicPinDataV2::new(7, signer.verifying_key().to_bytes()).unwrap();
    write_private(
        &root
            .join(ROOT_SERVICE.trim_start_matches('/'))
            .join(ROOT_NAME),
        &secret[..],
    );
    write_private(
        &root
            .join(HOST_SERVICE.trim_start_matches('/'))
            .join(HOST_NAME),
        &pin.encode_canonical(),
    );
}

fn capture_refusal(case: &str, kind: &str, expected: &[u8]) {
    let path = credential(kind);
    match case {
        "missing" => std::fs::remove_file(&path).unwrap(),
        "short" => replace_same_bytes(&path, &expected[..79]),
        "trailing" => {
            let mut bytes = Zeroizing::new(expected.to_vec());
            bytes.push(0);
            replace_same_bytes(&path, &bytes);
        }
        "mode" => std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap(),
        "uid" => chown(&path, Some(1), None)
            .expect("native owner case requires CAP_CHOWN and mapped UID1"),
        "gid" => chown(&path, None, Some(1))
            .expect("native owner case requires CAP_CHOWN and mapped GID1"),
        "hardlink" => std::fs::hard_link(&path, path.with_extension("alias")).unwrap(),
        "symlink" => {
            let target = path.with_extension("target");
            std::fs::rename(&path, &target).unwrap();
            symlink(target, &path).unwrap();
        }
        "writable_ancestor" => {
            std::fs::set_permissions("/run", std::fs::Permissions::from_mode(0o777)).unwrap()
        }
        "symlink_ancestor" => {
            std::fs::rename("/run/credentials", "/run/original-credentials").unwrap();
            symlink("/run/original-credentials", "/run/credentials").unwrap();
        }
        _ => panic!("unknown capture refusal"),
    }
    let mut original = Original::new(kind);

    assert!(!original.capture(), "fixed wrapper accepted {case}/{kind}");
    if matches!(case, "missing" | "symlink") {
        assert!(
            original.failure().unwrap().source().is_some(),
            "native IO cause was erased"
        );
    }
    let first = original.failure().unwrap() as *const dyn Error;
    assert!(original.bytes().is_none());

    assert!(!original.capture());
    assert!(std::ptr::eq(first, original.failure().unwrap()));
}

fn readback_refusal(case: &str, kind: &str, expected: &[u8]) {
    let mut original = Original::new(kind);
    assert!(original.capture());
    assert!(original.bytes() == Some(expected));
    match case {
        "changed_name" => replace_same_bytes(&credential(kind), expected),
        "changed_ancestry" => {
            let directory = directory(kind);
            std::fs::rename(directory, directory.with_extension("held")).unwrap();
            std::fs::create_dir(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            write_private(&credential(kind), expected);
        }
        "changed_held_mode" => {
            std::fs::set_permissions(credential(kind), std::fs::Permissions::from_mode(0o600))
                .unwrap()
        }
        _ => panic!("unknown readback refusal"),
    }
    assert!(!original.before());
    let first = original.failure().unwrap() as *const dyn Error;
    assert!(!original.owed_after());
    assert!(original.after_entered(), "owed native after did not enter");
    assert!(std::ptr::eq(first, original.failure().unwrap()));
    assert!(original.bytes().is_none());
}

fn after_refusal(kind: &str, expected: &[u8]) {
    let mut original = Original::new(kind);
    assert!(original.capture());
    assert!(original.before());
    assert!(original.failure().is_none());
    replace_same_bytes(&credential(kind), expected);

    assert!(!original.owed_after());
    assert!(original.after_entered());
    let first = original.failure().unwrap() as *const dyn Error;
    assert!(!original.capture());
    assert!(std::ptr::eq(first, original.failure().unwrap()));
    assert!(original.bytes().is_none());
}

fn run_child(root: &Path, case: &str, kind: &str) {
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        0,
        "privileged native fixture requires UID0"
    );
    assert_eq!(root.parent(), Some(std::env::temp_dir().as_path()));
    assert!(
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("aos-noapply-native-")
    );
    assert!(root.symlink_metadata().unwrap().file_type().is_dir());
    chroot(root).expect("native fixed-path fixture requires CAP_SYS_CHROOT in a fresh child");
    std::env::set_current_dir("/").unwrap();
    let secret = Zeroizing::new(std::fs::read(credential("root")).unwrap());
    let public = std::fs::read(credential("host")).unwrap();
    let pin = RootNoApplyPublicPinDataV2::decode_canonical(&public).unwrap();
    let seed = Zeroizing::new(<[u8; 32]>::try_from(&secret[16..48]).unwrap());
    assert!(SigningKey::from_bytes(&seed).verifying_key().to_bytes() == pin.public_key_v2());
    assert_eq!(pin.generation_v2(), 7);
    let expected = if kind == "root" {
        &secret[..]
    } else {
        &public[..]
    };
    match case {
        "positive" => {
            let mut original = Original::new(kind);
            assert!(original.capture());
            assert!(original.bytes() == Some(expected));
            assert!(original.before());
            assert!(original.owed_after());
            assert!(original.after_entered());
            if let Original::Host(value) = &mut original {
                value.nonce_before_once_v2().unwrap();
                value.nonce_after_once_v2().unwrap();
                value.floor_before_once_v2().unwrap();
                value.floor_after_once_v2().unwrap();
                value.ack_before_once_v2().unwrap();
                value.ack_after_once_v2().unwrap();
            }
            if let Original::Root(value) = &original {
                value.require_complete_v2().unwrap();
            }
            assert!(original.failure().is_none());
        }
        "changed_name" | "changed_ancestry" | "changed_held_mode" => {
            readback_refusal(case, kind, expected)
        }
        "changed_after" => after_refusal(kind, expected),
        _ => capture_refusal(case, kind, expected),
    }
}

#[test]
#[ignore = "requires UID0/CAP_SYS_CHROOT; foreign-owner cases require mapped UID/GID1 and CAP_CHOWN; not PID1 delivery"]
fn fixed_root_and_host_wrappers_native() {
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let case = std::env::var(CHILD_CASE).unwrap();
        let kind = std::env::var(CHILD_KIND).unwrap();
        run_child(Path::new(&root), &case, &kind);
        println!("fixed80 native reader case {case}/{kind} passed");
        return;
    }
    assert_eq!(
        rustix::process::geteuid().as_raw(),
        0,
        "select this fixture only with honest root privileges"
    );
    for kind in ["root", "host"] {
        for case in [
            "positive",
            "missing",
            "short",
            "trailing",
            "mode",
            "uid",
            "gid",
            "hardlink",
            "symlink",
            "writable_ancestor",
            "symlink_ancestor",
            "changed_name",
            "changed_ancestry",
            "changed_held_mode",
            "changed_after",
        ] {
            let root = tempfile::Builder::new()
                .prefix("aos-noapply-native-")
                .tempdir()
                .unwrap();
            prepare_root(root.path());

            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", TEST, "--nocapture"])
                .env(CHILD_ROOT, root.path())
                .env(CHILD_CASE, case)
                .env(CHILD_KIND, kind)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "native fixture {case}/{kind} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let receipt = format!("fixed80 native reader case {case}/{kind} passed");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains(&receipt),
                "the exact native child test did not execute"
            );
            // TempDir removes both ephemeral envelopes after the child exits.
        }
    }
}
