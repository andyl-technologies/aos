//! Bootstraps real protected Q04 owner journals and role-separated VM credentials.
//!
//! This fixture has no accepted Create, Source hold, or Root binding. Its pins
//! are deterministic test material, never deployment credentials or authority.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use aos_sandbox::Journal;
use aos_sandbox::cache_residency::{
    CacheOwnerReadbackChallengeV1, PinnedCacheOwnerReadbackSignerV1,
    encode_cache_owner_readback_signer_credential_v1, sign_fixed_signer_cache_owner_readback_v2,
    verify_closed_cache_owner_readback_v2,
};
use aos_sandbox::controller_service::journal::production_journal_limits;
use aos_sandbox::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use aos_sandbox::policy_compiler::{
    PinnedControllerHoldSignerV1, PinnedSourceHoldReadbackSignerV1, PolicyCompilerProtectedOwnerV1,
    SourceHoldReadbackChallengeV1, encode_controller_hold_signer_credential_v1,
    encode_source_hold_readback_signer_credential_v1, read_fixed_policy_cache_hold_v1,
    sign_fixed_source_signer_readback_v2, verify_fixed_policy_cache_owner_readback_v2,
};
use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::SigningKey;

const CONTROLLER_UID: u32 = 811;
const CACHE_SIGNER_UID: u32 = 813;
const SOURCE_SIGNER_UID: u32 = 814;
const CONTROLLER_ROOT: &str = "/var/lib/aos/sandboxd";
const CREDENTIAL_ROOT: &str = "/run/credentials";
const CACHE_PACKET: &str = "/tmp/q04-bootstrap-cache-packet";

fn main() {
    if let Err(error) = run() {
        eprintln!("Q04 protected bootstrap VM prerequisite failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mode = std::env::args().nth(1).ok_or("missing bootstrap mode")?;
    match mode.as_str() {
        "controller-bootstrap" | "controller-replay" => {
            require_uid(CONTROLLER_UID)?;
            controller_replay(mode == "controller-replay")?;
        }
        "root-bootstrap" | "root-replay" => {
            require_uid(0)?;
            root_replay(mode == "root-replay")?;
        }
        "credentials-bootstrap" => {
            require_uid(0)?;
            bootstrap_credentials()?;
        }
        "credentials-replay" => {
            require_uid(0)?;
            replay_credentials()?;
        }
        "cache-signer-readback" => {
            require_uid(CACHE_SIGNER_UID)?;
            cache_signer_readback()?;
        }
        "root-cache-verify" => {
            require_uid(0)?;
            root_cache_verify()?;
        }
        "source-signer-reject-unheld" => {
            require_uid(SOURCE_SIGNER_UID)?;
            source_signer_reject_unheld()?;
        }
        _ => return Err("unknown bootstrap mode".into()),
    }
    println!("q04-{mode}:PASS");
    Ok(())
}

fn require_uid(expected: u32) -> Result<(), Box<dyn Error>> {
    if rustix::process::geteuid().as_raw() != expected {
        return Err("wrong VM owner identity".into());
    }
    Ok(())
}

fn require_existing_journal(directory: &str, name: &str) -> Result<(), Box<dyn Error>> {
    for path in [
        Path::new(directory).join(name),
        Path::new(directory).join(format!("{name}.lock")),
    ] {
        if !fs::metadata(path)?.is_file() {
            return Err("cold replay journal or lock is missing".into());
        }
    }
    Ok(())
}

fn controller_replay(require_existing: bool) -> Result<(), Box<dyn Error>> {
    if require_existing {
        require_existing_journal(CONTROLLER_ROOT, "controller.journal")?;
        require_existing_journal(
            "/var/lib/aos/sandbox/source-domains",
            "source-domains-v1.journal",
        )?;
    }
    let (journal, _) = Journal::open_protected_at_for_uid(
        Path::new(CONTROLLER_ROOT),
        "controller.journal",
        production_journal_limits(),
        CONTROLLER_UID,
    )?;
    let (source, _) =
        ProtectedSourceDomainJournalOwnerV1::open_fixed_protected_for_uid(CONTROLLER_UID)?;
    if journal.controller_policy_v8_attempt_v1()?.is_some()
        || journal.controller_policy_v8_effect_ack_v1()?.is_some()
        || source.closed_policy_source_hold_v1()?.is_some()
    {
        return Err("bootstrap unexpectedly acquired Create custody".into());
    }
    Ok(())
}

fn root_replay(require_existing: bool) -> Result<(), Box<dyn Error>> {
    if require_existing {
        for name in ["authority.journal", "state.journal"] {
            require_existing_journal("/var/lib/aos/sandbox/policy-compiler", name)?;
        }
    }
    let (mut root, _) = PolicyCompilerProtectedOwnerV1::open_fixed_protected()?;
    root.replay()?;
    Ok(())
}

fn credential_path(service: &str, name: &str) -> std::path::PathBuf {
    Path::new(CREDENTIAL_ROOT).join(service).join(name)
}

fn create_credential(service: &str, name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let path = credential_path(service, name);
    let parent = path.parent().ok_or("credential parent absent")?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn bootstrap_credentials() -> Result<(), Box<dyn Error>> {
    let cache = SigningKey::from_bytes(&[7; 32]);
    let source = SigningKey::from_bytes(&[8; 32]);
    let controller = SigningKey::from_bytes(&[9; 32]);
    let cache_pin = encode_cache_owner_readback_signer_credential_v1(7, &cache.verifying_key())?;
    let source_pin = encode_source_hold_readback_signer_credential_v1(8, &source.verifying_key())?;
    let controller_pin =
        encode_controller_hold_signer_credential_v1(9, &controller.verifying_key())?;
    let mut memory = [0; 16];
    memory[..8].copy_from_slice(b"AOSCSM01");
    memory[8..].copy_from_slice(&(1024_u64 * 1024).to_be_bytes());

    create_credential(
        "aos-sandbox-cache-signerd.service",
        "cache-signer-v2-seed",
        &[7; 32],
    )?;
    create_credential(
        "aos-sandbox-cache-signerd.service",
        "cache-owner-readback-public-key",
        &cache_pin,
    )?;
    create_credential(
        "aos-sandbox-cache-signerd.service",
        "cache-signer-v2-memory-ceiling",
        &memory,
    )?;
    create_credential(
        "aos-sandbox-source-signerd.service",
        "source-hold-signing-seed",
        &[8; 32],
    )?;
    create_credential(
        "aos-sandbox-source-signerd.service",
        "source-hold-public-key",
        &source_pin,
    )?;
    create_credential(
        "aos-sandboxd.service",
        "controller-hold-signing-key",
        &[9; 32],
    )?;
    create_credential(
        "aos-sandboxd.service",
        "controller-hold-public-key",
        &controller_pin,
    )?;
    create_credential(
        "aos-sandboxd.service",
        "cache-owner-readback-public-key",
        &cache_pin,
    )?;
    for (name, pin) in [
        ("cache-owner-readback-public-key", cache_pin.as_slice()),
        ("source-hold-public-key", source_pin.as_slice()),
        ("controller-hold-public-key", controller_pin.as_slice()),
    ] {
        create_credential("aos-sandbox-policy-authorityd.service", name, pin)?;
    }
    replay_credentials()
}

fn replay_credentials() -> Result<(), Box<dyn Error>> {
    let cache = fs::read(credential_path(
        "aos-sandbox-policy-authorityd.service",
        "cache-owner-readback-public-key",
    ))?;
    let source = fs::read(credential_path(
        "aos-sandbox-policy-authorityd.service",
        "source-hold-public-key",
    ))?;
    let controller = fs::read(credential_path(
        "aos-sandbox-policy-authorityd.service",
        "controller-hold-public-key",
    ))?;
    for (service, name, expected) in [
        (
            "aos-sandbox-cache-signerd.service",
            "cache-owner-readback-public-key",
            cache.as_slice(),
        ),
        (
            "aos-sandboxd.service",
            "cache-owner-readback-public-key",
            cache.as_slice(),
        ),
        (
            "aos-sandbox-source-signerd.service",
            "source-hold-public-key",
            source.as_slice(),
        ),
        (
            "aos-sandboxd.service",
            "controller-hold-public-key",
            controller.as_slice(),
        ),
    ] {
        if fs::read(credential_path(service, name))? != expected {
            return Err("role pin differs between fixed VM services".into());
        }
    }
    let cache = PinnedCacheOwnerReadbackSignerV1::decode(&cache)?;
    let source = PinnedSourceHoldReadbackSignerV1::decode(&source)?;
    let controller = PinnedControllerHoldSignerV1::decode(&controller)?;
    let controller_seed = fs::read(credential_path(
        "aos-sandboxd.service",
        "controller-hold-signing-key",
    ))?;
    let controller_seed: [u8; 32] = controller_seed
        .try_into()
        .map_err(|_| "invalid Controller seed")?;
    if cache.generation() != 7
        || source.generation() != 8
        || controller.generation() != 9
        || controller.verifying_key() != &SigningKey::from_bytes(&controller_seed).verifying_key()
        || cache.verifying_key() == source.verifying_key()
        || cache.verifying_key() == controller.verifying_key()
        || source.verifying_key() == controller.verifying_key()
    {
        return Err("VM signer roles are not distinct".into());
    }
    Ok(())
}

fn cache_signer_readback() -> Result<(), Box<dyn Error>> {
    let seed = fs::read(credential_path(
        "aos-sandbox-cache-signerd.service",
        "cache-signer-v2-seed",
    ))?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| "invalid Cache seed")?;
    let pin = fs::read(credential_path(
        "aos-sandbox-cache-signerd.service",
        "cache-owner-readback-public-key",
    ))?;
    let pin = PinnedCacheOwnerReadbackSignerV1::decode(&pin)?;
    let key = SigningKey::from_bytes(&seed);
    if pin.verifying_key() != &key.verifying_key() {
        return Err("Cache signer seed/pin mismatch".into());
    }
    let challenge = CacheOwnerReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32]))?;
    let packet =
        sign_fixed_signer_cache_owner_readback_v2(1024 * 1024, challenge, pin.generation(), &key)?;
    verify_closed_cache_owner_readback_v2(&packet, &pin, challenge, CONTROLLER_UID)?;
    fs::write(CACHE_PACKET, packet)?;
    Ok(())
}

fn root_cache_verify() -> Result<(), Box<dyn Error>> {
    let pin = fs::read(credential_path(
        "aos-sandbox-policy-authorityd.service",
        "cache-owner-readback-public-key",
    ))?;
    let pin = PinnedCacheOwnerReadbackSignerV1::decode(&pin)?;
    let packet = fs::read(CACHE_PACKET)?;
    let challenge = CacheOwnerReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32]))?;
    let observed = read_fixed_policy_cache_hold_v1()?;
    verify_fixed_policy_cache_owner_readback_v2(
        &packet,
        &pin,
        challenge,
        CONTROLLER_UID,
        observed.hold,
    )?;
    Ok(())
}

fn source_signer_reject_unheld() -> Result<(), Box<dyn Error>> {
    let seed = fs::read(credential_path(
        "aos-sandbox-source-signerd.service",
        "source-hold-signing-seed",
    ))?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| "invalid Source seed")?;
    let pin = fs::read(credential_path(
        "aos-sandbox-source-signerd.service",
        "source-hold-public-key",
    ))?;
    let pin = PinnedSourceHoldReadbackSignerV1::decode(&pin)?;
    let key = SigningKey::from_bytes(&seed);
    let challenge = SourceHoldReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32]))?;
    if pin.verifying_key() != &key.verifying_key()
        || sign_fixed_source_signer_readback_v2(
            CONTROLLER_UID,
            ProjectId::from_bytes([1; 16]),
            challenge,
            pin.generation(),
            &key,
        )
        .is_ok()
    {
        return Err("unheld Source unexpectedly signed".into());
    }
    Ok(())
}
