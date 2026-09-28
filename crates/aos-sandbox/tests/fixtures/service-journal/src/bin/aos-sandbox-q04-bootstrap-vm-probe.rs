//! Bootstraps real protected Q04 owner journals and role-separated VM credentials.
//!
//! The explicit debug fixture retains an exact accepted Create only for denial
//! and history retirement. Its synthetic historical heads and deterministic
//! pins never establish current publisher/ancestry authority or Root publication.

#[path = "aos-sandbox-q04-bootstrap-vm-probe/negative_recovery.rs"]
mod negative_recovery;

#[path = "aos-sandbox-q04-bootstrap-vm-probe/project_recovery.rs"]
mod project_recovery;

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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
    PolicyDeploymentInputsV1, SourceHoldReadbackChallengeV1,
    encode_controller_hold_signer_credential_v1, encode_source_hold_readback_signer_credential_v1,
    query_fixed_root_v8_settled_grant_v1, read_fixed_policy_cache_hold_v1,
    sign_fixed_source_signer_readback_v2, verify_fixed_policy_cache_owner_readback_v2,
    verify_policy_deployment_head_v1, verify_signed_project_policy_source_v2,
};
use aos_sandbox_core::{ObjectDigest, ProjectId};
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

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
        "root-signed-inputs" => {
            require_uid(0)?;
            provision_root_signed_inputs()?;
        }
        "root-settlement-absent" => {
            require_uid(CONTROLLER_UID)?;
            if query_fixed_root_v8_settled_grant_v1(ObjectDigest::from_bytes([1; 32]), 1)?.is_some()
            {
                return Err("unissued Root V8 settlement was returned".into());
            }
        }
        "root-settlement-peer-denied" => {
            require_uid(0)?;
            if query_fixed_root_v8_settled_grant_v1(ObjectDigest::from_bytes([1; 32]), 1).is_ok() {
                return Err("Root accepted a non-Controller settlement peer".into());
            }
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
        "source-signer-listener" => {
            require_uid(0)?;
            project_recovery::launch_source_signer()?;
        }
        "project-cancel-pending"
        | "project-cancel-recover"
        | "project-stage-abort"
        | "project-stage-pending"
        | "project-stage-recover"
        | "project-recovery-history"
        | "project-recovery-deny-fresh" => {
            require_uid(CONTROLLER_UID)?;
            project_recovery::run_controller_mode(&mode)?;
        }
        "project-expire-deployment" => {
            require_uid(0)?;
            project_recovery::expire_deployment_credential()?;
        }
        "project-rotate-controller-credential" => {
            require_uid(0)?;
            rotate_controller_credential()?;
        }
        "project-rotate-root-source-credential" => {
            require_uid(0)?;
            let key = SigningKey::from_bytes(&[0x43; 32]);
            let pin = encode_source_hold_readback_signer_credential_v1(18, &key.verifying_key())?;
            fs::write(
                credential_path(
                    "aos-sandbox-policy-authorityd.service",
                    "source-hold-public-key",
                ),
                pin,
            )?;
        }
        "project-historical-source-pin" => {
            require_uid(0)?;
            let pin = aos_sandbox::policy_compiler::recover_fixed_root_project_source_pin_v1()?
                .ok_or("protected historical Source pin absent")?;
            let current = PinnedSourceHoldReadbackSignerV1::decode(&fs::read(credential_path(
                "aos-sandbox-policy-authorityd.service",
                "source-hold-public-key",
            ))?)?;
            if pin.generation() != 8
                || pin.verifying_key() != &SigningKey::from_bytes(&[8; 32]).verifying_key()
                || current.generation() != 18
                || current.verifying_key() == pin.verifying_key()
            {
                return Err("historical Root trust followed a replacement credential".into());
            }
        }
        negative if negative.starts_with("project-negative-") => {
            require_uid(CONTROLLER_UID)?;
            negative_recovery::run(negative)?;
        }
        _ => return Err("unknown bootstrap mode".into()),
    }
    println!("q04-{mode}:PASS");
    Ok(())
}

fn rotate_controller_credential() -> Result<(), Box<dyn Error>> {
    let key = SigningKey::from_bytes(&[0x42; 32]);
    let pin = encode_controller_hold_signer_credential_v1(10, &key.verifying_key())?;
    let service = "aos-sandboxd.service";
    fs::write(
        credential_path(service, "controller-hold-signing-key"),
        [0x42; 32],
    )?;
    fs::write(credential_path(service, "controller-hold-public-key"), pin)?;
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

fn signed_packet(magic: &[u8; 8], domain: &[u8], payload: &[u8], key: &SigningKey) -> Vec<u8> {
    let mut packet = Vec::with_capacity(payload.len() + 8 + 64);
    packet.extend_from_slice(magic);
    packet.extend_from_slice(payload);

    let mut signed = Vec::with_capacity(domain.len() + packet.len());
    signed.extend_from_slice(domain);
    signed.extend_from_slice(&packet);
    packet.extend_from_slice(&key.sign(&signed).to_bytes());
    packet
}

fn provision_root_signed_inputs() -> Result<(), Box<dyn Error>> {
    let deployment_key = SigningKey::from_bytes(&[10; 32]);
    let project_key = SigningKey::from_bytes(&[11; 32]);
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let issued = now.checked_sub(60).ok_or("VM clock underflow")?;
    let expires = now.checked_add(86_400).ok_or("VM clock overflow")?;

    let portable = vec![serde_json::json!({"kind": "inherit"}); 16];
    let accounting = vec![serde_json::json!({"kind": "inherit"}); 22];
    let layer = serde_json::json!({"accounting": accounting, "portable": portable});
    let inputs = [
        serde_json::to_vec(
            &serde_json::json!({"generation": 1, "input": layer, "magic": "AOSPNI01"}),
        )?,
        serde_json::to_vec(
            &serde_json::json!({"generation": 1, "input": layer, "magic": "AOSPSI01"}),
        )?,
        serde_json::to_vec(
            &serde_json::json!({"generation": 1, "input": {"enforcement": []}, "magic": "AOSPBI01"}),
        )?,
        serde_json::to_vec(
            &serde_json::json!({"generation": 1, "input": {"destinations": [], "endpoints": []}, "magic": "AOSPCI01"}),
        )?,
    ];
    let mut deployment_payload = Vec::with_capacity(152);
    deployment_payload.extend_from_slice(&1_u64.to_be_bytes());
    deployment_payload.extend_from_slice(&issued.to_be_bytes());
    deployment_payload.extend_from_slice(&expires.to_be_bytes());
    for input in &inputs {
        deployment_payload.extend_from_slice(&Sha256::digest(input));
    }
    let deployment = signed_packet(
        b"AOSPDH01",
        b"aos.sandbox.policy-deployment-head.v1\0",
        &deployment_payload,
        &deployment_key,
    );
    let sources = PolicyDeploymentInputsV1 {
        node: &inputs[0],
        site: &inputs[1],
        backend: &inputs[2],
        catalogs: &inputs[3],
    };
    verify_policy_deployment_head_v1(&deployment, &sources, &deployment_key.verifying_key(), now)?;

    // A signed source is required for normal Root service startup. Its
    // publisher and ancestry claims are not admitted by this bootstrap probe.
    let project = ProjectId::from_bytes([1; 16]);
    let project_layer = serde_json::to_vec(&serde_json::json!({
        "generation": 1,
        "input": {
            "accounting": vec![serde_json::json!({"kind": "inherit"}); 22],
            "advisory_actions": [],
            "cache_domain": "project",
            "grants": [],
            "namespace_rules": [],
            "portable": vec![serde_json::json!({"kind": "inherit"}); 16],
            "revocation": {"grace_nanos": 0, "mode": "deny-new"},
        },
        "magic": "AOSPPL02",
        "project_id": project.to_string(),
    }))?;
    let mut project_payload = Vec::with_capacity(256);
    project_payload.extend_from_slice(project.as_bytes());
    project_payload.extend_from_slice(&1_u64.to_be_bytes());
    project_payload.extend_from_slice(&issued.to_be_bytes());
    project_payload.extend_from_slice(&expires.to_be_bytes());
    project_payload.extend_from_slice(&1_u64.to_be_bytes());
    project_payload.extend_from_slice(&[1; 32]);
    project_payload.extend_from_slice(&Sha256::digest(&project_layer));
    project_payload.extend_from_slice(&[2; 32]);
    project_payload.extend_from_slice(&Sha256::digest(&deployment));
    project_payload.extend_from_slice(&[3; 32]);
    project_payload.extend_from_slice(&[4; 32]);
    project_payload.extend_from_slice(&1_u64.to_be_bytes());
    project_payload.extend_from_slice(&1_u64.to_be_bytes());
    let project_packet = signed_packet(
        b"AOSPPH02",
        b"aos.sandbox.policy-project-head.v2\0",
        &project_payload,
        &project_key,
    );
    verify_signed_project_policy_source_v2(
        &project_packet,
        &project_layer,
        &project_key.verifying_key(),
        now,
    )?;

    let root = "aos-sandbox-policy-authorityd.service";
    for (name, bytes) in [
        ("deployment-head.packet", deployment.as_slice()),
        ("node-policy.json", inputs[0].as_slice()),
        ("site-policy.json", inputs[1].as_slice()),
        ("backend-capabilities.json", inputs[2].as_slice()),
        ("catalogs.json", inputs[3].as_slice()),
        ("project-head-v2.packet", project_packet.as_slice()),
        ("project-layer-v2.json", project_layer.as_slice()),
    ] {
        create_credential(root, name, bytes)?;
    }
    fs::write(
        "/tmp/q04-deployment-public-key.raw",
        deployment_key.verifying_key().as_bytes(),
    )?;
    fs::write(
        "/tmp/q04-project-public-key.raw",
        project_key.verifying_key().as_bytes(),
    )?;
    Ok(())
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
