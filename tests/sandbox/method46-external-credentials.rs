//! Prepares external initial-floor credentials using the ordinary public codecs.
//!
//! Fresh normal-owner keys are generated at runtime outside the Nix store.
//! Independent operator public pins, existing native-history comparison DATA
//! and external TPM preparation records are supplied separately. This fixture
//! neither signs initial approval nor establishes installed Source authority.
//!
//! ```text
//! NODE EPOCH TPM_PREPARATION CONTROLLER_PUBLIC STORAGE_PUBLIC EXPECTED_CUT OUTPUT
//! ```

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use aos_sandbox_broker_session_protocol::manifest::{
    BrokerSessionManifestAudienceV1, BrokerSessionManifestKeyPinV1, BrokerSessionManifestV1,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionKeyUsageV1, BrokerSessionProtocolV1,
    BrokerSessionSignerReferenceV1, supported_broker_session_version_v1,
};
use aos_sandbox_broker_session_security::method46_initial_provisioning::{
    Method46InitialPurposeV1, Method46InitialRequestDataV1,
};
use aos_sandbox_controller_domain::policy_compiler::encode_source_hold_readback_signer_credential_v1;
use aos_sandbox_policy::policy_signer_credential::{
    PolicySignerRoleV1, encode_policy_signer_credential_v1,
};
use aos_sandbox_protocol::host_execution_no_apply::root_attestation::RootNoApplyPublicPinDataV2;
use aos_sandbox_protocol::method46_provisioning::{
    Method46EndpointDataV1, Method46ProfileDataV1, decode_provision_v1,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rustix::fs::{Mode, OFlags};
use sha2::{Digest as _, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("external METHOD46 credential preparation refused: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 7 {
        return Err("expected NODE EPOCH TPM_DIRECTORY CONTROLLER_PUBLIC STORAGE_PUBLIC EXPECTED_CUT OUTPUT".into());
    }
    let node = read_exact::<16>(Path::new(&args[0]))?;
    let epoch = read_exact::<16>(Path::new(&args[1]))?;
    let approvals = [
        read_exact::<32>(Path::new(&args[3]))?,
        read_exact::<32>(Path::new(&args[4]))?,
    ];
    for pin in approvals {
        if VerifyingKey::from_bytes(&pin)?.is_weak() {
            return Err("operator public pin is weak".into());
        }
    }
    if node == [0; 16] || epoch == [0; 16] || approvals[0] == approvals[1] {
        return Err("node, deployment epoch and independent purpose pins are required".into());
    }
    let prepared: [[u8; 130]; 2] = [
        read_bounded(&Path::new(&args[2]).join("endpoint-0"), 130, true)?
            .try_into()
            .map_err(|_| "inexact Controller preparation")?,
        read_bounded(&Path::new(&args[2]).join("endpoint-1"), 130, true)?
            .try_into()
            .map_err(|_| "inexact Storage preparation")?,
    ];
    for record in &prepared {
        if record[..32] == [0; 32] || record[32..34] != [0, 0x0b] || record[66..] != [0; 64] {
            return Err("expected exact external unwritten preparation DATA".into());
        }
    }
    if prepared[0][..32] == prepared[1][..32] {
        return Err("index authentication must be independent".into());
    }
    let cut: serde_json::Value =
        serde_json::from_slice(&read_bounded(Path::new(&args[5]), 4096, false)?)?;
    let next = cut["next_sequence"]
        .as_u64()
        .ok_or("missing native sequence")?;
    let head: [u8; 32] = serde_json::from_value(cut["head"].clone())?;
    if cut["namespace"] != 47 || cut["live_records"] != 0 || next <= 1 {
        return Err("expected nonempty native history with an empty current Session map".into());
    }

    let root = Path::new(&args[6]);
    directory(root)?;
    let delivered = root.join("system-credentials");
    let private = root.join("normal-authorities");
    let expected = root.join("operator-expectations");
    for directory_path in [&delivered, &private, &expected] {
        directory(directory_path)?;
    }
    write_new(&delivered.join("qualification-node-id"), &node)?;
    let mut entropy = File::open("/dev/urandom")?;

    let mut storage_manifest = None;
    for (name, protocol) in [
        ("Host", BrokerSessionProtocolV1::Host),
        ("Storage", BrokerSessionProtocolV1::Storage),
        ("Mount", BrokerSessionProtocolV1::Mount),
        ("Network", BrokerSessionProtocolV1::Network),
        ("NixCatalog", BrokerSessionProtocolV1::Nix),
        ("NixOnline", BrokerSessionProtocolV1::Nix),
    ] {
        let (manifest, secrets) = manifest(&mut entropy, node, protocol, approvals)?;
        let encoded = manifest.encode();
        for (index, secret) in secrets.iter().enumerate() {
            write_new(&private.join(format!("{name}-session-key-{index}")), secret)?;
        }
        match name {
            "NixCatalog" => write_new(
                &delivered.join("qualification-nix-broker-session-manifest-v1"),
                &encoded,
            )?,
            "NixOnline" => {
                for suffix in ["manifest", "clientManifest"] {
                    write_new(
                        &delivered.join(format!("qualification-nix-session-{suffix}")),
                        &encoded,
                    )?;
                }
                for (suffix, index) in [
                    ("clientHello", 0),
                    ("hello", 1),
                    ("clientRecord", 2),
                    ("record", 3),
                ] {
                    write_new(
                        &delivered.join(format!("qualification-nix-session-{suffix}")),
                        &secrets[index],
                    )?;
                }
            }
            _ => {
                for (suffix, bytes) in [
                    ("Manifest", encoded.as_slice()),
                    ("HelloKey", &secrets[0]),
                    ("RecordKey", &secrets[2]),
                ] {
                    write_new(
                        &delivered.join(format!("qualification-{name}-{suffix}")),
                        bytes,
                    )?;
                }
                for (suffix, bytes) in [
                    ("manifest", encoded.as_slice()),
                    ("hello", &secrets[1]),
                    ("outcome", &secrets[3]),
                ] {
                    write_new(
                        &delivered.join(format!(
                            "qualification-{}-broker-{suffix}",
                            name.to_lowercase()
                        )),
                        bytes,
                    )?;
                }
            }
        }
        if protocol == BrokerSessionProtocolV1::Storage {
            storage_manifest = Some(manifest);
        }
    }

    for (name, role) in [
        ("deploymentPublicKey", PolicySignerRoleV1::Deployment),
        ("projectPublicKey", PolicySignerRoleV1::Project),
    ] {
        let key = normal_key(&mut entropy, approvals)?;
        write_new(&private.join(name), &key.to_bytes())?;
        write_new(
            &delivered.join(format!("qualification-root-{name}")),
            &encode_policy_signer_credential_v1(role, 1, &key.verifying_key())?,
        )?;
    }
    let source = normal_key(&mut entropy, approvals)?;
    write_new(&private.join("source-hold"), &source.to_bytes())?;
    write_new(
        &delivered.join("qualification-source-hold-public-key"),
        &encode_source_hold_readback_signer_credential_v1(1, &source.verifying_key())?,
    )?;
    let noapply = normal_key(&mut entropy, approvals)?;
    write_new(&private.join("root-noapply"), &noapply.to_bytes())?;
    write_new(
        &delivered.join("qualification-root-noapply-public"),
        &RootNoApplyPublicPinDataV2::new(1, noapply.verifying_key().to_bytes())?.encode_canonical(),
    )?;
    for name in [
        "nix-recipe-issuer-v2",
        "ownership-lease-public-key",
        "broker-plan-public-key",
        "mount-broker-plan-public-key",
    ] {
        let key = normal_key(&mut entropy, approvals)?;
        write_new(&private.join(name), &key.to_bytes())?;
        write_new(
            &delivered.join(format!("qualification-{name}")),
            &key.verifying_key().to_bytes(),
        )?;
    }
    for name in ["controller", "owner"] {
        let key = normal_key(&mut entropy, approvals)?;
        let mut issuer = [0; 48];
        issuer[..16].copy_from_slice(&random::<16>(&mut entropy)?);
        issuer[16..].copy_from_slice(&key.verifying_key().to_bytes());
        write_new(&private.join(format!("nix-{name}-issuer")), &key.to_bytes())?;
        write_new(
            &delivered.join(format!("qualification-nix-{name}-issuer")),
            &issuer,
        )?;
    }

    let storage = storage_manifest.ok_or("missing Storage manifest")?;
    for (index, (name, endpoint, purpose, durable)) in [
        (
            "controller",
            Method46EndpointDataV1::ControllerStorageClient,
            Method46InitialPurposeV1::ControllerStorageClient,
            BrokerSessionDurableEndpointV1::Client,
        ),
        (
            "storage",
            Method46EndpointDataV1::StorageBroker,
            Method46InitialPurposeV1::StorageBroker,
            BrokerSessionDurableEndpointV1::Broker,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let salt: [u8; 34] = prepared[index][32..66].try_into()?;
        let stable = storage
            .binding()
            .stable_endpoint_identity_data_v2(BrokerSessionProtocolV1::Storage, durable);
        let profile =
            Method46ProfileDataV1::new(endpoint, node, epoch, stable, Sha256::digest(salt).into())?;
        let mut provision = [0; 160];
        provision[..8].copy_from_slice(b"AOSBTD01");
        provision[8..10].copy_from_slice(&1u16.to_be_bytes());
        provision[12..124].copy_from_slice(&profile.encode());
        provision[124..158].copy_from_slice(&salt);
        decode_provision_v1(&provision, endpoint)?;
        let prefix = format!("qualification-method46-{name}");
        write_new(&delivered.join(format!("{prefix}-provision")), &provision)?;
        write_new(
            &delivered.join(format!("{prefix}-index-auth")),
            &prepared[index][..32],
        )?;
        write_new(
            &delivered.join(format!("{prefix}-approval-public")),
            &approvals[index],
        )?;
        let request =
            Method46InitialRequestDataV1::new(purpose, node, epoch, stable, salt, next, head)?;
        write_new(
            &expected.join(format!("{name}-checkpoint")),
            &request.checkpoint(),
        )?;
    }
    for directory_path in [&delivered, &private, &expected, root] {
        File::open(directory_path)?.sync_all()?;
    }
    File::open(
        root.parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

fn manifest(
    entropy: &mut File,
    node: [u8; 16],
    protocol: BrokerSessionProtocolV1,
    approvals: [[u8; 32]; 2],
) -> Result<(BrokerSessionManifestV1, [[u8; 48]; 4])> {
    let usages = [
        BrokerSessionKeyUsageV1::ClientHello,
        BrokerSessionKeyUsageV1::BrokerHello,
        BrokerSessionKeyUsageV1::ClientRecord,
        BrokerSessionKeyUsageV1::BrokerOutcome,
    ];
    let mut secrets = [[0; 48]; 4];
    let mut pins = Vec::with_capacity(4);
    for (index, usage) in usages.into_iter().enumerate() {
        let id = random::<16>(entropy)?;
        let key = normal_key(entropy, approvals)?;
        secrets[index][..16].copy_from_slice(&id);
        secrets[index][16..].copy_from_slice(&key.to_bytes());
        let signer = BrokerSessionSignerReferenceV1::for_signing_key(
            random(entropy)?,
            1,
            random(entropy)?,
            id,
            1,
            usage,
            &key,
        )
        .map_err(|_| "noncanonical normal signer DATA")?;
        pins.push(
            BrokerSessionManifestKeyPinV1::new(
                signer,
                key.verifying_key().to_bytes(),
                1,
                1,
                false,
                None,
            )
            .map_err(|_| "noncanonical normal pin DATA")?,
        );
    }
    let (major, minor) = supported_broker_session_version_v1(protocol);
    let manifest = BrokerSessionManifestV1::new(
        protocol,
        BrokerSessionManifestAudienceV1::NodeController,
        major,
        minor,
        random(entropy)?,
        random(entropy)?,
        1,
        random(entropy)?,
        1,
        random(entropy)?,
        1,
        random(entropy)?,
        node,
        pins.try_into().map_err(|_| "expected four pins")?,
    )
    .map_err(|_| "noncanonical normal manifest DATA")?;
    BrokerSessionManifestV1::decode(&manifest.encode())
        .map_err(|_| "manifest round trip refused")?;
    Ok((manifest, secrets))
}

fn normal_key(entropy: &mut File, approvals: [[u8; 32]; 2]) -> Result<SigningKey> {
    let key = SigningKey::from_bytes(&random(entropy)?);
    if approvals.contains(&key.verifying_key().to_bytes()) {
        return Err("normal signer must be independent of both approvers".into());
    }
    Ok(key)
}

fn random<const N: usize>(entropy: &mut File) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    entropy.read_exact(&mut bytes)?;
    if bytes == [0; N] {
        return Err("kernel entropy produced a reserved sentinel".into());
    }
    Ok(bytes)
}

fn read_bounded(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>> {
    let file = File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("expected a bounded regular input file".into());
    }
    if private
        && (metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw())
    {
        return Err("TPM preparation must be an owner-only singly linked file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input grew beyond its bound".into());
    }
    Ok(bytes)
}

fn read_exact<const N: usize>(path: &Path) -> Result<[u8; N]> {
    read_bounded(path, N, false)?
        .try_into()
        .map_err(|_| "input has inexact width".into())
}

fn directory(path: &Path) -> Result<()> {
    DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
