//! Signs independent operator approvals outside the offline provisioning guest.
//!
//! The input candidate is the genuine owner's public export. This fixture never
//! reads its private candidate, writes a journal, initializes hardware or issues
//! runtime credentials. Its test-only manifest coordinates describe the offline
//! installation; they establish no runtime currentness or paid startup authority.
//!
//! ```text
//! initialize PUBLIC DOMAIN PROFILE OPERATOR_KEY OUTPUT_DIRECTORY
//! recover PUBLIC DOMAIN PROFILE OPERATOR_KEY OUTPUT_DIRECTORY ORIGINAL_HISTORY
//! OPERATOR_KEY = approval ID16 || Ed25519 seed32 (host-only)
//! ```

#![forbid(unsafe_code)]

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

use aos_sandbox_broker_session_protocol::manifest::{
    BrokerSessionManifestAudienceV1, BrokerSessionManifestKeyPinV1, BrokerSessionManifestV1,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionKeyUsageV1, BrokerSessionProtocolV1, BrokerSessionSignerReferenceV1,
};
use aos_sandbox_controller_domain::normal_root::{
    NixOfflineEffectApprovalKindV4, fill_nix_offline_static_preimage_v3,
    require_nix_offline_effect_approval_v4, require_nix_offline_static_header_v3,
};
use aos_sandbox_controller_domain::production_operation_compiler::NixFixedDomainPinsDataV2;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() {
    if let Err(error) = run() {
        eprintln!("independent offline approval failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let recovery = match arguments.first().and_then(|value| value.to_str()) {
        Some("initialize") if arguments.len() == 6 => false,
        Some("recover") if arguments.len() == 7 => true,
        _ => {
            return Err(
                "expected initialize/recover PUBLIC DOMAIN PROFILE KEY OUTPUT [HISTORY]".into(),
            );
        }
    };
    let public = read_bounded(Path::new(&arguments[1]), 268)?;
    let domain_bytes = read_bounded(Path::new(&arguments[2]), 1024 * 1024)?;
    let domain = NixFixedDomainPinsDataV2::decode(&domain_bytes)?;
    let profile_bytes = read_bounded(Path::new(&arguments[3]), 1024 * 1024)?;
    let profile: serde_json::Value = serde_json::from_slice(&profile_bytes)?;
    let operator = read_bounded(Path::new(&arguments[4]), 48)?;
    if operator.len() != 48 || operator[..16] == [0; 16] || operator[16..] == [0; 32] {
        return Err("operator key must contain a nonzero ID and seed".into());
    }
    let signing = SigningKey::from_bytes(operator[16..].try_into()?);
    let mut approval = [0; 48];
    approval[..16].copy_from_slice(&operator[..16]);
    approval[16..].copy_from_slice(signing.verifying_key().as_bytes());

    let job = static_approval(&public, &domain, &approval, &signing)?;

    if profile["format"] != "AOS_NIX_OFFLINE_PREPARE_STARTUP_3"
        || profile["hardware"]["format"] != "AOS_NIX_OFFLINE_HARDWARE_5"
    {
        return Err("expected the original V3/V5 hardware profile".into());
    }
    let helper = profile["hardware"]["helper"]["path"]
        .as_str()
        .ok_or("missing helper pin")?;
    let contract = read_bounded(&Path::new(helper).with_extension("contract"), 1024 * 1024)?;
    let contract_digest: [u8; 32] = Sha256::digest(contract).into();
    let pinned_contract: [u8; 32] =
        serde_json::from_value(profile["hardware"]["compiled_contract_sha256"].clone())?;
    if contract_digest != pinned_contract {
        return Err("original helper contract differs from the profile".into());
    }
    let prior = if recovery {
        let history = read_bounded(Path::new(&arguments[6]), 64 * 1024 * 1024)?;
        if history.is_empty() {
            return Err("recovery requires the actual nonempty retained history".into());
        }
        digest(
            b"aos.sandbox.nix-floor.offline-native-history.v4\0",
            &history,
        )
    } else {
        [0; 32]
    };
    let digests = [
        digest(b"aos.sandbox.nix-floor.approved-static-job.v4\0", &job),
        digest(
            b"aos.sandbox.nix-floor.offline-profile.v4\0",
            &profile_bytes,
        ),
        digest(b"aos.sandbox.nix-floor.fixed-domain.v4\0", &domain_bytes),
        contract_digest,
        prior,
    ];
    let effect = effect_approval(&public, &approval, &signing, &digests, recovery)?;

    // A fresh host directory prevents a second approval from silently replacing
    // the originals. Only these public signed records are delivered to the VM.
    let output = Path::new(&arguments[5]);
    fs::DirBuilder::new().mode(0o700).create(output)?;
    write_new(&output.join("approved-job-v3"), &job)?;
    let name = if recovery {
        "approved-recovery-v4"
    } else {
        "approved-effect-v4"
    };
    write_new(&output.join(name), &effect)?;
    Ok(())
}

fn static_approval(
    public: &[u8],
    domain: &NixFixedDomainPinsDataV2,
    approval: &[u8; 48],
    signing: &SigningKey,
) -> Result<[u8; 1332]> {
    let manifest = candidate_manifest(public, domain, approval)?;
    let mut job = [0; 1332];
    job[..8].copy_from_slice(b"AOSNAJ03");
    job[8..10].copy_from_slice(&3_u16.to_be_bytes());
    job[10..12].copy_from_slice(&1_u16.to_be_bytes());
    job[16..32].copy_from_slice(&approval[..16]);
    job[32..40].copy_from_slice(&1_u64.to_be_bytes());
    for (offset, role, nv, salt) in [
        (48, 1, 0x0180_a058_u32, 0x8100_a058_u32),
        (64, 2, 0x0180_a059, 0x8100_a059),
    ] {
        job[offset] = role;
        job[offset + 4..offset + 8].copy_from_slice(&nv.to_be_bytes());
        job[offset + 8..offset + 12].copy_from_slice(&salt.to_be_bytes());
    }
    job[80..348].copy_from_slice(public);
    job[348..1268].copy_from_slice(&manifest.encode());
    require_nix_offline_static_header_v3(&job, approval)?;
    let mut preimage = [0; 1317];
    fill_nix_offline_static_preimage_v3(&job, &mut preimage)?;
    job[1268..].copy_from_slice(&signing.sign(&preimage).to_bytes());

    Ok(job)
}

fn candidate_manifest(
    public: &[u8],
    domain: &NixFixedDomainPinsDataV2,
    approval: &[u8; 48],
) -> Result<BrokerSessionManifestV1> {
    if public.len() != 268
        || public[..12] != *b"AOSNPC03\x03\0\0\0"
        || public[12..28] == [0; 16]
        || public[28..44] != *domain.node().as_bytes()
        || public[44..76] == [0; 32]
    {
        return Err("public candidate shape or node differs".into());
    }
    let roles = [
        BrokerSessionKeyUsageV1::ClientHello,
        BrokerSessionKeyUsageV1::BrokerHello,
        BrokerSessionKeyUsageV1::ClientRecord,
        BrokerSessionKeyUsageV1::BrokerOutcome,
    ];
    let mut keys = Vec::with_capacity(4);
    for (index, role) in roles.into_iter().enumerate() {
        let offset = 76 + index * 48;
        let key_id: [u8; 16] = public[offset..offset + 16].try_into()?;
        let key: [u8; 32] = public[offset + 16..offset + 48].try_into()?;
        if key_id == approval[..16] || key == approval[16..] {
            return Err("candidate key reuses the independent approver".into());
        }
        let controller = index % 2 == 0;
        let signer = BrokerSessionSignerReferenceV1::new(
            [if controller { 0x61 } else { 0x62 }; 16],
            1,
            [if controller { 0x63 } else { 0x64 }; 32],
            key_id,
            1,
            Sha256::digest(key).into(),
            role,
        )?;
        keys.push(BrokerSessionManifestKeyPinV1::new(
            signer, key, 1, 1, false, None,
        )?);
    }
    let keys = keys
        .try_into()
        .map_err(|_| "expected four public candidate keys")?;
    Ok(BrokerSessionManifestV1::new(
        BrokerSessionProtocolV1::Nix,
        BrokerSessionManifestAudienceV1::NodeController,
        1,
        0,
        *domain.domain().as_bytes(),
        *domain.endpoint().as_bytes(),
        1,
        *domain.deployment().as_bytes(),
        1,
        *domain.domain_commitment().as_bytes(),
        1,
        *domain.disclosure().as_bytes(),
        *domain.node().as_bytes(),
        keys,
    )?)
}

fn effect_approval(
    public: &[u8],
    approval: &[u8; 48],
    signing: &SigningKey,
    digests: &[[u8; 32]; 5],
    recovery: bool,
) -> Result<[u8; 304]> {
    let mut bytes = [0; 304];
    bytes[..8].copy_from_slice(b"AOSNAE04");
    bytes[8..10].copy_from_slice(&4_u16.to_be_bytes());
    bytes[10] = if recovery { 2 } else { 1 };
    bytes[11] = 1;
    bytes[16..32].copy_from_slice(&approval[..16]);
    bytes[32..48].copy_from_slice(&public[12..28]);
    bytes[48..64].copy_from_slice(&public[28..44]);
    bytes[64..72].copy_from_slice(&1_u64.to_be_bytes());
    for (index, digest) in digests.iter().enumerate() {
        bytes[80 + index * 32..112 + index * 32].copy_from_slice(digest);
    }
    let mut preimage = [0; b"aos.sandbox.nix-floor.approved-effect.v4\0".len() + 240];
    let prefix = preimage.len() - 240;
    preimage[..prefix].copy_from_slice(b"aos.sandbox.nix-floor.approved-effect.v4\0");
    preimage[prefix..].copy_from_slice(&bytes[..240]);
    bytes[240..].copy_from_slice(&signing.sign(&preimage).to_bytes());
    let kind = if recovery {
        NixOfflineEffectApprovalKindV4::Recover
    } else {
        NixOfflineEffectApprovalKindV4::Initialize
    };
    require_nix_offline_effect_approval_v4(
        &bytes,
        approval,
        public[12..28].try_into()?,
        public[28..44].try_into()?,
        digests,
        kind,
        &mut preimage,
    )?;
    Ok(bytes)
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("fixture input exceeds its bound".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_controller_domain::normal_root::{
        derive_nix_offline_public_candidates_v3, require_nix_offline_public_static_approval_v3,
        require_nix_offline_static_approval_v3,
    };

    #[test]
    fn public_only_operator_output_passes_the_existing_private_candidate_consumer() {
        let domain_bytes = concat!(
            r#"{"version":2,"identities":[811,811,819,819],"#,
            r#""node":"41414141-4141-4141-4141-414141414141","#,
            r#""deployment":"sha256:7171717171717171717171717171717171717171717171717171717171717171","#,
            r#""endpoint":"72727272-7272-7272-7272-727272727272","#,
            r#""domain":"73737373-7373-7373-7373-737373737373","#,
            r#""domain_commitment":"sha256:7474747474747474747474747474747474747474747474747474747474747474","#,
            r#""disclosure":"sha256:7575757575757575757575757575757575757575757575757575757575757575"}"#,
        );
        let domain = NixFixedDomainPinsDataV2::decode(domain_bytes.as_bytes()).unwrap();
        let operator = SigningKey::from_bytes(&[0x90; 32]);
        let mut approval = [0x51; 48];
        approval[16..].copy_from_slice(operator.verifying_key().as_bytes());
        let mut private = [0; 336];
        private[..8].copy_from_slice(b"AOSNPK03");
        private[8..10].copy_from_slice(&3_u16.to_le_bytes());
        for index in 0..4 {
            private[16 + index * 48..32 + index * 48].fill(10 + index as u8);
            private[32 + index * 48..64 + index * 48].fill(20 + index as u8);
            private[208 + index * 32..240 + index * 32].fill(30 + index as u8);
        }
        let mut public = [0; 268];
        derive_nix_offline_public_candidates_v3(
            &private,
            &[0x52; 16],
            domain.node().as_bytes(),
            &approval,
            &mut public,
        )
        .unwrap();

        // The signer receives no private candidate. The production comparator
        // independently derives and compares all four keys from the original.
        let job = static_approval(&public, &domain, &approval, &operator).unwrap();
        let mut derived = [0; 268];
        let mut preimage = [0; 1317];
        require_nix_offline_static_approval_v3(
            &private,
            &public,
            &job,
            domain.node().as_bytes(),
            &approval,
            &mut derived,
            &mut preimage,
        )
        .unwrap();

        let mut changed = public;
        require_nix_offline_public_static_approval_v3(
            &public,
            &job,
            domain.node().as_bytes(),
            &approval,
            &mut preimage,
        )
        .unwrap();
        assert!(
            require_nix_offline_public_static_approval_v3(
                &public,
                &job,
                &[0x42; 16],
                &approval,
                &mut preimage,
            )
            .is_err()
        );
        let mut forged_job = job;
        forged_job[1268] ^= 1;
        assert!(
            require_nix_offline_public_static_approval_v3(
                &public,
                &forged_job,
                domain.node().as_bytes(),
                &approval,
                &mut preimage,
            )
            .is_err()
        );
        changed[92] ^= 1;
        assert!(
            require_nix_offline_public_static_approval_v3(
                &changed,
                &job,
                domain.node().as_bytes(),
                &approval,
                &mut preimage,
            )
            .is_err()
        );
        assert!(
            require_nix_offline_static_approval_v3(
                &private,
                &changed,
                &job,
                domain.node().as_bytes(),
                &approval,
                &mut derived,
                &mut preimage,
            )
            .is_err()
        );
    }
}
