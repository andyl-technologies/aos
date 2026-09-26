//! Exercises the production Cache-only signer readback on two live idmapped views.
//!
//! This VM probe supplies a fixed test key and challenge. It creates neither
//! Cache state nor policy authority, and it never handles a deployed credential.

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use aos_sandbox::cache_residency::{
    CacheOwnerReadbackChallengeV1, PinnedCacheOwnerReadbackSignerV1,
    encode_cache_owner_readback_signer_credential_v1, sign_fixed_signer_cache_owner_readback_v2,
    verify_closed_cache_owner_readback_v2,
};
use aos_sandbox::policy_compiler::{
    read_fixed_policy_cache_hold_v1, verify_fixed_policy_cache_owner_readback_v2,
};
use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;

const CONTROLLER_UID: u32 = 811;
const SIGNER_UID: u32 = 813;
const MEMORY_CEILING_BYTES: u64 = 1024 * 1024;
const SIGNER_GENERATION: u64 = 7;
const PACKET_PATH: &str = "/tmp/cache-signer-v2-packet";

fn main() {
    if let Err(error) = run() {
        eprintln!("Cache signer VM qualification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let challenge = CacheOwnerReadbackChallengeV1::new([8; 16], ObjectDigest::from_bytes([9; 32]))?;
    let key = SigningKey::from_bytes(&[7; 32]);
    let pin =
        encode_cache_owner_readback_signer_credential_v1(SIGNER_GENERATION, &key.verifying_key())?;
    let pin = PinnedCacheOwnerReadbackSignerV1::decode(&pin)?;
    let mode = std::env::args().nth(1);
    if matches!(mode.as_deref(), Some("root-verify" | "root-reject")) {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err("Root readback probe requires the cap-empty root UID".into());
        }
        let result = verify_root_view(challenge, &pin);
        return match (mode.as_deref(), result) {
            (Some("root-verify"), Ok(())) => {
                println!("cache-root-protected-readback:PASS");
                Ok(())
            }
            (Some("root-reject"), Err(_)) => {
                println!("cache-root-unsafe-protected-view-rejected:PASS");
                Ok(())
            }
            _ => Err("unexpected Root Cache readback result".into()),
        };
    }
    if rustix::process::geteuid().as_raw() != SIGNER_UID {
        return Err("probe must run as the isolated Cache signer".into());
    }

    let result = sign_fixed_signer_cache_owner_readback_v2(
        MEMORY_CEILING_BYTES,
        challenge,
        SIGNER_GENERATION,
        &key,
    );

    match std::env::args().nth(1).as_deref() {
        Some("sign") => {
            let packet = result?;
            let verified =
                verify_closed_cache_owner_readback_v2(&packet, &pin, challenge, CONTROLLER_UID)?;
            if verified.manifest_identity() == (0, 0) {
                return Err("signed Cache receipt lacks the physical manifest".into());
            }
            fs::write(PACKET_PATH, packet)?;
            fs::set_permissions(PACKET_PATH, fs::Permissions::from_mode(0o644))?;
            println!("cache-signer-joined-readback:PASS");
            Ok(())
        }
        Some("reject") if result.is_err() => {
            println!("cache-signer-unsafe-view-rejected:PASS");
            Ok(())
        }
        _ => Err("unexpected Cache signer probe result or mode".into()),
    }
}

fn verify_root_view(
    challenge: CacheOwnerReadbackChallengeV1,
    pin: &PinnedCacheOwnerReadbackSignerV1,
) -> Result<(), Box<dyn Error>> {
    let packet = fs::read(PACKET_PATH)?;
    let observed = read_fixed_policy_cache_hold_v1()?;
    verify_fixed_policy_cache_owner_readback_v2(
        &packet,
        pin,
        challenge,
        CONTROLLER_UID,
        observed.hold,
    )?;
    Ok(())
}
