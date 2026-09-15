//! Pure deterministic AOSSPL effect, backend-plan, and lease identities.
//!
//! These functions authenticate nothing and grant no journal, backend,
//! signing, descriptor, or send authority. They exist so every layer validates
//! one canonical derivation instead of duplicating runtime-local domains.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

fn truncated_id(domain: &[u8], components: &[&[u8]]) -> Option<[u8; 16]> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for component in components {
        hasher.update(component);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&digest[..16]);
    (identity != [0; 16]).then_some(identity)
}

/// Derives one acquisition backend-effect identity.
#[must_use]
pub fn acquire_effect_id_v1(
    acquisition_id: ObjectDigest,
    attempt_digest: ObjectDigest,
) -> Option<[u8; 16]> {
    truncated_id(
        b"aos.sandbox.source-provider.acquire-effect.v1\0",
        &[acquisition_id.as_bytes(), attempt_digest.as_bytes()],
    )
}

/// Derives one immutable backend-plan identity.
#[must_use]
pub fn acquire_backend_plan_id_v1(
    intent_digest: ObjectDigest,
    catalog_generation: u64,
    catalog_digest: ObjectDigest,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.source-provider.acquire-backend-plan.v1\0");
    hasher.update(intent_digest.as_bytes());
    hasher.update(catalog_generation.to_be_bytes());
    hasher.update(catalog_digest.as_bytes());
    hasher.finalize().into()
}

/// Derives one release backend-effect identity.
#[must_use]
pub fn release_effect_id_v1(
    acquisition_id: ObjectDigest,
    attempt_digest: ObjectDigest,
    release_generation: u64,
) -> Option<[u8; 16]> {
    truncated_id(
        b"aos.sandbox.source-provider.release-effect.v1\0",
        &[
            acquisition_id.as_bytes(),
            attempt_digest.as_bytes(),
            &release_generation.to_be_bytes(),
        ],
    )
}

/// Derives one globally generation-bound lease identity.
#[must_use]
pub fn lease_id_v1(
    acquisition_id: ObjectDigest,
    lease_generation: u64,
    backend_id: [u8; 32],
) -> Option<[u8; 16]> {
    truncated_id(
        b"aos.sandbox.source-provider.lease-id.v1\0",
        &[
            acquisition_id.as_bytes(),
            &lease_generation.to_be_bytes(),
            &backend_id,
        ],
    )
}
