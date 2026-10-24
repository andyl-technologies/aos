//! Encodes independently signed ONLINE floor initialization DATA.
//!
//! Provisioning and consumption share the exact empty anchor, signed seed,
//! initialized main-journal cut, initial sidecar checkpoint and NV equation.
//! Signature verification establishes historical DATA authenticity only. It
//! never opens a journal, writes an NV index or establishes currentness.
//!
//! ```text
//! AOSNXS02/version2/reserved | profile532 | emptyHEAD32 | signature64
//! AOSNXG02/version2/reserved | signedSeed640 | checkpoint156 | NV32 | signature64
//! ```

use aos_sandbox_model::journal_namespace::RecordNamespace;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::nix_online_floor_profile::OnlineFloorProfileV2;

/// Fixes the canonical signed seed width.
pub const SEED_BYTES_V2: usize = 640;
/// Fixes the canonical signed initialization width.
pub const INITIALIZATION_BYTES_V2: usize = 904;

const SEED_BODY_BYTES: usize = 576;
const INITIAL_BODY_BYTES: usize = 840;
const SEED_DOMAIN: &[u8] = b"aos.sandbox.nix.online-floor.seed.v2\0";
const INITIAL_DOMAIN: &[u8] = b"aos.sandbox.nix.online-floor.initial-cut.v2\0";
const HEAD_DOMAIN: &[u8] = b"aos.sandbox.nix.online-floor.head.v1\0";
const EXTEND_DOMAIN: &[u8] = b"aos.sandbox.nix.online-floor.extend.v1\0";

/// Reports a noncanonical or unauthenticated initialization DATA record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid independently signed ONLINE floor initialization")]
pub struct OnlineFloorInitializationErrorV2;

use OnlineFloorInitializationErrorV2 as Error;

/// Retains a canonical signed seed without owning its issuer or a live floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineFloorSeedDataV2 {
    profile: OnlineFloorProfileV2,
    signature: [u8; 64],
}

impl OnlineFloorSeedDataV2 {
    /// Prepares the complete domain-separated message for an external issuer.
    ///
    /// This method owns no private key and authenticates no profile origin.
    #[must_use]
    pub fn signing_message(profile: OnlineFloorProfileV2) -> Vec<u8> {
        message(SEED_DOMAIN, &seed_body(profile))
    }

    /// Joins an external signature to its exact canonical profile and anchor.
    ///
    /// # Errors
    /// Rejects malformed or mismatched issuer records and invalid signatures.
    pub fn from_signature(
        profile: OnlineFloorProfileV2,
        issuer: &[u8; 48],
        signature: [u8; 64],
    ) -> Result<Self, Error> {
        verify(profile, issuer, &Self::signing_message(profile), &signature)?;
        Ok(Self { profile, signature })
    }

    /// Decodes and verifies a complete canonical signed seed.
    ///
    /// # Errors
    /// Rejects width, framing, profile, empty-anchor or signature substitutions.
    pub fn decode(bytes: &[u8], issuer: &[u8; 48]) -> Result<Self, Error> {
        if bytes.len() != SEED_BYTES_V2 || bytes[..12] != *b"AOSNXS02\0\x02\0\0" {
            return Err(Error);
        }
        let profile = OnlineFloorProfileV2::decode(&bytes[12..544]).map_err(|_| Error)?;
        if bytes[..SEED_BODY_BYTES] != seed_body(profile) {
            return Err(Error);
        }
        let signature = bytes[SEED_BODY_BYTES..].try_into().map_err(|_| Error)?;
        Self::from_signature(profile, issuer, signature)
    }

    /// Returns the canonical profile DATA bound by the signature.
    #[must_use]
    pub const fn profile(&self) -> OnlineFloorProfileV2 {
        self.profile
    }

    /// Encodes the complete canonical signed seed.
    #[must_use]
    pub fn encode(&self) -> [u8; SEED_BYTES_V2] {
        let mut bytes = [0; SEED_BYTES_V2];
        bytes[..SEED_BODY_BYTES].copy_from_slice(&seed_body(self.profile));
        bytes[SEED_BODY_BYTES..].copy_from_slice(&self.signature);
        bytes
    }

    /// Returns the sole initialized main-journal key DATA.
    #[must_use]
    pub fn journal_key(&self) -> [u8; 24] {
        let mut key = [0; 24];
        key[..8].copy_from_slice(b"AOSNXK01");
        key[8..].copy_from_slice(&self.profile.encode()[256..272]);
        key
    }
}

/// Retains canonical signed initialization DATA without publishing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnlineFloorInitializationDataV2 {
    seed: OnlineFloorSeedDataV2,
    signature: [u8; 64],
}

impl OnlineFloorInitializationDataV2 {
    /// Prepares the exact initial-cut message for the independent ONLINE issuer.
    #[must_use]
    pub fn signing_message(seed: &OnlineFloorSeedDataV2) -> Vec<u8> {
        message(INITIAL_DOMAIN, &initial_body(seed))
    }

    /// Verifies an external signature over the complete canonical initial cut.
    ///
    /// # Errors
    /// Rejects a substituted issuer, seed signature or initialization signature.
    pub fn from_signature(
        seed: OnlineFloorSeedDataV2,
        issuer: &[u8; 48],
        signature: [u8; 64],
    ) -> Result<Self, Error> {
        verify(
            seed.profile,
            issuer,
            &Self::signing_message(&seed),
            &signature,
        )?;
        Ok(Self { seed, signature })
    }

    /// Decodes both signatures and requires the exact canonical initialization.
    ///
    /// # Errors
    /// Rejects altered framing, profile, anchors, seed, main cut, checkpoint,
    /// initial NV equation, trailing data or either independent signature.
    pub fn decode(bytes: &[u8], issuer: &[u8; 48]) -> Result<Self, Error> {
        if bytes.len() != INITIALIZATION_BYTES_V2 || bytes[..12] != *b"AOSNXG02\0\x02\0\0" {
            return Err(Error);
        }
        let seed = OnlineFloorSeedDataV2::decode(&bytes[12..652], issuer)?;
        if bytes[..INITIAL_BODY_BYTES] != initial_body(&seed) {
            return Err(Error);
        }
        let signature = bytes[INITIAL_BODY_BYTES..].try_into().map_err(|_| Error)?;
        Self::from_signature(seed, issuer, signature)
    }

    /// Returns the signed profile DATA without authenticating runtime originals.
    #[must_use]
    pub const fn profile(&self) -> OnlineFloorProfileV2 {
        self.seed.profile
    }

    /// Borrows the canonical signed seed DATA.
    #[must_use]
    pub const fn seed(&self) -> &OnlineFloorSeedDataV2 {
        &self.seed
    }

    /// Encodes the complete signed initialization record.
    #[must_use]
    pub fn encode(&self) -> [u8; INITIALIZATION_BYTES_V2] {
        let mut bytes = [0; INITIALIZATION_BYTES_V2];
        bytes[..INITIAL_BODY_BYTES].copy_from_slice(&initial_body(&self.seed));
        bytes[INITIAL_BODY_BYTES..].copy_from_slice(&self.signature);
        bytes
    }

    /// Returns the exact initial sidecar checkpoint DATA.
    #[must_use]
    pub fn checkpoint(&self) -> [u8; 156] {
        checkpoint(&self.seed)
    }

    /// Computes the expected first NV value without contacting a TPM.
    #[must_use]
    pub fn nv_value(&self) -> [u8; 32] {
        nv_value(&self.checkpoint())
    }
}

fn verify(
    profile: OnlineFloorProfileV2,
    issuer: &[u8; 48],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), Error> {
    if issuer[..16] == [0; 16]
        || issuer[16..] == [0; 32]
        || profile.encode()[272..304] != Sha256::digest(issuer)[..]
    {
        return Err(Error);
    }
    let public = issuer[16..].try_into().map_err(|_| Error)?;
    let verifier = VerifyingKey::from_bytes(&public).map_err(|_| Error)?;
    verifier
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| Error)
}

fn message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len() + body.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(body);
    bytes
}

fn seed_body(profile: OnlineFloorProfileV2) -> [u8; SEED_BODY_BYTES] {
    let mut bytes = [0; SEED_BODY_BYTES];
    bytes[..12].copy_from_slice(b"AOSNXS02\0\x02\0\0");
    bytes[12..544].copy_from_slice(&profile.encode());
    bytes[544..].copy_from_slice(&main_head(profile, None));
    bytes
}

fn main_head(profile: OnlineFloorProfileV2, seed: Option<&OnlineFloorSeedDataV2>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(HEAD_DOMAIN);
    digest.update(profile.scope());
    digest.update([RecordNamespace::BrokerSessionTraffic as u8]);
    digest.update(if seed.is_some() { 4_u64 } else { 1_u64 }.to_be_bytes());
    if let Some(seed) = seed {
        digest.update(24_u64.to_be_bytes());
        digest.update(seed.journal_key());
        digest.update((SEED_BYTES_V2 as u64).to_be_bytes());
        digest.update(seed.encode());
    }
    digest.update(u64::from(seed.is_some()).to_be_bytes());
    digest.finalize().into()
}

fn checkpoint(seed: &OnlineFloorSeedDataV2) -> [u8; 156] {
    let mut bytes = [0; 156];
    bytes[..12].copy_from_slice(b"AOSNXC01\0\x01\0\0");
    bytes[12..20].copy_from_slice(&1_u64.to_be_bytes());
    bytes[20..52].copy_from_slice(&seed.profile.scope());
    bytes[52..60].copy_from_slice(&4_u64.to_be_bytes());
    bytes[60..92].copy_from_slice(&main_head(seed.profile, Some(seed)));
    bytes
}

fn nv_value(checkpoint: &[u8; 156]) -> [u8; 32] {
    let mut extend = Sha256::new();
    extend.update(EXTEND_DOMAIN);
    extend.update(checkpoint);

    let mut nv = Sha256::new();
    nv.update([0; 32]);
    nv.update(extend.finalize());
    nv.finalize().into()
}

fn initial_body(seed: &OnlineFloorSeedDataV2) -> [u8; INITIAL_BODY_BYTES] {
    let mut bytes = [0; INITIAL_BODY_BYTES];
    bytes[..12].copy_from_slice(b"AOSNXG02\0\x02\0\0");
    bytes[12..652].copy_from_slice(&seed.encode());
    let checkpoint = checkpoint(seed);
    bytes[652..808].copy_from_slice(&checkpoint);
    bytes[808..].copy_from_slice(&nv_value(&checkpoint));
    bytes
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use crate::nix_online_floor_profile::{OnlineFloorProfileFieldsV2, OnlineFloorRoleV2};

    use super::*;

    fn fixture(role: OnlineFloorRoleV2) -> (SigningKey, [u8; 48], OnlineFloorInitializationDataV2) {
        let signing = SigningKey::from_bytes(&[role as u8; 32]);
        let mut issuer = [3; 48];
        issuer[16..].copy_from_slice(&signing.verifying_key().to_bytes());
        let mut salt_name = [4; 34];
        salt_name[..2].copy_from_slice(&[0, 0x0b]);
        let profile = OnlineFloorProfileV2::from_fields(OnlineFloorProfileFieldsV2 {
            role,
            node: [1; 16],
            deployment: [2; 32],
            endpoint: [3; 16],
            domain: [4; 16],
            domain_commitment: [5; 32],
            disclosure: [6; 32],
            public_set_digest: [7; 32],
            startup_digest: [8; 32],
            stable_endpoint: [9; 32],
            genesis_id: [10; 16],
            issuer_digest: Sha256::digest(issuer).into(),
            auth_digest: Sha256::digest([31; 32]).into(),
            salt_name,
            snapshot_digest: [11; 32],
        })
        .unwrap();

        let signature = signing
            .sign(&OnlineFloorSeedDataV2::signing_message(profile))
            .to_bytes();
        let seed = OnlineFloorSeedDataV2::from_signature(profile, &issuer, signature).unwrap();
        let signature = signing
            .sign(&OnlineFloorInitializationDataV2::signing_message(&seed))
            .to_bytes();
        let initialization =
            OnlineFloorInitializationDataV2::from_signature(seed, &issuer, signature).unwrap();
        (signing, issuer, initialization)
    }

    #[test]
    fn both_purposes_round_trip_complete_initialization_data() {
        let mut scopes = Vec::new();
        for role in [OnlineFloorRoleV2::Controller, OnlineFloorRoleV2::Owner] {
            let (_, issuer, initialization) = fixture(role);
            let bytes = initialization.encode();

            assert_eq!(
                OnlineFloorInitializationDataV2::decode(&bytes, &issuer).unwrap(),
                initialization
            );
            assert_eq!(
                OnlineFloorSeedDataV2::decode(&bytes[12..652], &issuer).unwrap(),
                *initialization.seed()
            );
            assert_eq!(initialization.profile().role(), role);
            assert_eq!(bytes[652..808], initialization.checkpoint());
            assert_eq!(bytes[808..840], initialization.nv_value());
            assert_ne!(initialization.nv_value(), [0; 32]);
            assert_eq!(bytes[704..712], 4_u64.to_be_bytes());
            assert_eq!(bytes[744..808], [0; 64]);
            scopes.push(initialization.profile().scope());
        }
        assert_ne!(scopes[0], scopes[1]);
    }

    #[test]
    fn substitutions_and_noncanonical_widths_are_rejected() {
        let (_, issuer, initialization) = fixture(OnlineFloorRoleV2::Controller);
        let bytes = initialization.encode();

        for offset in [
            0, 8, 10, 12, 20, 24, 36, 284, 556, 588, 651, 652, 664, 672, 704, 712, 744, 776, 808,
            840, 903,
        ] {
            let mut changed = bytes;
            changed[offset] ^= 0x80;
            assert!(
                OnlineFloorInitializationDataV2::decode(&changed, &issuer).is_err(),
                "offset {offset}"
            );
        }
        for length in [0, 12, 640, 840, 903, 905] {
            let mut changed = bytes.to_vec();
            changed.resize(length, 0);
            assert!(OnlineFloorInitializationDataV2::decode(&changed, &issuer).is_err());
        }
        let mut other_issuer = issuer;
        other_issuer[0] ^= 1;
        assert!(OnlineFloorInitializationDataV2::decode(&bytes, &other_issuer).is_err());

        let (_, owner_issuer, _) = fixture(OnlineFloorRoleV2::Owner);
        assert!(OnlineFloorInitializationDataV2::decode(&bytes, &owner_issuer).is_err());
    }

    #[test]
    fn valid_signatures_cannot_authorize_a_different_initial_cut() {
        let (signing, issuer, initialization) = fixture(OnlineFloorRoleV2::Controller);
        let bytes = initialization.encode();

        for offset in [652, 660, 664, 672, 704, 712, 744, 776, 808] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            let signature = signing.sign(&message(INITIAL_DOMAIN, &changed[..840]));
            changed[840..].copy_from_slice(&signature.to_bytes());
            assert!(
                OnlineFloorInitializationDataV2::decode(&changed, &issuer).is_err(),
                "offset {offset}"
            );
        }

        let mut seed = initialization.seed().encode();
        seed[544] ^= 1;
        let signature = signing.sign(&message(SEED_DOMAIN, &seed[..576]));
        seed[576..].copy_from_slice(&signature.to_bytes());
        assert!(OnlineFloorSeedDataV2::decode(&seed, &issuer).is_err());
    }
}
