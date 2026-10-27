//! Shares canonical public METHOD46 provisioning DATA without native authority.
//!
//! The initial Source and normal Security owner decode the same public bytes.
//! Files, delivery provenance, independent approval, private index auth,
//! authenticated TPM observations and publication remain with their owners.
//!
//! ```text
//! AOSBTP01 | version:u16be=1 | reserved:u16be=0 | endpoint:u8 |
//! reserved:3 | node:16 | deployment-epoch:16 | stable-endpoint:32 |
//! salt-key-Name-digest:32                                      (112 bytes)
//! AOSBTD01 | version:u16be=1 | reserved:u16be=0 | profile:112 |
//! salt-key-Name:34 | reserved:2                                (160 bytes)
//! ```

use sha2::{Digest as _, Sha256};

/// Bounds the canonical public METHOD46 profile.
pub const PROFILE_BYTES: usize = 112;
/// Bounds the canonical public METHOD46 provisioning credential.
pub const PROVISION_BYTES: usize = 160;

const SCOPE_DOMAIN: &[u8] = b"aos.sandbox.broker-session.tpm-floor.scope.v1\0";

/// Refuses malformed framing or mismatched endpoint/salt DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Method46ProvisionDataErrorV1 {
    /// The fixed shape, reserved bytes or sentinel fields are noncanonical.
    #[error("noncanonical METHOD46 provisioning DATA")]
    Encoding,
    /// The selected endpoint or salt Name commitment differs.
    #[error("METHOD46 provisioning DATA does not match")]
    Provisioning,
}

/// Selects a fixed endpoint and a collision-checked local owner NV handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method46EndpointDataV1 {
    /// Selects the original Controller endpoint's local NV index.
    ControllerStorageClient = 1,
    /// Selects the original Storage endpoint's local NV index.
    StorageBroker = 2,
}

impl Method46EndpointDataV1 {
    /// Returns the fixed local owner index as nonauthorizing DATA.
    pub const fn nv_index(self) -> u32 {
        match self {
            Self::ControllerStorageClient => 0x0180_a046,
            Self::StorageBroker => 0x0180_a047,
        }
    }
}

/// Carries canonical deployment, endpoint and salt-commitment claims as DATA.
///
/// Decoding or constructing these claims grants no provisioning or TPM authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Method46ProfileDataV1 {
    endpoint: Method46EndpointDataV1,
    node: [u8; 16],
    deployment_epoch: [u8; 16],
    stable_endpoint: [u8; 32],
    salt_key_name_digest: [u8; 32],
}

impl Method46ProfileDataV1 {
    /// Constructs shape-only provisioning claims without installing an NV index.
    ///
    /// # Errors
    ///
    /// Rejects zero node, deployment, endpoint or salt commitments.
    pub fn new(
        endpoint: Method46EndpointDataV1,
        node: [u8; 16],
        deployment_epoch: [u8; 16],
        stable_endpoint: [u8; 32],
        salt_key_name_digest: [u8; 32],
    ) -> Result<Self, Method46ProvisionDataErrorV1> {
        if node == [0; 16]
            || deployment_epoch == [0; 16]
            || stable_endpoint == [0; 32]
            || salt_key_name_digest == [0; 32]
        {
            return Err(Method46ProvisionDataErrorV1::Encoding);
        }
        Ok(Self {
            endpoint,
            node,
            deployment_epoch,
            stable_endpoint,
            salt_key_name_digest,
        })
    }

    /// Returns the fixed Broker endpoint DATA.
    pub const fn endpoint(self) -> Method46EndpointDataV1 {
        self.endpoint
    }

    /// Returns the independently supplied stable endpoint claim.
    pub const fn stable_endpoint(self) -> [u8; 32] {
        self.stable_endpoint
    }

    /// Returns the provisioned node claim.
    pub const fn node(self) -> [u8; 16] {
        self.node
    }

    /// Returns the provisioned salt Name commitment.
    pub const fn salt_key_name_digest(self) -> [u8; 32] {
        self.salt_key_name_digest
    }

    /// Encodes the original fixed 112-byte Broker provisioning claim.
    pub fn encode(self) -> [u8; PROFILE_BYTES] {
        let mut bytes = [0; PROFILE_BYTES];
        header(&mut bytes, b"AOSBTP01");
        bytes[12] = self.endpoint as u8;
        bytes[16..32].copy_from_slice(&self.node);
        bytes[32..48].copy_from_slice(&self.deployment_epoch);
        bytes[48..80].copy_from_slice(&self.stable_endpoint);
        bytes[80..112].copy_from_slice(&self.salt_key_name_digest);
        bytes
    }

    /// Decodes the original fixed Broker provisioning claim.
    ///
    /// # Errors
    ///
    /// Rejects noncanonical framing, reserved bytes, endpoint codes or sentinel fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, Method46ProvisionDataErrorV1> {
        require_header(bytes, b"AOSBTP01", PROFILE_BYTES)?;
        if bytes[13..16] != [0; 3] {
            return Err(Method46ProvisionDataErrorV1::Encoding);
        }
        let endpoint = match bytes[12] {
            1 => Method46EndpointDataV1::ControllerStorageClient,
            2 => Method46EndpointDataV1::StorageBroker,
            _ => return Err(Method46ProvisionDataErrorV1::Encoding),
        };
        Self::new(
            endpoint,
            array(bytes, 16)?,
            array(bytes, 32)?,
            array(bytes, 48)?,
            array(bytes, 80)?,
        )
    }

    /// Computes the original Broker scope DATA without admitting a provisioned owner.
    pub fn scope(self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(SCOPE_DOMAIN);
        digest.update(self.encode());
        digest.finalize().into()
    }
}
/// Decodes the public credential and compares its selected endpoint and salt Name.
///
/// This is canonical DATA only; successful decoding authenticates no file,
/// supplier, approval or private key and permits no TPM or journal operation.
///
/// # Errors
/// Rejects noncanonical framing, reserved bytes or sentinel claims, a different
/// endpoint, malformed SHA-256 salt Name or mismatched salt commitment.
pub fn decode_provision_v1(
    bytes: &[u8],
    endpoint: Method46EndpointDataV1,
) -> Result<(Method46ProfileDataV1, [u8; 34]), Method46ProvisionDataErrorV1> {
    if bytes.len() != PROVISION_BYTES
        || &bytes[..8] != b"AOSBTD01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..12] != [0; 2]
        || bytes[158..160] != [0; 2]
    {
        return Err(Method46ProvisionDataErrorV1::Encoding);
    }
    let profile = Method46ProfileDataV1::decode(&bytes[12..12 + PROFILE_BYTES])?;
    let salt_name: [u8; 34] = bytes[124..158]
        .try_into()
        .map_err(|_| Method46ProvisionDataErrorV1::Encoding)?;
    if profile.endpoint() != endpoint
        || salt_name[..2] != 0x000b_u16.to_be_bytes()
        || salt_name[2..] == [0; 32]
        || Sha256::digest(salt_name).as_slice() != profile.salt_key_name_digest()
    {
        return Err(Method46ProvisionDataErrorV1::Provisioning);
    }
    Ok((profile, salt_name))
}

fn header(bytes: &mut [u8], magic: &[u8; 8]) {
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
}

fn require_header(
    bytes: &[u8],
    magic: &[u8; 8],
    length: usize,
) -> Result<(), Method46ProvisionDataErrorV1> {
    if bytes.len() != length
        || &bytes[..8] != magic
        || bytes[8..10] != [0, 1]
        || bytes[10..12] != [0; 2]
    {
        return Err(Method46ProvisionDataErrorV1::Encoding);
    }
    Ok(())
}

fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], Method46ProvisionDataErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(Method46ProvisionDataErrorV1::Encoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINTS: [Method46EndpointDataV1; 2] = [
        Method46EndpointDataV1::ControllerStorageClient,
        Method46EndpointDataV1::StorageBroker,
    ];

    fn public_fixture(endpoint: Method46EndpointDataV1) -> [u8; PROVISION_BYTES] {
        let mut name = [8; 34];
        name[..2].copy_from_slice(&0x000b_u16.to_be_bytes());
        let profile = Method46ProfileDataV1::new(
            endpoint,
            [1; 16],
            [2; 16],
            [3; 32],
            Sha256::digest(name).into(),
        )
        .unwrap();
        let mut bytes = [0; PROVISION_BYTES];
        bytes[..12].copy_from_slice(b"AOSBTD01\0\x01\0\0");
        bytes[12..124].copy_from_slice(&profile.encode());
        bytes[124..158].copy_from_slice(&name);
        bytes
    }

    #[test]
    fn scope_preserves_the_existing_profile_wire_vector() {
        let profile = Method46ProfileDataV1::new(
            Method46EndpointDataV1::ControllerStorageClient,
            [1; 16],
            [2; 16],
            [3; 32],
            [4; 32],
        )
        .unwrap();

        assert_eq!(
            profile.scope(),
            [
                0xb6, 0xeb, 0x9d, 0xba, 0x08, 0x0a, 0x32, 0x3b, 0x6f, 0x11, 0x93, 0x7d, 0xf7, 0x0e,
                0x87, 0xa8, 0xa1, 0x98, 0x2e, 0xe3, 0x1e, 0x1a, 0x99, 0xff, 0x61, 0x2e, 0xf2, 0xb7,
                0xa6, 0x75, 0x90, 0x2e
            ]
        );
        assert_eq!(
            Method46ProfileDataV1::decode(&profile.encode()).unwrap(),
            profile
        );
    }

    #[test]
    fn provision_rejects_every_truncation_append_and_reserved_field() {
        for endpoint in ENDPOINTS {
            let bytes = public_fixture(endpoint);
            assert_eq!(
                decode_provision_v1(&bytes, endpoint).unwrap().0.endpoint(),
                endpoint
            );
            for length in 0..PROVISION_BYTES {
                assert!(
                    decode_provision_v1(&bytes[..length], endpoint).is_err(),
                    "length {length}"
                );
            }
            assert!(decode_provision_v1(&[bytes.as_slice(), &[0]].concat(), endpoint).is_err());
            for offset in [0, 8, 9, 10, 11, 12, 20, 21, 22, 23, 25, 26, 27, 158, 159] {
                let mut changed = bytes;
                changed[offset] ^= 1;
                assert!(
                    decode_provision_v1(&changed, endpoint).is_err(),
                    "offset {offset}"
                );
            }
        }
    }

    #[test]
    fn provision_refuses_crossed_roles_and_changed_or_malformed_salt_names() {
        for endpoint in ENDPOINTS {
            let bytes = public_fixture(endpoint);
            let foreign = ENDPOINTS
                .into_iter()
                .find(|candidate| *candidate != endpoint)
                .unwrap();
            assert_eq!(
                decode_provision_v1(&bytes, foreign),
                Err(Method46ProvisionDataErrorV1::Provisioning)
            );
            for offset in [124, 125, 126, 157] {
                let mut changed = bytes;
                changed[offset] ^= 1;
                assert_eq!(
                    decode_provision_v1(&changed, endpoint),
                    Err(Method46ProvisionDataErrorV1::Provisioning)
                );
            }
            let mut changed = bytes;
            changed[126..158].fill(0);
            let digest = Sha256::digest(&changed[124..158]);
            changed[92..124].copy_from_slice(&digest);
            assert_eq!(
                decode_provision_v1(&changed, endpoint),
                Err(Method46ProvisionDataErrorV1::Provisioning)
            );
        }
    }

    #[test]
    fn profile_rejects_sentinel_claims_and_unknown_endpoint_codes() {
        for endpoint in ENDPOINTS {
            let provision = public_fixture(endpoint);
            let profile = &provision[12..124];
            for (start, end) in [(16, 32), (32, 48), (48, 80), (80, 112)] {
                let mut changed = profile.to_vec();
                changed[start..end].fill(0);
                assert_eq!(
                    Method46ProfileDataV1::decode(&changed),
                    Err(Method46ProvisionDataErrorV1::Encoding)
                );
            }
            for code in [0, 3, 255] {
                let mut changed = profile.to_vec();
                changed[12] = code;
                assert_eq!(
                    Method46ProfileDataV1::decode(&changed),
                    Err(Method46ProvisionDataErrorV1::Encoding)
                );
            }
        }
    }
}
