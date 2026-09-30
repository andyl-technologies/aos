//! Closed deployment preparation records, independent of runtime execution.
//!
//! The provisioner supplies the signed genesis before startup. These records
//! contain neither a runtime handle nor a guest session or PayloadBootID.
//! Decoding and signature verification establish comparison data only; live
//! journal locks, authenticated NV and physical process custody remain local.
//!
//! ```text
//! AOSRDG01 | node:16 | deployment:16 | signer:32 | NV-Name:34 |
//! salt-Name:34 | eight SHA-256 commitments | uid-start:u32be | count:u32be
//! AOSRDQ01 | nonce:32 | kernel-boot:16 | genesis-digest:32
//! AOSRDR01 | query | generation:u64be | monotonic-epoch:u64be |
//! current-NV:32 | prepared-HEAD:32 | specimen-profile:32 | signature:64
//! ```

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

/// Fixed publisher endpoint; this is not a public broker method.
pub const DEPLOYMENT_SOCKET_V1: &str = "/run/aos/sandbox/runtime-deployment.sock";
/// Separately provisioned deployment-only SHA-256 extend index.
pub const DEPLOYMENT_NV_INDEX_V1: u32 = 0x0180_a055;
/// Deployment-only persistent salt key, unrelated to method 46.
pub const DEPLOYMENT_SALT_HANDLE_V1: u32 = 0x8100_a055;
/// Fixed incarnation reserved for the deployment specimen, never a runtime.
pub const SPECIMEN_INCARNATION_V1: [u8; 16] = [0x55; 16];
/// Exact externally provisioned genesis byte count, excluding its signature.
pub const DEPLOYMENT_GENESIS_BYTES_V1: usize = 404;
/// Exact fresh-read request byte count.
pub const DEPLOYMENT_QUERY_BYTES_V1: usize = 88;
/// Exact signed response byte count.
pub const DEPLOYMENT_RECEIPT_BYTES_V1: usize = 272;

/// Reports a malformed or incorrectly signed deployment comparison record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid fixed deployment preparation record")]
pub struct DeploymentWireErrorV1;

/// Binds independently provisioned deployment identity and immutable inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentGenesisV1 {
    /// Provisioned node identity, independent of a runtime manifest.
    pub node: [u8; 16],
    /// Provisioned deployment generation identity.
    pub deployment: [u8; 16],
    /// Deployment-only Ed25519 verification key.
    pub signer: [u8; 32],
    /// Canonical SHA-256 Name of the fixed deployment NV index.
    pub nv_name: [u8; 34],
    /// Canonical SHA-256 Name of its separately provisioned salt key.
    pub salt_name: [u8; 34],
    /// Canonical empty pre-genesis ledger anchor, not a current journal HEAD.
    ///
    /// The independent provisioner computes the complete initialized map and
    /// first NV checkpoint only after signing this genesis. Neither that future
    /// head nor its future NV value is stored inside its own hashed genesis row.
    pub empty_ledger_anchor: [u8; 32],
    /// Canonical immutable publisher startup/profile binding.
    pub publisher_profile: [u8; 32],
    /// Actual immutable nspawn executable digest.
    pub nspawn_digest: [u8; 32],
    /// Immutable specimen root publication digest.
    pub root_digest: [u8; 32],
    /// Reviewed compiled supervisor filter artifact digest.
    pub supervisor_filter: [u8; 32],
    /// Reviewed compiled payload filter artifact digest.
    pub payload_filter: [u8; 32],
    /// Loaded MAC policy publication digest.
    pub mac_policy: [u8; 32],
    /// Deployment-only credential and fixed endpoint contract digest.
    pub credential_contract: [u8; 32],
    /// Fixed nonzero host-side private-user range start.
    pub uid_start: u32,
    /// Fixed private-user range length.
    pub uid_count: u32,
}

impl DeploymentGenesisV1 {
    /// Encodes the closed provisioned genesis without issuing live authority.
    ///
    /// # Errors
    ///
    /// Rejects sentinel identities, malformed Names, or an invalid user range.
    pub fn encode(&self) -> Result<[u8; DEPLOYMENT_GENESIS_BYTES_V1], DeploymentWireErrorV1> {
        self.validate()?;
        let mut bytes = [0; DEPLOYMENT_GENESIS_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSRDG01");
        bytes[8..24].copy_from_slice(&self.node);
        bytes[24..40].copy_from_slice(&self.deployment);
        bytes[40..72].copy_from_slice(&self.signer);
        bytes[72..106].copy_from_slice(&self.nv_name);
        bytes[106..140].copy_from_slice(&self.salt_name);
        for (index, commitment) in self.commitments().into_iter().enumerate() {
            bytes[140 + index * 32..172 + index * 32].copy_from_slice(commitment);
        }
        bytes[396..400].copy_from_slice(&self.uid_start.to_be_bytes());
        bytes[400..404].copy_from_slice(&self.uid_count.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes only the fixed provisioned data contract.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions, truncation, trailing bytes and sentinels.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeploymentWireErrorV1> {
        if bytes.len() != DEPLOYMENT_GENESIS_BYTES_V1 || bytes[..8] != *b"AOSRDG01" {
            return Err(DeploymentWireErrorV1);
        }
        let genesis = Self {
            node: array(bytes, 8)?,
            deployment: array(bytes, 24)?,
            signer: array(bytes, 40)?,
            nv_name: array(bytes, 72)?,
            salt_name: array(bytes, 106)?,
            empty_ledger_anchor: array(bytes, 140)?,
            publisher_profile: array(bytes, 172)?,
            nspawn_digest: array(bytes, 204)?,
            root_digest: array(bytes, 236)?,
            supervisor_filter: array(bytes, 268)?,
            payload_filter: array(bytes, 300)?,
            mac_policy: array(bytes, 332)?,
            credential_contract: array(bytes, 364)?,
            uid_start: u32::from_be_bytes(array(bytes, 396)?),
            uid_count: u32::from_be_bytes(array(bytes, 400)?),
        };
        genesis.validate()?;
        Ok(genesis)
    }

    /// Checks the external provisioner's signature against the pinned key.
    ///
    /// This never authorizes initialization, replacement or adoption of NV.
    ///
    /// # Errors
    ///
    /// Rejects an invalid genesis, substituted key or invalid strict signature.
    pub fn verify_signature(
        &self,
        provisioner: &VerifyingKey,
        signature: [u8; 64],
    ) -> Result<(), DeploymentWireErrorV1> {
        let mut message = b"aos.runtime-deployment.genesis.v1\0".to_vec();
        message.extend_from_slice(&self.encode()?);
        provisioner
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| DeploymentWireErrorV1)
    }

    /// Returns the domain-separated commitment used in preparation exchanges.
    ///
    /// # Errors
    ///
    /// Rejects the same invalid fields as [`Self::encode`].
    pub fn digest(&self) -> Result<[u8; 32], DeploymentWireErrorV1> {
        let mut hash = Sha256::new();
        hash.update(b"aos.runtime-deployment.genesis.v1\0");
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }

    fn commitments(&self) -> [&[u8; 32]; 8] {
        [
            &self.empty_ledger_anchor,
            &self.publisher_profile,
            &self.nspawn_digest,
            &self.root_digest,
            &self.supervisor_filter,
            &self.payload_filter,
            &self.mac_policy,
            &self.credential_contract,
        ]
    }

    fn validate(&self) -> Result<(), DeploymentWireErrorV1> {
        if self.node == [0; 16]
            || self.deployment == [0; 16]
            || self.signer == [0; 32]
            || self.commitments().iter().any(|value| **value == [0; 32])
            || [&self.nv_name, &self.salt_name].iter().any(|name| {
                name[..2] != 0x000b_u16.to_be_bytes() || name[2..] == [0; 32]
            })
            || self.uid_start == 0
            || self.uid_count < 65_536
            || self.uid_start.checked_add(self.uid_count).is_none()
            || VerifyingKey::from_bytes(&self.signer).is_err()
        {
            return Err(DeploymentWireErrorV1);
        }
        Ok(())
    }
}

/// Correlates one fresh deployment-currentness observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentQueryV1 {
    /// Fresh challenge generated by the actual consumer, never a watermark.
    pub nonce: [u8; 32],
    /// Consumer-observed physical kernel boot identifier.
    pub kernel_boot: [u8; 16],
    /// Exact externally provisioned genesis commitment.
    pub genesis_digest: [u8; 32],
}

impl DeploymentQueryV1 {
    /// Encodes the fixed challenge request.
    ///
    /// # Errors
    ///
    /// Rejects zero challenges, boots and genesis commitments.
    pub fn encode(&self) -> Result<[u8; DEPLOYMENT_QUERY_BYTES_V1], DeploymentWireErrorV1> {
        if self.nonce == [0; 32] || self.kernel_boot == [0; 16] || self.genesis_digest == [0; 32] {
            return Err(DeploymentWireErrorV1);
        }
        let mut bytes = [0; DEPLOYMENT_QUERY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSRDQ01");
        bytes[8..40].copy_from_slice(&self.nonce);
        bytes[40..56].copy_from_slice(&self.kernel_boot);
        bytes[56..88].copy_from_slice(&self.genesis_digest);
        Ok(bytes)
    }

    /// Decodes exact challenge data without authenticating its sender.
    ///
    /// # Errors
    ///
    /// Rejects unsupported framing, trailing bytes and sentinel fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeploymentWireErrorV1> {
        if bytes.len() != DEPLOYMENT_QUERY_BYTES_V1 || bytes[..8] != *b"AOSRDQ01" {
            return Err(DeploymentWireErrorV1);
        }
        let query = Self {
            nonce: array(bytes, 8)?,
            kernel_boot: array(bytes, 40)?,
            genesis_digest: array(bytes, 56)?,
        };
        query.encode()?;
        Ok(query)
    }
}

/// Carries a signed fresh NV/prepared-HEAD observation, not readiness authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentReceiptV1 {
    /// Original complete fresh request.
    pub query: DeploymentQueryV1,
    /// Monotonic protected preparation generation.
    pub generation: u64,
    /// Owner epoch bound to physical takeover and the current kernel boot.
    pub monotonic_epoch: u64,
    /// Independently authenticated current hardware NV value.
    pub current_nv: [u8; 32],
    /// Exact floored complete preparation HEAD.
    pub prepared_head: [u8; 32],
    /// Exact compiled specimen profile commitment.
    pub specimen_profile: [u8; 32],
    /// Deployment-only signature over all preceding fields and a fixed domain.
    pub signature: [u8; 64],
}

impl DeploymentReceiptV1 {
    /// Returns the exact domain-separated message to be signed by the owner.
    ///
    /// # Errors
    ///
    /// Rejects invalid correlation, zero generations and incomplete HEADs.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, DeploymentWireErrorV1> {
        let encoded = self.encode()?;
        let mut message = b"aos.runtime-deployment.current.v1\0".to_vec();
        message.extend_from_slice(&encoded[..208]);
        Ok(message)
    }

    /// Encodes the complete bounded receipt as comparison data.
    ///
    /// # Errors
    ///
    /// Rejects zero generations, epochs or commitments and invalid queries.
    pub fn encode(&self) -> Result<[u8; DEPLOYMENT_RECEIPT_BYTES_V1], DeploymentWireErrorV1> {
        if self.generation == 0
            || self.monotonic_epoch == 0
            || [self.current_nv, self.prepared_head, self.specimen_profile].contains(&[0; 32])
        {
            return Err(DeploymentWireErrorV1);
        }
        let mut bytes = [0; DEPLOYMENT_RECEIPT_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSRDR01");
        bytes[8..96].copy_from_slice(&self.query.encode()?);
        bytes[96..104].copy_from_slice(&self.generation.to_be_bytes());
        bytes[104..112].copy_from_slice(&self.monotonic_epoch.to_be_bytes());
        bytes[112..144].copy_from_slice(&self.current_nv);
        bytes[144..176].copy_from_slice(&self.prepared_head);
        bytes[176..208].copy_from_slice(&self.specimen_profile);
        bytes[208..272].copy_from_slice(&self.signature);
        Ok(bytes)
    }

    /// Decodes a strict fixed receipt without authenticating its producer.
    ///
    /// # Errors
    ///
    /// Rejects malformed fields, another version and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DeploymentWireErrorV1> {
        if bytes.len() != DEPLOYMENT_RECEIPT_BYTES_V1 || bytes[..8] != *b"AOSRDR01" {
            return Err(DeploymentWireErrorV1);
        }
        let receipt = Self {
            query: DeploymentQueryV1::decode(&bytes[8..96])?,
            generation: u64::from_be_bytes(array(bytes, 96)?),
            monotonic_epoch: u64::from_be_bytes(array(bytes, 104)?),
            current_nv: array(bytes, 112)?,
            prepared_head: array(bytes, 144)?,
            specimen_profile: array(bytes, 176)?,
            signature: array(bytes, 208)?,
        };
        receipt.encode()?;
        Ok(receipt)
    }

    /// Verifies the exact fresh query and provisioned deployment signer.
    ///
    /// Fresh physical NV verification and retained owner pins are additionally
    /// required by the consumer; this method does not create readiness.
    ///
    /// # Errors
    ///
    /// Rejects substituted queries, malformed records and invalid signatures.
    pub fn verify(
        &self,
        query: DeploymentQueryV1,
        signer: &VerifyingKey,
    ) -> Result<(), DeploymentWireErrorV1> {
        if self.query != query {
            return Err(DeploymentWireErrorV1);
        }
        signer
            .verify_strict(&self.signing_bytes()?, &Signature::from_bytes(&self.signature))
            .map_err(|_| DeploymentWireErrorV1)
    }
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], DeploymentWireErrorV1> {
    bytes.get(offset..offset + N)
        .ok_or(DeploymentWireErrorV1)?
        .try_into()
        .map_err(|_| DeploymentWireErrorV1)
}

#[cfg(test)]
mod tests;
