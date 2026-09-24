//! Closed root-policy binding format for a future cross-owner issuer.
//!
//! `AOSPCB02` records bind the accepted Create, signed inputs, independent
//! owner heads, physical Cache partition, and one handoff epoch. They remain
//! historical evidence only: no producer or verifier grants publication from
//! this format until an ordered writer-held barrier can establish every field.
//!
//! ```text
//! AOSPCB02 | version=2 | reserved=0 | issuer/project/sandbox/Create |
//! accepted operation revision/generation | projection | publisher |
//! signed project | ancestry/compiler/cache-domain/revocation |
//! physical partition/replay head | normalized input/candidate |
//! signer generations | barrier/root CAS | effect handoff epoch | SHA-256
//! ```

use aos_sandbox_core::{ObjectDigest, OperationId, ProjectId, SandboxId};
use sha2::{Digest as _, Sha256};

use super::PolicyCompilerJournalErrorV1;

pub(super) const BINDING_V2_KEY_PREFIX: &[u8] = b"\0aos-policy-compiler-binding-v2\0";
const MAGIC: &[u8; 8] = b"AOSPCB02";
const CHECKSUM_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.protected-binding.v2\0";
const KEY_DOMAIN: &[u8] = b"aos.sandbox.policy-compiler.binding-key.v2\0";
const RECORD_BYTES: usize = 664;
const BODY_BYTES: usize = RECORD_BYTES - 32;

/// Retains canonical fields without asserting that their independent owners held a barrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ClosedPolicyRootBindingV2 {
    issuer_owner: [u8; 16],
    project: ProjectId,
    sandbox: SandboxId,
    operation: OperationId,
    operation_revision: ObjectDigest,
    accepted_generation: u64,
    projection_revision: ObjectDigest,
    publisher_generation: u64,
    publisher_head: ObjectDigest,
    project_policy_head: ObjectDigest,
    project_policy_input: ObjectDigest,
    ancestry_head: ObjectDigest,
    compiler_head: ObjectDigest,
    cache_domain_head: ObjectDigest,
    revocation_head: ObjectDigest,
    physical_partition: ObjectDigest,
    physical_cache_head: ObjectDigest,
    normalized_input: ObjectDigest,
    candidate: ObjectDigest,
    project_signer_generation: u64,
    deployment_signer_generation: u64,
    barrier_epoch: u64,
    barrier_head: ObjectDigest,
    root_predecessor: ObjectDigest,
    root_generation: u64,
    effect_transaction: [u8; 16],
    handoff_epoch: u64,
}

impl ClosedPolicyRootBindingV2 {
    fn canonical(&self) -> bool {
        self.issuer_owner != [0; 16]
            && self.project.as_bytes() != &[0; 16]
            && self.sandbox.as_bytes() != &[0; 16]
            && self.operation.as_bytes() != &[0; 16]
            && self.effect_transaction != [0; 16]
            && self.accepted_generation != 0
            && self.publisher_generation != 0
            && self.project_signer_generation != 0
            && self.deployment_signer_generation != 0
            && self.barrier_epoch != 0
            && self.root_generation != 0
            && self.handoff_epoch == self.barrier_epoch
            && (self.root_predecessor.as_bytes() == &[0; 32]) == (self.root_generation == 1)
            && [
                self.operation_revision,
                self.projection_revision,
                self.publisher_head,
                self.project_policy_head,
                self.project_policy_input,
                self.ancestry_head,
                self.compiler_head,
                self.cache_domain_head,
                self.revocation_head,
                self.physical_partition,
                self.physical_cache_head,
                self.normalized_input,
                self.candidate,
                self.barrier_head,
            ]
            .iter()
            .all(|digest| digest.as_bytes() != &[0; 32])
    }

    fn encode(&self) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
        if !self.canonical() {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }

        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&2_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 6]);
        bytes.extend_from_slice(&self.issuer_owner);
        bytes.extend_from_slice(self.project.as_bytes());
        bytes.extend_from_slice(self.sandbox.as_bytes());
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(self.operation_revision.as_bytes());
        bytes.extend_from_slice(&self.accepted_generation.to_be_bytes());
        bytes.extend_from_slice(self.projection_revision.as_bytes());
        bytes.extend_from_slice(&self.publisher_generation.to_be_bytes());
        bytes.extend_from_slice(self.publisher_head.as_bytes());
        bytes.extend_from_slice(self.project_policy_head.as_bytes());
        bytes.extend_from_slice(self.project_policy_input.as_bytes());
        bytes.extend_from_slice(self.ancestry_head.as_bytes());
        bytes.extend_from_slice(self.compiler_head.as_bytes());
        bytes.extend_from_slice(self.cache_domain_head.as_bytes());
        bytes.extend_from_slice(self.revocation_head.as_bytes());
        bytes.extend_from_slice(self.physical_partition.as_bytes());
        bytes.extend_from_slice(self.physical_cache_head.as_bytes());
        bytes.extend_from_slice(self.normalized_input.as_bytes());
        bytes.extend_from_slice(self.candidate.as_bytes());
        bytes.extend_from_slice(&self.project_signer_generation.to_be_bytes());
        bytes.extend_from_slice(&self.deployment_signer_generation.to_be_bytes());
        bytes.extend_from_slice(&self.barrier_epoch.to_be_bytes());
        bytes.extend_from_slice(self.barrier_head.as_bytes());
        bytes.extend_from_slice(self.root_predecessor.as_bytes());
        bytes.extend_from_slice(&self.root_generation.to_be_bytes());
        bytes.extend_from_slice(&self.effect_transaction);
        bytes.extend_from_slice(&self.handoff_epoch.to_be_bytes());
        if bytes.len() != BODY_BYTES {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&bytes)
            .finalize();
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, PolicyCompilerJournalErrorV1> {
        if bytes.len() != RECORD_BYTES {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let mut reader = BindingReaderV2 { bytes, offset: 0 };
        if reader.take::<8>()? != *MAGIC
            || reader.take::<2>()? != 2_u16.to_be_bytes()
            || reader.take::<6>()? != [0; 6]
        {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        let binding = Self {
            issuer_owner: reader.take()?,
            project: ProjectId::from_bytes(reader.take()?),
            sandbox: SandboxId::from_bytes(reader.take()?),
            operation: OperationId::from_bytes(reader.take()?),
            operation_revision: reader.digest()?,
            accepted_generation: reader.u64()?,
            projection_revision: reader.digest()?,
            publisher_generation: reader.u64()?,
            publisher_head: reader.digest()?,
            project_policy_head: reader.digest()?,
            project_policy_input: reader.digest()?,
            ancestry_head: reader.digest()?,
            compiler_head: reader.digest()?,
            cache_domain_head: reader.digest()?,
            revocation_head: reader.digest()?,
            physical_partition: reader.digest()?,
            physical_cache_head: reader.digest()?,
            normalized_input: reader.digest()?,
            candidate: reader.digest()?,
            project_signer_generation: reader.u64()?,
            deployment_signer_generation: reader.u64()?,
            barrier_epoch: reader.u64()?,
            barrier_head: reader.digest()?,
            root_predecessor: reader.digest()?,
            root_generation: reader.u64()?,
            effect_transaction: reader.take()?,
            handoff_epoch: reader.u64()?,
        };
        if reader.offset != BODY_BYTES || binding.encode()?.as_slice() != bytes {
            return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
        }
        Ok(binding)
    }

    fn key(&self) -> Result<Vec<u8>, PolicyCompilerJournalErrorV1> {
        let encoded = self.encode()?;
        let digest = Sha256::new()
            .chain_update(KEY_DOMAIN)
            .chain_update(encoded)
            .finalize();
        let mut key = Vec::with_capacity(BINDING_V2_KEY_PREFIX.len() + 32);
        key.extend_from_slice(BINDING_V2_KEY_PREFIX);
        key.extend_from_slice(&digest);
        Ok(key)
    }
}

/// Decodes an exact root-journal key/value pair without granting publication authority.
pub(super) fn decode_closed_policy_binding_v2(
    key: &[u8],
    value: &[u8],
) -> Result<ClosedPolicyRootBindingV2, PolicyCompilerJournalErrorV1> {
    let binding = ClosedPolicyRootBindingV2::decode(value)?;
    if binding.key()?.as_slice() != key {
        return Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate);
    }
    Ok(binding)
}

struct BindingReaderV2<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl BindingReaderV2<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], PolicyCompilerJournalErrorV1> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .and_then(|value| value.try_into().ok())
            .ok_or(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)?;
        self.offset = end;
        Ok(value)
    }

    fn digest(&mut self) -> Result<ObjectDigest, PolicyCompilerJournalErrorV1> {
        Ok(ObjectDigest::from_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, PolicyCompilerJournalErrorV1> {
        Ok(u64::from_be_bytes(self.take()?))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use super::*;
    use crate::journal::{Journal, JournalRecord, JournalTransaction, RecordNamespace};
    use crate::policy_compiler::protected_owner::{
        ProtectedPolicyPublicationVerifierV1, policy_authority_journal_limits,
    };

    fn fixture() -> ClosedPolicyRootBindingV2 {
        ClosedPolicyRootBindingV2 {
            issuer_owner: [1; 16],
            project: ProjectId::from_bytes([2; 16]),
            sandbox: SandboxId::from_bytes([3; 16]),
            operation: OperationId::from_bytes([4; 16]),
            operation_revision: ObjectDigest::from_bytes([5; 32]),
            accepted_generation: 6,
            projection_revision: ObjectDigest::from_bytes([7; 32]),
            publisher_generation: 8,
            publisher_head: ObjectDigest::from_bytes([9; 32]),
            project_policy_head: ObjectDigest::from_bytes([10; 32]),
            project_policy_input: ObjectDigest::from_bytes([11; 32]),
            ancestry_head: ObjectDigest::from_bytes([12; 32]),
            compiler_head: ObjectDigest::from_bytes([13; 32]),
            cache_domain_head: ObjectDigest::from_bytes([14; 32]),
            revocation_head: ObjectDigest::from_bytes([15; 32]),
            physical_partition: ObjectDigest::from_bytes([16; 32]),
            physical_cache_head: ObjectDigest::from_bytes([17; 32]),
            normalized_input: ObjectDigest::from_bytes([18; 32]),
            candidate: ObjectDigest::from_bytes([19; 32]),
            project_signer_generation: 20,
            deployment_signer_generation: 21,
            barrier_epoch: 22,
            barrier_head: ObjectDigest::from_bytes([23; 32]),
            root_predecessor: ObjectDigest::from_bytes([0; 32]),
            root_generation: 1,
            effect_transaction: [24; 16],
            handoff_epoch: 22,
        }
    }

    #[test]
    fn canonical_binding_round_trips_and_rejects_every_substituted_head() {
        let binding = fixture();
        let encoded = binding.encode().expect("canonical binding");
        let key = binding.key().expect("content-addressed key");
        assert_eq!(encoded.len(), RECORD_BYTES);
        assert_eq!(
            decode_closed_policy_binding_v2(&key, &encoded).expect("readback"),
            binding
        );

        for offset in [
            0, 8, 10, 16, 32, 48, 64, 80, 104, 120, 144, 160, 192, 224, 256, 288, 320, 352, 384,
            416, 448, 480, 496, 512, 528, 536, 568, 600, 608, 624, 632,
        ] {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(
                decode_closed_policy_binding_v2(&key, &changed).is_err(),
                "offset {offset}"
            );
        }
        let mut wrong_key = key.clone();
        *wrong_key.last_mut().expect("digest suffix") ^= 1;
        assert!(decode_closed_policy_binding_v2(&wrong_key, &encoded).is_err());

        let mut substituted = encoded.clone();
        substituted[384] ^= 1;
        let checksum = Sha256::new()
            .chain_update(CHECKSUM_DOMAIN)
            .chain_update(&substituted[..BODY_BYTES])
            .finalize();
        substituted[BODY_BYTES..].copy_from_slice(&checksum);
        assert!(decode_closed_policy_binding_v2(&key, &substituted).is_err());
    }

    #[test]
    fn barrier_epoch_and_root_predecessor_shape_fail_closed() {
        let mut binding = fixture();
        binding.handoff_epoch += 1;
        assert!(binding.encode().is_err());

        binding = fixture();
        binding.root_generation = 2;
        assert!(binding.encode().is_err());

        binding.root_predecessor = ObjectDigest::from_bytes([25; 32]);
        assert!(binding.encode().is_ok());
    }

    #[test]
    fn protected_root_readback_still_cannot_authorize_v2_publication() {
        let directory = tempfile::tempdir().expect("protected test directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = fs::metadata(directory.path())
            .expect("directory owner")
            .uid();
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "authority.journal",
            policy_authority_journal_limits(),
            uid,
        )
        .expect("protected root journal");
        let binding = fixture();
        let key = binding.key().expect("binding key");
        let encoded = binding.encode().expect("binding bytes");
        let transaction = JournalTransaction::new(
            [26; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                key.clone(),
                encoded.clone(),
            )],
        )
        .expect("root transaction");
        journal
            .claim_protected_authority(RecordNamespace::DesiredState)
            .expect("root claim")
            .commit(&transaction)
            .expect("durable write");
        assert_eq!(
            decode_closed_policy_binding_v2(
                &key,
                journal
                    .get(RecordNamespace::DesiredState, &key)
                    .expect("durable readback"),
            )
            .expect("canonical readback"),
            binding
        );
        assert!(matches!(
            ProtectedPolicyPublicationVerifierV1::from_journal(journal),
            Err(PolicyCompilerJournalErrorV1::UnauthenticatedCandidate)
        ));
    }
}
