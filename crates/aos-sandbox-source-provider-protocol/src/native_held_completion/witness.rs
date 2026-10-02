//! Fixed-family byte commitments and diagnostic native owner projections.
//!
//! ```text
//! ByteWitness = namespace:u16be | key_length:u16be | digest[32] | exact_key
//! W = version:u16be=1 | reserved[6] | concrete_owner_fields | fixed_witnesses
//! ```
//!
//! No witness serializes a journal snapshot or constructs a held writer. The
//! owning layer rederives the key and compares actual canonical record bytes.
//! A zero digest is an absence claim only when that owner's exact prefix allows
//! it; this format cannot prove that a later dispatch is excluded.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::{SourceProviderAuthorityV1, SourceProviderMethod};

use super::codec::{Reader, invalid, nonzero};
use super::{NativeHeldOwnerV1, Result};

const RECORD_DOMAIN: &[u8] = b"aos.sandbox.native-held-completion.record-bytes.v1\0";

/// Names one exact record family in its independently fixed physical owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHeldRecordFamilyV1 {
    /// Original immutable Mount provider session, namespace40/key69.
    RootSession,
    /// Original Mount provider attempt, namespace40/key75.
    RootAttempt,
    /// Original Mount acquisition companion, namespace40/key64.
    RootAcquisition,
    /// Original Mount provider head, namespace40/key66.
    RootHead,
    /// Source authority head, namespace41/key49.
    ProviderAuthority,
    /// Source original attempt, namespace41/key96.
    ProviderAttempt,
    /// Source original acquisition, namespace41/key99.
    ProviderAcquisition,
    /// Source current holder head, namespace41/key63.
    ProviderHolder,
    /// Source immutable original holder history, namespace41/key103.
    ProviderHistory,
    /// Source original native carrier, namespace41/key40.
    ProviderNative,
    /// Original challenge in the separately held challenge journal41/key40.
    Challenge,
    /// Original consumer-interest row in Storage's separate journal6/key48.
    StorageIssuance,
}

impl NativeHeldRecordFamilyV1 {
    /// Returns the fixed wire namespace, not a physical journal identity.
    #[must_use]
    pub const fn namespace(self) -> u16 {
        match self {
            Self::RootSession | Self::RootAttempt | Self::RootAcquisition | Self::RootHead => 40,
            Self::StorageIssuance => 6,
            _ => 41,
        }
    }

    /// Returns the exact canonical key width of this existing record family.
    #[must_use]
    pub const fn key_bytes(self) -> usize {
        match self {
            Self::RootSession => 69,
            Self::RootAttempt => 75,
            Self::RootAcquisition => 64,
            Self::RootHead => 66,
            Self::ProviderAuthority => 49,
            Self::ProviderAttempt => 96,
            Self::ProviderAcquisition => 99,
            Self::ProviderHolder => 63,
            Self::ProviderHistory => 103,
            Self::ProviderNative | Self::Challenge => 40,
            Self::StorageIssuance => 48,
        }
    }

    fn prefix(self) -> &'static [u8] {
        match self {
            Self::RootSession => b"aos.mount.source-provider-session.v2\0",
            Self::RootAttempt => b"aos.mount.source-provider-query-attempt.v2\0",
            Self::RootAcquisition => b"aos.mount.source-acquisition.v2\0",
            Self::RootHead => b"aos.mount.source-provider-head.v2\0",
            Self::ProviderAuthority => b"aos.source-provider.authority.v1\0",
            Self::ProviderAttempt => b"aos.source-provider.attempt.v1\0",
            Self::ProviderAcquisition => b"aos.source-provider.acquisition.v1\0",
            Self::ProviderHolder => b"aos.source-provider.session.v1\0",
            Self::ProviderHistory => b"aos.source-provider.session-history.v1\0",
            Self::ProviderNative => b"AOSNCK02",
            Self::Challenge => b"AOSZHK01",
            Self::StorageIssuance => b"",
        }
    }

    fn validate_key(self, key: &[u8]) -> Result<()> {
        if key.len() != self.key_bytes() || !key.starts_with(self.prefix()) {
            return Err(invalid("fixed witness key family"));
        }
        let subject = key
            .get(self.prefix().len()..)
            .ok_or_else(|| invalid("witness key"))?;
        let widths: &[usize] = match self {
            Self::ProviderAuthority => &[16],
            Self::RootSession
            | Self::RootAttempt
            | Self::RootAcquisition
            | Self::ProviderNative
            | Self::Challenge => &[32],
            Self::RootHead | Self::ProviderHolder => &[16, 16],
            Self::ProviderAcquisition => &[16, 16, 32],
            Self::ProviderHistory => &[16, 16, 32],
            Self::StorageIssuance => &[16, 32],
            Self::ProviderAttempt => &[16, 16, 16, 1, 16],
        };
        let mut reader = Reader::new(subject);
        for (index, width) in widths.iter().enumerate() {
            let field = reader.bytes(*width)?;
            if self == Self::ProviderAttempt && index == 3 {
                if field != [SourceProviderMethod::Acquire as u8] {
                    return Err(invalid("native attempt method"));
                }
            } else if field.iter().all(|byte| *byte == 0) {
                return Err(invalid("sentinel witness key subject"));
            }
        }
        reader.finish()
    }
}

/// Fixes Root's four companion witnesses in their canonical wire order.
pub const ROOT_NATIVE_WITNESS_FAMILIES_V1: [NativeHeldRecordFamilyV1; 4] = [
    NativeHeldRecordFamilyV1::RootSession,
    NativeHeldRecordFamilyV1::RootAttempt,
    NativeHeldRecordFamilyV1::RootAcquisition,
    NativeHeldRecordFamilyV1::RootHead,
];

/// Fixes Source's six owner records and separate challenge witness wire order.
pub const PROVIDER_NATIVE_WITNESS_FAMILIES_V1: [NativeHeldRecordFamilyV1; 7] = [
    NativeHeldRecordFamilyV1::ProviderAuthority,
    NativeHeldRecordFamilyV1::ProviderAttempt,
    NativeHeldRecordFamilyV1::ProviderAcquisition,
    NativeHeldRecordFamilyV1::ProviderHolder,
    NativeHeldRecordFamilyV1::ProviderHistory,
    NativeHeldRecordFamilyV1::ProviderNative,
    NativeHeldRecordFamilyV1::Challenge,
];

/// Retains a fixed key and byte commitment without asserting protected provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHeldByteWitnessV1 {
    family: NativeHeldRecordFamilyV1,
    digest: ObjectDigest,
    key: Vec<u8>,
}

impl NativeHeldByteWitnessV1 {
    /// Constructs only a canonical claim for one exact existing record family.
    ///
    /// # Errors
    ///
    /// Rejects a differing family, key width, prefix or sentinel key subject.
    pub fn new(
        family: NativeHeldRecordFamilyV1,
        key: Vec<u8>,
        digest: ObjectDigest,
    ) -> Result<Self> {
        family.validate_key(&key)?;
        Ok(Self {
            family,
            digest,
            key,
        })
    }

    /// Returns the independently fixed record family.
    #[must_use]
    pub const fn family(&self) -> NativeHeldRecordFamilyV1 {
        self.family
    }

    /// Returns the exact canonical key; the owner must rederive it independently.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Returns the byte commitment or the explicitly nonauthorizing absence marker.
    #[must_use]
    pub const fn digest(&self) -> ObjectDigest {
        self.digest
    }

    /// Encodes this already-validated fixed-family witness.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(36 + self.key.len());
        bytes.extend_from_slice(&self.family.namespace().to_be_bytes());
        bytes.extend_from_slice(&(self.family.key_bytes() as u16).to_be_bytes());
        bytes.extend_from_slice(self.digest.as_bytes());
        bytes.extend_from_slice(&self.key);
        bytes
    }

    /// Decodes one exact expected family, never a caller-nominated namespace.
    ///
    /// # Errors
    ///
    /// Rejects wrong namespace/key family, noncanonical length or trailing bytes.
    pub fn from_canonical_bytes(family: NativeHeldRecordFamilyV1, bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let value = Self::decode(family, &mut reader)?;
        reader.finish()?;
        Ok(value)
    }

    pub(super) fn decode(
        family: NativeHeldRecordFamilyV1,
        reader: &mut Reader<'_>,
    ) -> Result<Self> {
        if reader.u16()? != family.namespace() || usize::from(reader.u16()?) != family.key_bytes() {
            return Err(invalid("witness namespace or length"));
        }
        let digest = reader.digest()?;
        Self::new(family, reader.bytes(family.key_bytes())?.to_vec(), digest)
    }
}

/// Hashes exact canonical record bytes for one fixed diagnostic family only.
///
/// # Errors
///
/// Rejects an incorrect family/key shape; this does not validate record provenance.
pub fn native_held_record_byte_digest_v1(
    family: NativeHeldRecordFamilyV1,
    key: &[u8],
    value: &[u8],
) -> Result<ObjectDigest> {
    family.validate_key(key)?;
    Ok(ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(RECORD_DOMAIN)
            .chain_update(family.namespace().to_be_bytes())
            .chain_update((family.key_bytes() as u16).to_be_bytes())
            .chain_update(key)
            .chain_update(value)
            .finalize()
            .into(),
    ))
}

/// Retains one generation/digest tuple; equality alone does not hold its owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHeldGenerationClaimV1 {
    /// Names the original protected generation.
    pub generation: u64,
    /// Commits the original protected head or floor bytes.
    pub digest: ObjectDigest,
}

impl NativeHeldGenerationClaimV1 {
    fn validate(self) -> Result<()> {
        if self.generation == 0 || !nonzero(self.digest) {
            return Err(invalid("generation tuple"));
        }
        Ok(())
    }

    fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(self.digest.as_bytes());
    }

    fn decode(reader: &mut Reader<'_>) -> Result<Self> {
        let value = Self {
            generation: reader.u64()?,
            digest: reader.digest()?,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Carries Root's original diagnostic fields and fixed companion witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeHeldWitnessV1 {
    /// Correlates Root's own original endpoint, never the remote endpoint cookie.
    pub local_socket_cookie: u64,
    /// Reports the current journal sequence without serializing its opaque token.
    pub journal_sequence: u64,
    /// Reports original planning's sequence, not a replacement planning token.
    pub planning_sequence: u64,
    /// Retains independently owned trust generation and digest claims.
    pub trust: NativeHeldGenerationClaimV1,
    /// Retains independently owned revocation generation and digest claims.
    pub revocation: NativeHeldGenerationClaimV1,
    /// Retains the original provider head claim.
    pub provider_head: NativeHeldGenerationClaimV1,
    /// Retains the original provider floor claim.
    pub provider_floor: NativeHeldGenerationClaimV1,
    /// Commits the exact original publication bytes.
    pub publication: ObjectDigest,
    /// Lists session, attempt, acquisition and head in that fixed order.
    pub records: [NativeHeldByteWitnessV1; 4],
}

/// Carries Source's original diagnostic fields and its seven fixed witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderNativeHeldWitnessV1 {
    /// Correlates Source's original Root endpoint.
    pub root_local_cookie: u64,
    /// Correlates Source's original Storage endpoint.
    pub storage_local_cookie: u64,
    /// Reports the Source journal sequence, not its protected snapshot.
    pub completion_sequence: u64,
    /// Reports the separately held challenge journal sequence.
    pub challenge_sequence: u64,
    /// Retains the existing complete 56-byte authority tuple.
    pub authority: SourceProviderAuthorityV1,
    /// Commits the original native resource namespace.
    pub native_namespace: ObjectDigest,
    /// Retains the original catalog head claim.
    pub catalog_head: NativeHeldGenerationClaimV1,
    /// Retains the original catalog floor claim.
    pub catalog_floor: NativeHeldGenerationClaimV1,
    /// Commits the original protected current head.
    pub head_commitment: ObjectDigest,
    /// Commits the entire original signed publication bytes.
    pub publication: ObjectDigest,
    /// Commits Source's original AOSNEM01 selected native execution inputs.
    ///
    /// This Source-local assertion does not carry Root's Mount plan or lease,
    /// and its authentication does not independently verify Source file origin.
    pub selected_manifest: ObjectDigest,
    /// Uses SHA-256 of the exact original 928-byte AOSSPBV1 enrollment.
    pub backend_manifest: ObjectDigest,
    /// Uses SHA-256 of the exact separately owned 160-byte AOSZHV01 enrollment.
    pub verifier_manifest: ObjectDigest,
    /// Lists the six Source owner records and separate challenge in fixed order.
    pub records: [NativeHeldByteWitnessV1; 7],
}

/// Carries Storage's original child/cut diagnostics and its exact issuance key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageNativeHeldWitnessV1 {
    /// Correlates Storage's own original child endpoint.
    pub local_socket_cookie: u64,
    /// Reports the actual primary journal diagnostic sequence.
    pub primary_sequence: u64,
    /// Reports the actual workspace journal diagnostic sequence.
    pub workspace_sequence: u64,
    /// Reports the single already-open request-trust journal sequence.
    pub request_trust_sequence: u64,
    /// Reports the actual separate issuance journal diagnostic sequence.
    pub issuance_sequence: u64,
    /// Names the protected original request-trust generation.
    pub request_trust_generation: u64,
    /// Commits the exact original request-trust file bytes.
    pub request_trust_file: ObjectDigest,
    /// Names the original actual consumer-interest row.
    pub issuance: NativeHeldByteWitnessV1,
}

/// Separates concrete diagnostic projection shapes without producing owners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeHeldOwnerWitnessV1 {
    /// Root's exact642-byte shape.
    Root(RootNativeHeldWitnessV1),
    /// Source's exact1110-byte shape.
    Provider(ProviderNativeHeldWitnessV1),
    /// Storage's exact172-byte shape.
    Storage(StorageNativeHeldWitnessV1),
}

impl NativeHeldOwnerWitnessV1 {
    /// Returns the projection's fixed actual role.
    #[must_use]
    pub const fn owner(&self) -> NativeHeldOwnerV1 {
        match self {
            Self::Root(_) => NativeHeldOwnerV1::Root,
            Self::Provider(_) => NativeHeldOwnerV1::Provider,
            Self::Storage(_) => NativeHeldOwnerV1::Storage,
        }
    }

    /// Encodes only the concrete bounded diagnostic projection.
    ///
    /// # Errors
    ///
    /// Rejects sentinel original fields or substituted fixed record families.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = vec![0, 1, 0, 0, 0, 0, 0, 0];
        match self {
            Self::Root(value) => {
                if value.local_socket_cookie == 0 || !nonzero(value.publication) {
                    return Err(invalid("Root witness fields"));
                }
                for claim in [
                    value.trust,
                    value.revocation,
                    value.provider_head,
                    value.provider_floor,
                ] {
                    claim.validate()?;
                }
                bytes.extend_from_slice(&value.local_socket_cookie.to_be_bytes());
                bytes.extend_from_slice(&value.journal_sequence.to_be_bytes());
                bytes.extend_from_slice(&value.planning_sequence.to_be_bytes());
                for claim in [
                    value.trust,
                    value.revocation,
                    value.provider_head,
                    value.provider_floor,
                ] {
                    claim.encode(&mut bytes);
                }
                bytes.extend_from_slice(value.publication.as_bytes());
                encode_records(&mut bytes, &value.records, &ROOT_NATIVE_WITNESS_FAMILIES_V1)?;
            }
            Self::Provider(value) => {
                if value.root_local_cookie == 0
                    || value.storage_local_cookie == 0
                    || [
                        value.native_namespace,
                        value.head_commitment,
                        value.publication,
                        value.selected_manifest,
                        value.backend_manifest,
                        value.verifier_manifest,
                    ]
                    .iter()
                    .any(|digest| !nonzero(*digest))
                {
                    return Err(invalid("Provider witness fields"));
                }
                value.catalog_head.validate()?;
                value.catalog_floor.validate()?;
                for number in [
                    value.root_local_cookie,
                    value.storage_local_cookie,
                    value.completion_sequence,
                    value.challenge_sequence,
                ] {
                    bytes.extend_from_slice(&number.to_be_bytes());
                }
                bytes.extend_from_slice(&value.authority.authority_id());
                bytes.extend_from_slice(&value.authority.authority_generation().to_be_bytes());
                bytes.extend_from_slice(value.authority.authority_digest().as_bytes());
                bytes.extend_from_slice(value.native_namespace.as_bytes());
                value.catalog_head.encode(&mut bytes);
                value.catalog_floor.encode(&mut bytes);
                for digest in [
                    value.head_commitment,
                    value.publication,
                    value.selected_manifest,
                    value.backend_manifest,
                    value.verifier_manifest,
                ] {
                    bytes.extend_from_slice(digest.as_bytes());
                }
                encode_records(
                    &mut bytes,
                    &value.records,
                    &PROVIDER_NATIVE_WITNESS_FAMILIES_V1,
                )?;
            }
            Self::Storage(value) => {
                if value.local_socket_cookie == 0
                    || value.request_trust_generation == 0
                    || !nonzero(value.request_trust_file)
                    || value.issuance.family != NativeHeldRecordFamilyV1::StorageIssuance
                {
                    return Err(invalid("Storage witness fields"));
                }
                for number in [
                    value.local_socket_cookie,
                    value.primary_sequence,
                    value.workspace_sequence,
                    value.request_trust_sequence,
                    value.issuance_sequence,
                    value.request_trust_generation,
                ] {
                    bytes.extend_from_slice(&number.to_be_bytes());
                }
                bytes.extend_from_slice(value.request_trust_file.as_bytes());
                bytes.extend_from_slice(&value.issuance.to_canonical_bytes());
            }
        }
        Ok(bytes)
    }

    /// Decodes only the exact witness shape implied by the enclosing sender.
    ///
    /// # Errors
    ///
    /// Rejects wrong width/version/reserved fields, key family or scalar shape.
    pub fn from_canonical_bytes(owner: NativeHeldOwnerV1, bytes: &[u8]) -> Result<Self> {
        let expected = match owner {
            NativeHeldOwnerV1::Root => 642,
            NativeHeldOwnerV1::Provider => 1110,
            NativeHeldOwnerV1::Storage => 172,
        };
        if bytes.len() != expected {
            return Err(invalid("owner witness width"));
        }
        let mut reader = Reader::new(bytes);
        if reader.u16()? != 1 {
            return Err(invalid("witness version"));
        }
        reader.zeros(6)?;
        let value = match owner {
            NativeHeldOwnerV1::Root => Self::Root(RootNativeHeldWitnessV1 {
                local_socket_cookie: reader.u64()?,
                journal_sequence: reader.u64()?,
                planning_sequence: reader.u64()?,
                trust: NativeHeldGenerationClaimV1::decode(&mut reader)?,
                revocation: NativeHeldGenerationClaimV1::decode(&mut reader)?,
                provider_head: NativeHeldGenerationClaimV1::decode(&mut reader)?,
                provider_floor: NativeHeldGenerationClaimV1::decode(&mut reader)?,
                publication: reader.digest()?,
                records: decode_records(&mut reader, ROOT_NATIVE_WITNESS_FAMILIES_V1)?,
            }),
            NativeHeldOwnerV1::Provider => Self::Provider(ProviderNativeHeldWitnessV1 {
                root_local_cookie: reader.u64()?,
                storage_local_cookie: reader.u64()?,
                completion_sequence: reader.u64()?,
                challenge_sequence: reader.u64()?,
                authority: SourceProviderAuthorityV1::new(
                    reader.array()?,
                    reader.u64()?,
                    reader.digest()?,
                )
                .map_err(|_| invalid("Provider authority tuple"))?,
                native_namespace: reader.digest()?,
                catalog_head: NativeHeldGenerationClaimV1::decode(&mut reader)?,
                catalog_floor: NativeHeldGenerationClaimV1::decode(&mut reader)?,
                head_commitment: reader.digest()?,
                publication: reader.digest()?,
                selected_manifest: reader.digest()?,
                backend_manifest: reader.digest()?,
                verifier_manifest: reader.digest()?,
                records: decode_records(&mut reader, PROVIDER_NATIVE_WITNESS_FAMILIES_V1)?,
            }),
            NativeHeldOwnerV1::Storage => Self::Storage(StorageNativeHeldWitnessV1 {
                local_socket_cookie: reader.u64()?,
                primary_sequence: reader.u64()?,
                workspace_sequence: reader.u64()?,
                request_trust_sequence: reader.u64()?,
                issuance_sequence: reader.u64()?,
                request_trust_generation: reader.u64()?,
                request_trust_file: reader.digest()?,
                issuance: NativeHeldByteWitnessV1::decode(
                    NativeHeldRecordFamilyV1::StorageIssuance,
                    &mut reader,
                )?,
            }),
        };
        reader.finish()?;
        if value.to_canonical_bytes()? != bytes {
            return Err(invalid("owner witness canonical bytes"));
        }
        Ok(value)
    }
}

pub(super) fn encode_records<const N: usize>(
    bytes: &mut Vec<u8>,
    records: &[NativeHeldByteWitnessV1; N],
    families: &[NativeHeldRecordFamilyV1; N],
) -> Result<()> {
    for (record, family) in records.iter().zip(families) {
        if record.family != *family {
            return Err(invalid("fixed witness order"));
        }
        bytes.extend_from_slice(&record.to_canonical_bytes());
    }
    Ok(())
}

pub(super) fn decode_records<const N: usize>(
    reader: &mut Reader<'_>,
    families: [NativeHeldRecordFamilyV1; N],
) -> Result<[NativeHeldByteWitnessV1; N]> {
    let mut records = Vec::with_capacity(N);
    for family in families {
        records.push(NativeHeldByteWitnessV1::decode(family, reader)?);
    }
    records
        .try_into()
        .map_err(|_| invalid("fixed witness count"))
}
