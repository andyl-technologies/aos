//! Private canonical account-companion DATA and checked obligation folding.
//!
//! This child owns neither an authority nor another account/Journal reducer.
//! Original owner comparison, enrollment, native co-commit and currentness are
//! mandatory separate joins at the actual Publisher store and cohort owner.
//!
//! ```text
//! AOSGUBC1 header228 | owner140[<=16] | obligation312[<=64] | checksum32
//! account-coverage/<project16><generationBE64>
//! UUID = SHA256(transaction-domain || bytes excluding UUID/checksum)[0..16]
//! owner disposition: 0 = native COMMIT, 1 = empty native, 2 = physical empty
//! ```

use aos_sandbox_core::{ObjectDigest, ProjectId, ResourceDimension, ResourceVector};
use sha2::{Digest as _, Sha256};

use super::{PublisherPolicyError, array, key};
use super::project_authorization_source_v2::commitment;

pub(super) const PREFIX: &[u8] = b"git-upload/account-coverage/";
const MAGIC: &[u8; 8] = b"AOSGUBC1";
const DOMAIN: &[u8] = b"aos.sandbox.git-upload.account-coverage.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.git-upload.account-coverage-transaction.v1\0";
const HEADER_BYTES: usize = 228;
const OWNER_BYTES: usize = 140;
const OBLIGATION_BYTES: usize = 312;
const MAXIMUM_OWNERS: usize = 16;
const MAXIMUM_OBLIGATIONS: usize = 64;
pub(super) const MAXIMUM_BYTES: usize =
    HEADER_BYTES + MAXIMUM_OWNERS * OWNER_BYTES + MAXIMUM_OBLIGATIONS * OBLIGATION_BYTES + 32;

type Result<T> = std::result::Result<T, PublisherPolicyError>;

pub(super) fn first_profile_key(project: ProjectId) -> Vec<u8> {
    key(PREFIX, project.as_bytes(), Some(2))
}

/// Supplies nonauthorizing coordinates from the retained successor attempt.
pub(super) struct EmptyAccountCoverageFieldsV1 {
    pub(super) project: ProjectId,
    pub(super) generation: u64,
    pub(super) origin: ObjectDigest,
    pub(super) account: ObjectDigest,
    pub(super) predecessor: ObjectDigest,
    pub(super) enrollment: ObjectDigest,
    pub(super) ceiling_authority: ObjectDigest,
    pub(super) cpu_period_micros: u64,
}

/// Encodes only the first covered profile, after its actual owners prove empty.
///
/// The caller supplies the original owner rows, not resource amounts. This
/// codec cannot establish their provenance or authorize a successor append.
pub(super) fn encode_empty_first_profile(
    fields: &EmptyAccountCoverageFieldsV1,
    owners: &[[u8; OWNER_BYTES]],
) -> Result<Vec<u8>> {
    if owners.is_empty() || owners.len() > MAXIMUM_OWNERS {
        return Err(PublisherPolicyError::CorruptState);
    }
    let length = HEADER_BYTES
        .checked_add(owners.len().checked_mul(OWNER_BYTES)
            .ok_or(PublisherPolicyError::CorruptState)?)
        .and_then(|size| size.checked_add(32))
        .ok_or(PublisherPolicyError::CorruptState)?;
    if length > MAXIMUM_BYTES {
        return Err(PublisherPolicyError::CorruptState);
    }

    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&[0, 1, 0, 0]);
    bytes.extend_from_slice(fields.project.as_bytes());
    bytes.extend_from_slice(&fields.generation.to_be_bytes());
    for digest in [
        fields.origin,
        fields.account,
        fields.predecessor,
        fields.enrollment,
        fields.ceiling_authority,
    ] {
        bytes.extend_from_slice(digest.as_bytes());
    }
    bytes.extend_from_slice(&fields.cpu_period_micros.to_be_bytes());
    bytes.extend_from_slice(&[0; 16]);
    let owner_count = u16::try_from(owners.len())
        .map_err(|_| PublisherPolicyError::CorruptState)?;
    bytes.extend_from_slice(&owner_count.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&[0; 4]);
    for owner in owners {
        bytes.extend_from_slice(owner);
    }

    // The native identity excludes its own field and the later checksum. It
    // commits the exact original owner rows rather than a projected census.
    let transaction: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update(&bytes[..204])
        .chain_update(&bytes[220..])
        .finalize()
        .into();
    bytes[204..220].copy_from_slice(&transaction[..16]);
    let checksum = commitment(DOMAIN, &bytes);
    bytes.extend_from_slice(checksum.as_bytes());

    // There is one canonical shape/fold body for both encoding and replay.
    AccountCoverageV1::decode(&bytes)?.require_empty_first_profile()?;
    Ok(bytes)
}

/// Borrows one fully shape-checked companion without authenticating its claims.
pub(super) struct AccountCoverageV1<'record> {
    bytes: &'record [u8],
    owners: usize,
    obligations: usize,
}

impl<'record> AccountCoverageV1<'record> {
    pub(super) fn decode(bytes: &'record [u8]) -> Result<Self> {
        if !(HEADER_BYTES + 32..=MAXIMUM_BYTES).contains(&bytes.len())
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes.get(8..12) != Some([0, 1, 0, 0].as_slice())
            || bytes.get(224..228) != Some([0; 4].as_slice())
        {
            return Err(PublisherPolicyError::CorruptState);
        }
        let owners = usize::from(u16::from_be_bytes(array(bytes, 220)?));
        let obligations = usize::from(u16::from_be_bytes(array(bytes, 222)?));
        if owners == 0 || owners > MAXIMUM_OWNERS || obligations > MAXIMUM_OBLIGATIONS {
            return Err(PublisherPolicyError::CorruptState);
        }
        let expected = HEADER_BYTES
            .checked_add(owners.checked_mul(OWNER_BYTES).ok_or(PublisherPolicyError::CorruptState)?)
            .and_then(|size| size.checked_add(obligations.checked_mul(OBLIGATION_BYTES)?))
            .and_then(|size| size.checked_add(32))
            .ok_or(PublisherPolicyError::CorruptState)?;
        if expected != bytes.len() {
            return Err(PublisherPolicyError::CorruptState);
        }
        let checksum_offset = bytes.len() - 32;
        if commitment(DOMAIN, &bytes[..checksum_offset]).as_bytes()
                != &array::<32>(bytes, checksum_offset)?
        {
            return Err(PublisherPolicyError::CorruptState);
        }

        let record = Self { bytes, owners, obligations };
        record.validate_header()?;
        record.validate_rows()?;
        record.fold()?;
        Ok(record)
    }

    pub(super) fn project(&self) -> Result<ProjectId> {
        Ok(ProjectId::from_bytes(array(self.bytes, 12)?))
    }

    pub(super) fn generation(&self) -> Result<u64> {
        Ok(u64::from_be_bytes(array(self.bytes, 28)?))
    }

    pub(super) fn origin(&self) -> Result<ObjectDigest> {
        self.digest_at(36)
    }

    pub(super) fn account(&self) -> Result<ObjectDigest> {
        self.digest_at(68)
    }

    pub(super) fn predecessor(&self) -> Result<ObjectDigest> {
        self.digest_at(100)
    }

    pub(super) fn enrollment(&self) -> Result<ObjectDigest> {
        self.digest_at(132)
    }

    pub(super) fn ceiling_authority(&self) -> Result<ObjectDigest> {
        self.digest_at(164)
    }

    pub(super) fn cpu_period_micros(&self) -> Result<u64> {
        Ok(u64::from_be_bytes(array(self.bytes, 196)?))
    }

    pub(super) fn transaction(&self) -> Result<[u8; 16]> {
        array(self.bytes, 204)
    }

    pub(super) fn digest(&self) -> ObjectDigest {
        commitment(DOMAIN, self.bytes)
    }

    pub(super) fn key(&self) -> Result<Vec<u8>> {
        Ok(key(PREFIX, self.project()?.as_bytes(), Some(self.generation()?)))
    }

    // The first profile has no owner migration or retirement. Successors must
    // retain these complete original rows, not only their cardinality.
    pub(super) fn owner_bytes(&self) -> &'record [u8] {
        &self.bytes[HEADER_BYTES..HEADER_BYTES + self.owners * OWNER_BYTES]
    }

    fn digest_at(&self, offset: usize) -> Result<ObjectDigest> {
        Ok(ObjectDigest::from_bytes(array(self.bytes, offset)?))
    }

    fn owner(&self, index: usize) -> Result<&'record [u8]> {
        if index >= self.owners {
            return Err(PublisherPolicyError::CorruptState);
        }
        let offset = HEADER_BYTES + index * OWNER_BYTES;
        self.bytes.get(offset..offset + OWNER_BYTES).ok_or(PublisherPolicyError::CorruptState)
    }

    fn obligation(&self, index: usize) -> Result<&'record [u8]> {
        if index >= self.obligations {
            return Err(PublisherPolicyError::CorruptState);
        }
        let offset = HEADER_BYTES + self.owners * OWNER_BYTES + index * OBLIGATION_BYTES;
        self.bytes.get(offset..offset + OBLIGATION_BYTES).ok_or(PublisherPolicyError::CorruptState)
    }

    fn validate_header(&self) -> Result<()> {
        if self.project()?.as_bytes() == &[0; 16]
            || self.generation()? < 2
            || self.origin()?.as_bytes() == &[0; 32]
            || self.account()?.as_bytes() == &[0; 32]
            || self.enrollment()?.as_bytes() == &[0; 32]
            || self.ceiling_authority()?.as_bytes() == &[0; 32]
            || self.cpu_period_micros()? == 0
            || (self.generation()? == 2) != (self.predecessor()?.as_bytes() == &[0; 32])
        {
            return Err(PublisherPolicyError::CorruptState);
        }
        let mut digest = Sha256::new();
        digest.update(TRANSACTION_DOMAIN);
        digest.update(&self.bytes[..204]);
        digest.update(&self.bytes[220..self.bytes.len() - 32]);
        let digest: [u8; 32] = digest.finalize().into();
        if self.transaction()?.as_slice() != &digest[..16] {
            return Err(PublisherPolicyError::CorruptState);
        }
        Ok(())
    }

    fn validate_rows(&self) -> Result<()> {
        let mut previous_owner = None;
        for index in 0..self.owners {
            let owner = self.owner(index)?;
            let kind = *owner.first().ok_or(PublisherPolicyError::CorruptState)?;
            let disposition = owner[1];
            let sequence = u64::from_be_bytes(array(owner, 68)?);
            if !(1..=11).contains(&kind)
                || owner.get(2..4) != Some([0; 2].as_slice())
                || !matches!((disposition, sequence), (0, 1..) | (1 | 2, 0))
                || (disposition == 2 && kind != 6)
                || (kind == 6 && disposition != 2)
                || array::<16>(owner, 4)? == [0; 16]
                || array::<16>(owner, 20)? == [0; 16]
                || array::<32>(owner, 36)? == [0; 32]
                || array::<32>(owner, 76)? == [0; 32]
                || array::<32>(owner, 108)? == [0; 32]
            {
                return Err(PublisherPolicyError::CorruptState);
            }
            let identity = (kind, array::<16>(owner, 4)?, array::<16>(owner, 20)?, array::<32>(owner, 108)?);
            if previous_owner.is_some_and(|old| old >= identity) {
                return Err(PublisherPolicyError::CorruptState);
            }
            previous_owner = Some(identity);
        }

        let mut previous_obligation = None;
        for index in 0..self.obligations {
            let row = self.obligation(index)?;
            let identity = array::<32>(row, 0)?;
            let owner = usize::from(u16::from_be_bytes(array(row, 32)?));
            let kind = *row.get(34).ok_or(PublisherPolicyError::CorruptState)?;
            let disposition = *row.get(35).ok_or(PublisherPolicyError::CorruptState)?;
            let relation = *row.get(36).ok_or(PublisherPolicyError::CorruptState)?;
            let enclosing = array::<32>(row, 40)?;
            let retirement = array::<32>(row, 104)?;
            if identity == [0; 32]
                || previous_obligation.is_some_and(|old| old >= identity)
                || owner >= self.owners
                || !(1..=11).contains(&kind)
                || !(1..=4).contains(&disposition)
                || !(1..=2).contains(&relation)
                || row.get(37..40) != Some([0; 3].as_slice())
                || array::<32>(row, 72)? == [0; 32]
                || (relation == 1) != (enclosing == [0; 32])
                || enclosing == identity
                || (disposition == 4) != (retirement != [0; 32])
            {
                return Err(PublisherPolicyError::CorruptState);
            }
            previous_obligation = Some(identity);
        }
        Ok(())
    }

    fn find_obligation(&self, identity: [u8; 32]) -> Result<usize> {
        for index in 0..self.obligations {
            if array::<32>(self.obligation(index)?, 0)? == identity {
                return Ok(index);
            }
        }
        Err(PublisherPolicyError::CorruptState)
    }

    // No projection into a second accounting representation is retained. Each
    // fixed row lends its vector directly to the existing checked arithmetic.
    fn amounts(&self, row: &[u8]) -> Result<ResourceVector> {
        let mut amounts = [0; ResourceDimension::COUNT];
        for (index, _dimension) in ResourceDimension::ALL.into_iter().enumerate() {
            amounts[index] = u64::from_be_bytes(array(row, 136 + index * 8)?);
        }
        Ok(ResourceVector::new(amounts))
    }

    /// Folds top-level debt and checks complete direct-child containment.
    pub(super) fn fold(&self) -> Result<(ResourceVector, ResourceVector)> {
        let mut committed = ResourceVector::ZERO;
        let mut reserved = ResourceVector::ZERO;
        for index in 0..self.obligations {
            let row = self.obligation(index)?;
            let disposition = *row.get(35).ok_or(PublisherPolicyError::CorruptState)?;
            if row.get(36) == Some(&1) && disposition != 4 {
                let amounts = self.amounts(row)?;
                let total = if disposition == 1 { &mut committed } else { &mut reserved };
                *total = total.checked_add(amounts).map_err(|_| PublisherPolicyError::CorruptState)?;
            }

            let mut ancestor = index;
            for depth in 0..=self.obligations {
                let current = self.obligation(ancestor)?;
                if current.get(36) == Some(&1) {
                    break;
                }
                if depth == self.obligations {
                    return Err(PublisherPolicyError::CorruptState);
                }
                ancestor = self.find_obligation(array(current, 40)?)?;
                if disposition != 4 && self.obligation(ancestor)?.get(35) == Some(&4) {
                    return Err(PublisherPolicyError::CorruptState);
                }
            }

            // Sum every direct nonretired child, not independent per-child
            // comparisons. Parent amounts describe its envelope, not an extra
            // additive charge; contained rows are not counted twice above.
            let identity = array::<32>(row, 0)?;
            let mut children = ResourceVector::ZERO;
            for child in 0..self.obligations {
                let child = self.obligation(child)?;
                if child.get(36) == Some(&2)
                    && child.get(35) != Some(&4)
                    && array::<32>(child, 40)? == identity
                {
                    children = children.checked_add(self.amounts(child)?)
                        .map_err(|_| PublisherPolicyError::CorruptState)?;
                }
            }
            if !children.is_within(self.amounts(row)?) {
                return Err(PublisherPolicyError::CorruptState);
            }
        }
        Ok((committed, reserved))
    }

    // The first installed profile has no retirement producer or populated
    // tenant domain. Authentication/coverage is checked on real owners before
    // this restriction; an empty row list by itself proves nothing.
    pub(super) fn require_empty_first_profile(&self) -> Result<()> {
        if self.obligations != 0 {
            return Err(PublisherPolicyError::CorruptState);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These rows exercise canonical DATA shape only. They are not signed
    // enrollment, native-history or positive protected-owner fixtures.
    fn fields() -> EmptyAccountCoverageFieldsV1 {
        EmptyAccountCoverageFieldsV1 {
            project: ProjectId::from_bytes([1; 16]),
            generation: 2,
            origin: ObjectDigest::from_bytes([2; 32]),
            account: ObjectDigest::from_bytes([3; 32]),
            predecessor: ObjectDigest::from_bytes([0; 32]),
            enrollment: ObjectDigest::from_bytes([4; 32]),
            ceiling_authority: ObjectDigest::from_bytes([5; 32]),
            cpu_period_micros: 100_000,
        }
    }

    fn owner(node: u8) -> [u8; OWNER_BYTES] {
        let mut bytes = [0; OWNER_BYTES];
        bytes[0] = 1;
        bytes[4..20].fill(node);
        bytes[20..36].fill(2);
        bytes[36..68].fill(3);
        bytes[68..76].copy_from_slice(&1_u64.to_be_bytes());
        bytes[76..108].fill(4);
        bytes[108..140].fill(5);
        bytes
    }

    #[test]
    fn empty_shape_round_trips_without_an_authority_constructor() {
        let owners = [owner(1), owner(2)];
        let bytes = encode_empty_first_profile(&fields(), &owners).unwrap();

        let decoded = AccountCoverageV1::decode(&bytes).unwrap();
        assert_eq!(bytes.len(), HEADER_BYTES + 2 * OWNER_BYTES + 32);
        assert_eq!(decoded.project().unwrap(), fields().project);
        assert_eq!(decoded.generation().unwrap(), 2);
        assert_eq!(decoded.fold().unwrap(), (ResourceVector::ZERO, ResourceVector::ZERO));
        assert!(decoded.require_empty_first_profile().is_ok());
    }

    #[test]
    fn owner_count_and_order_refuse_before_a_successful_carrier() {
        assert!(encode_empty_first_profile(&fields(), &[]).is_err());
        assert!(encode_empty_first_profile(&fields(), &[owner(1); 17]).is_err());
        assert!(encode_empty_first_profile(&fields(), &[owner(1), owner(1)]).is_err());
        assert!(encode_empty_first_profile(&fields(), &[owner(2), owner(1)]).is_err());

        let owners: [[u8; OWNER_BYTES]; MAXIMUM_OWNERS] =
            std::array::from_fn(|index| owner(u8::try_from(index + 1).unwrap()));
        assert!(encode_empty_first_profile(&fields(), &owners).is_ok());
    }

    #[test]
    fn empty_native_disposition_keeps_original_origin_and_prefix() {
        let mut original_empty = owner(1);
        original_empty[1] = 1;
        original_empty[68..76].copy_from_slice(&0_u64.to_be_bytes());

        let bytes = encode_empty_first_profile(&fields(), &[original_empty]).unwrap();
        let decoded = AccountCoverageV1::decode(&bytes).unwrap();
        assert_eq!(decoded.owner_bytes(), original_empty.as_slice());

        let mut wrong_sequence = original_empty;
        wrong_sequence[68..76].copy_from_slice(&1_u64.to_be_bytes());
        assert!(encode_empty_first_profile(&fields(), &[wrong_sequence]).is_err());

        let mut missing_origin = original_empty;
        missing_origin[36..68].fill(0);
        assert!(encode_empty_first_profile(&fields(), &[missing_origin]).is_err());

        let mut missing_prefix = original_empty;
        missing_prefix[76..108].fill(0);
        assert!(encode_empty_first_profile(&fields(), &[missing_prefix]).is_err());
    }

    #[test]
    fn physical_empty_is_distinct_from_an_empty_native_commit_history() {
        let mut physical_empty = owner(1);
        physical_empty[0] = 6;
        physical_empty[1] = 2;
        physical_empty[68..76].copy_from_slice(&0_u64.to_be_bytes());
        assert!(encode_empty_first_profile(&fields(), &[physical_empty]).is_ok());

        let mut native_disposition = physical_empty;
        native_disposition[1] = 1;
        assert!(encode_empty_first_profile(&fields(), &[native_disposition]).is_err());

        let mut wrong_owner = physical_empty;
        wrong_owner[0] = 1;
        assert!(encode_empty_first_profile(&fields(), &[wrong_owner]).is_err());

        let mut missing_commit = owner(1);
        missing_commit[68..76].copy_from_slice(&0_u64.to_be_bytes());
        assert!(encode_empty_first_profile(&fields(), &[missing_commit]).is_err());
    }

    #[test]
    fn generation_period_and_original_identity_are_not_wildcards() {
        let owners = [owner(1)];
        let mut invalid = fields();
        invalid.cpu_period_micros = 0;
        assert!(encode_empty_first_profile(&invalid, &owners).is_err());

        invalid = fields();
        invalid.generation = 1;
        assert!(encode_empty_first_profile(&invalid, &owners).is_err());

        invalid = fields();
        invalid.predecessor = ObjectDigest::from_bytes([6; 32]);
        assert!(encode_empty_first_profile(&invalid, &owners).is_err());

        let mut bytes = encode_empty_first_profile(&fields(), &owners).unwrap();
        bytes[204] ^= 1;
        let checksum_offset = bytes.len() - 32;
        let checksum = commitment(DOMAIN, &bytes[..checksum_offset]);
        bytes[checksum_offset..].copy_from_slice(checksum.as_bytes());
        assert!(AccountCoverageV1::decode(&bytes).is_err());
    }
}
