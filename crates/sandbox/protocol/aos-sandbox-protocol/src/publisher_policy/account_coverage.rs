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

crate::define_provider_account_coverage_data_recipe_v1!(
    super::PublisherPolicyError::CorruptState
);

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
