//! Shares the existing historical CLI time-floor DATA body.
//!
//! The concrete Controller and Source modules retain their own private types,
//! existing error projections and actual native/currentness entry points. This
//! recipe can only compare or encode historical DATA, never lend authority.

/// Defines the existing private historical time-floor codec and fold.
///
/// The caller binds only its existing closed comparison-error value. It keeps
/// the same native clock, signed authorization, journal and receiving owners.
#[macro_export]
macro_rules! define_provider_time_floor_data_recipe_v1 {
    ($refused:expr) => {
        const TIME_FLOOR_REVISION_MAGIC: &[u8; 8] = b"AOSCTFR1";
        const TIME_FLOOR_HEAD_MAGIC: &[u8; 8] = b"AOSCTFH1";
        const TIME_FLOOR_CURRENT_KEY: &[u8] = b"cli-authorization-time/current";
        const TIME_FLOOR_REVISION_PREFIX: &[u8] = b"cli-authorization-time/revision/";
        const TIME_FLOOR_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.cli.authorization-time-floor.v1\0";
        const TIME_FLOOR_TRANSACTION_DOMAIN: &[u8] =
            b"aos.sandbox.cli.authorization-time-floor-transaction.v1\0";

        #[derive(Clone, Copy)]
        pub(crate) struct ProtectedTimeFloorRevisionV1 {
            generation: u64,
            clock: RawPairedClockSample,
            previous: ObjectDigest,
            digest: ObjectDigest,
        }

        fn load_protected_time_floor_records<'a>(
            records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
        ) -> Result<Option<ProtectedTimeFloorRevisionV1>, CliAuthorizationAdapterError> {
            let mut revisions = BTreeMap::new();
            let mut head = None;
            for (key, value) in records {
                if key == TIME_FLOOR_CURRENT_KEY {
                    if head.replace(decode_time_floor_head(value)?).is_some() {
                        return Err($refused);
                    }
                } else if let Some(generation_bytes) = key.strip_prefix(TIME_FLOOR_REVISION_PREFIX) {
                    let generation = decode_u64(generation_bytes)?;
                    let revision = decode_time_floor_revision(value)?;
                    if generation != revision.generation || revisions.insert(generation, revision).is_some()
                    {
                        return Err($refused);
                    }
                } else {
                    return Err($refused);
                }
            }

            match (head, revisions.is_empty()) {
                (None, true) => Ok(None),
                (Some((head_generation, head_digest)), false) => {
                    let mut prior_digest = ObjectDigest::from_bytes([0; 32]);
                    let mut prior_revision = None;
                    for expected_generation in 1..=head_generation {
                        let revision = revisions
                            .get(&expected_generation)
                            .ok_or($refused)?;
                        if revision.previous != prior_digest {
                            return Err($refused);
                        }
                        validate_clock_advancement(prior_revision, revision.clock)?;
                        prior_digest = revision.digest;
                        prior_revision = Some(*revision);
                    }
                    if u64::try_from(revisions.len()) != Ok(head_generation) || prior_digest != head_digest
                    {
                        return Err($refused);
                    }
                    Ok(revisions.get(&head_generation).copied())
                }
                _ => Err($refused),
            }
        }

        pub(crate) fn require_git_coverage_floor_transaction_v1(
            transaction: &JournalTransaction,
            prior: Option<ProtectedTimeFloorRevisionV1>,
        ) -> Result<ProtectedTimeFloorRevisionV1, CliAuthorizationAdapterError> {
            let refused = || $refused;
            let records = transaction.records();
            if records.len() != 2
                || records.iter().any(|record| {
                    record.namespace() != RecordNamespace::CliAuthorizationTime
                        || record.value().is_none()
                })
            {
                return Err(refused());
            }
            let bytes = records[0].value().ok_or_else(refused)?;
            let revision = decode_time_floor_revision(bytes)?;
            let generation = prior.map_or(Some(1), |prior| prior.generation.checked_add(1))
                .ok_or_else(refused)?;
            if revision.generation != generation
                || revision.previous != prior.map_or(ObjectDigest::from_bytes([0; 32]), |prior| prior.digest)
                || records[0].key() != time_floor_revision_key(generation)
                || records[1].key() != TIME_FLOOR_CURRENT_KEY
                || decode_time_floor_head(records[1].value().ok_or_else(refused)?)?
                    != (generation, revision.digest)
            {
                return Err(refused());
            }
            validate_clock_advancement(prior, revision.clock)?;
            let digest = Sha256::new()
                .chain_update(TIME_FLOOR_TRANSACTION_DOMAIN)
                .chain_update(bytes)
                .finalize();
            let mut id: [u8; 16] = digest[..16].try_into().map_err(|_| refused())?;
            id[0] |= 0x80;
            if transaction.id() != &id {
                return Err(refused());
            }
            Ok(revision)
        }

        pub(crate) fn require_git_coverage_floor_from_state_v1(
            transaction: &JournalTransaction,
            state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        ) -> Result<(), CliAuthorizationAdapterError> {
            let prior = load_protected_time_floor_records(state.iter()
                .filter(|((namespace, _), _)| *namespace == RecordNamespace::CliAuthorizationTime)
                .map(|((_, key), value)| (key.as_slice(), value.as_slice())))?;
            require_git_coverage_floor_transaction_v1(transaction, prior).map(|_| ())
        }

        fn validate_clock_advancement(
            prior: Option<ProtectedTimeFloorRevisionV1>,
            clock: RawPairedClockSample,
        ) -> Result<(), CliAuthorizationAdapterError> {
            let Some(prior) = prior else {
                return Ok(());
            };
            if clock.provenance() != prior.clock.provenance()
                || clock.wall_seconds() < prior.clock.wall_seconds()
            {
                return Err($refused);
            }
            if clock.host_boot_id() != prior.clock.host_boot_id() {
                return Ok(());
            }

            let wall_elapsed = clock
                .wall_seconds()
                .checked_sub(prior.clock.wall_seconds())
                .and_then(|seconds| u64::try_from(seconds).ok())
                .and_then(|seconds| seconds.checked_mul(1_000_000_000))
                .ok_or($refused)?;
            let boottime_elapsed = clock
                .boottime_nanoseconds()
                .checked_sub(prior.clock.boottime_nanoseconds())
                .ok_or($refused)?;
            if wall_elapsed.abs_diff(boottime_elapsed) > CLOCK_PAIR_TOLERANCE_NANOSECONDS {
                return Err($refused);
            }
            Ok(())
        }

        fn encode_time_floor_revision(
            value: ProtectedTimeFloorRevisionV1,
            include_digest: bool,
        ) -> Vec<u8> {
            let mut encoded = Vec::with_capacity(128);
            encoded.extend_from_slice(TIME_FLOOR_REVISION_MAGIC);
            encoded.extend_from_slice(&value.generation.to_be_bytes());
            encoded.extend_from_slice(&value.clock.provenance().as_bytes());
            encoded.extend_from_slice(&value.clock.host_boot_id());
            encoded.extend_from_slice(&value.clock.wall_seconds().to_be_bytes());
            encoded.extend_from_slice(&value.clock.boottime_nanoseconds().to_be_bytes());
            encoded.extend_from_slice(value.previous.as_bytes());
            encoded.extend_from_slice(if include_digest {
                value.digest.as_bytes()
            } else {
                &[0; 32]
            });
            encoded
        }

        fn decode_time_floor_revision(
            bytes: &[u8],
        ) -> Result<ProtectedTimeFloorRevisionV1, CliAuthorizationAdapterError> {
            if bytes.len() != 128 || &bytes[..8] != TIME_FLOOR_REVISION_MAGIC {
                return Err($refused);
            }
            let generation = decode_u64(&bytes[8..16])?;
            if generation == 0 {
                return Err($refused);
            }
            let provenance_bytes = decode_array::<16>(&bytes[16..32])?;
            let host_boot_id = decode_array::<16>(&bytes[32..48])?;
            let wall_seconds = i64::from_be_bytes(decode_array::<8>(&bytes[48..56])?);
            let boottime_nanoseconds = u64::from_be_bytes(decode_array::<8>(&bytes[56..64])?);
            let previous = ObjectDigest::from_bytes(decode_array::<32>(&bytes[64..96])?);
            let digest = ObjectDigest::from_bytes(decode_array::<32>(&bytes[96..128])?);
            let expected = ObjectDigest::from_bytes(
                Sha256::new()
                    .chain_update(TIME_FLOOR_DIGEST_DOMAIN)
                    .chain_update(&bytes[..96])
                    .finalize()
                    .into(),
            );
            if digest != expected {
                return Err($refused);
            }
            let provenance = aos_sandbox_model::RawClockProvenance::new_untrusted(provenance_bytes)
                .map_err(|_| $refused)?;
            let clock = RawPairedClockSample::new_untrusted(
                provenance,
                host_boot_id,
                wall_seconds,
                boottime_nanoseconds,
            )
            .map_err(|_| $refused)?;
            Ok(ProtectedTimeFloorRevisionV1 {
                generation,
                clock,
                previous,
                digest,
            })
        }

        fn encode_time_floor_head(value: ProtectedTimeFloorRevisionV1) -> Vec<u8> {
            let mut encoded = Vec::with_capacity(48);
            encoded.extend_from_slice(TIME_FLOOR_HEAD_MAGIC);
            encoded.extend_from_slice(&value.generation.to_be_bytes());
            encoded.extend_from_slice(value.digest.as_bytes());
            encoded
        }

        fn decode_time_floor_head(
            bytes: &[u8],
        ) -> Result<(u64, ObjectDigest), CliAuthorizationAdapterError> {
            if bytes.len() != 48 || &bytes[..8] != TIME_FLOOR_HEAD_MAGIC {
                return Err($refused);
            }
            let generation = decode_u64(&bytes[8..16])?;
            let digest = ObjectDigest::from_bytes(decode_array::<32>(&bytes[16..48])?);
            if generation == 0 || digest.as_bytes() == &[0; 32] {
                return Err($refused);
            }
            Ok((generation, digest))
        }

        fn time_floor_revision_key(generation: u64) -> Vec<u8> {
            let mut key = Vec::with_capacity(TIME_FLOOR_REVISION_PREFIX.len() + 8);
            key.extend_from_slice(TIME_FLOOR_REVISION_PREFIX);
            key.extend_from_slice(&generation.to_be_bytes());
            key
        }

        fn decode_u64(bytes: &[u8]) -> Result<u64, CliAuthorizationAdapterError> {
            Ok(u64::from_be_bytes(decode_array::<8>(bytes)?))
        }

        fn decode_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CliAuthorizationAdapterError> {
            bytes
                .try_into()
                .map_err(|_| $refused)
        }

    };
}
