//! Shares the existing immutable initial-capability/bootstrap DATA relation.
//!
//! The concrete native issuer retains its signed entitlement, authenticated
//! holder, protected clock/policy and actual journal. This saved-state codec
//! and exact record relation supply no current capability or writer authority.
//!
//! ```text
//! bootstrap/<key-digest32> = {version,key_digest,request_digest,
//!   entitlement_digest,entitlement_generation,capability_id,principal,
//!   project,channel_binding}
//! entitlement/current = {version,generation,digest}
//! ```

/// Defines the same private bootstrap codec and initial-read comparisons.
///
/// The private module alias binds the same canonical record DATA recipe; it is
/// not supplied by a runtime request, effect caller, closure or authority loan.
#[macro_export]
macro_rules! define_provider_initial_issuance_data_recipe_v1 {
    ($refused:expr) => {
        const BOOTSTRAP_KEY_DOMAIN: &[u8] = b"aos.sandbox.public-capability-bootstrap-key.v1\0";
        const BOOTSTRAP_KEY_PREFIX: &[u8] = b"bootstrap/";
        const ENTITLEMENT_HEAD_KEY: &[u8] = b"entitlement/current";
        const MAXIMUM_BOOTSTRAP_RECORDS: usize = 65_536;

        #[derive(Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        struct BootstrapRecordV1 {
            version: u16,
            key_digest: [u8; 32],
            request_digest: [u8; 32],
            entitlement_digest: ObjectDigest,
            entitlement_generation: u64,
            capability_id: CapabilityId,
            principal: PrincipalId,
            project: ProjectId,
            channel_binding: [u8; 32],
        }

        #[derive(Clone, Copy, Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        struct EntitlementHeadV1 {
            version: u16,
            generation: u64,
            digest: ObjectDigest,
        }

        fn bootstrap_key(digest: &[u8; 32]) -> Vec<u8> {
            let mut key = Vec::with_capacity(BOOTSTRAP_KEY_PREFIX.len() + digest.len());
            key.extend_from_slice(BOOTSTRAP_KEY_PREFIX);
            key.extend_from_slice(digest);
            key
        }

        fn holder_key_digest(principal: PrincipalId, project: ProjectId, binding: &[u8; 32]) -> [u8; 32] {
            Sha256::new()
                .chain_update(BOOTSTRAP_KEY_DOMAIN)
                .chain_update(principal.as_bytes())
                .chain_update(project.as_bytes())
                .chain_update(binding)
                .finalize()
                .into()
        }

        fn decode_canonical<T>(bytes: &[u8]) -> Result<T, InitialPublicCapabilityErrorV1>
        where
            T: for<'de> Deserialize<'de> + Serialize,
        {
            let value: T =
                serde_json::from_slice(bytes).map_err(|_| $refused)?;
            if serde_json::to_vec(&value).map_err(|_| $refused)? != bytes {
                return Err($refused);
            }
            Ok(value)
        }

        fn validate_bootstrap_records<'a>(
            records: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
        ) -> Result<Option<EntitlementHeadV1>, InitialPublicCapabilityErrorV1> {
            let mut head = None;
            let mut count = 0_usize;
            let mut greatest_record_generation = 0_u64;
            for (key, bytes) in records {
                count = count
                    .checked_add(1)
                    .ok_or($refused)?;
                if count > MAXIMUM_BOOTSTRAP_RECORDS || bytes.len() > 2_048 {
                    return Err($refused);
                }
                if key == ENTITLEMENT_HEAD_KEY {
                    let value: EntitlementHeadV1 = decode_canonical(bytes)?;
                    if value.version != 1 || value.generation == 0 || value.digest.as_bytes() == &[0; 32] {
                        return Err($refused);
                    }
                    head = Some(value);
                } else if let Some(digest) = key.strip_prefix(BOOTSTRAP_KEY_PREFIX) {
                    let value: BootstrapRecordV1 = decode_canonical(bytes)?;
                    if digest.len() != 32
                        || digest != value.key_digest
                        || value.version != 1
                        || value.request_digest == [0; 32]
                        || value.entitlement_digest.as_bytes() == &[0; 32]
                        || value.entitlement_generation == 0
                        || value.capability_id.as_bytes() == &[0; 16]
                        || value.principal.as_bytes() == &[0; 16]
                        || value.project.as_bytes() == &[0; 16]
                        || value.channel_binding == [0; 32]
                        || value.key_digest
                            != holder_key_digest(value.principal, value.project, &value.channel_binding)
                    {
                        return Err($refused);
                    }
                    greatest_record_generation =
                        greatest_record_generation.max(value.entitlement_generation);
                } else {
                    return Err($refused);
                }
            }
            if count != 0 && head.is_none_or(|head| head.generation < greatest_record_generation) {
                return Err($refused);
            }
            Ok(head)
        }

        fn require_git_coverage_initial_transaction_v1(
            transaction: &JournalTransaction,
            previous_head: Option<EntitlementHeadV1>,
        ) -> Result<EntitlementHeadV1, InitialPublicCapabilityErrorV1> {
            let records = transaction.records();
            if !(2..=3).contains(&records.len())
                || records[0].namespace() != RecordNamespace::PublisherAuthority
                || records[1].namespace() != RecordNamespace::PublicCapabilityBootstrap
                || records.iter().any(|record| record.value().is_none())
                || records[1].value().is_none_or(|value| value.len() > 2_048)
            {
                return Err($refused);
            }
            let (capability, _) = provider_capability_record_data::decode_git_coverage_initial_content_read_v1(
                records[0].key(), records[0].value().ok_or($refused)?,
            )?;
            let retained: BootstrapRecordV1 = decode_canonical(
                records[1].value().ok_or($refused)?,
            )?;
            let claims = capability.claims();
            if retained.version != 1
                || retained.capability_id != capability.id()
                || transaction.id() != capability.id().as_bytes()
                || retained.principal != claims.holder
                || retained.project != claims.project
                || retained.channel_binding != *claims.channel_binding.as_bytes()
                || claims.root_subject != claims.holder
                || claims.issuer != claims.audience
                || claims.sandbox.is_some() || claims.incarnation.is_some()
                || claims.assignment_epoch.is_some()
                || retained.key_digest != holder_key_digest(
                    retained.principal, retained.project, &retained.channel_binding,
                )
                || records[1].key() != bootstrap_key(&retained.key_digest)
                || retained.request_digest == [0; 32]
                || retained.entitlement_digest.as_bytes() == &[0; 32]
                || retained.entitlement_generation == 0
            {
                return Err($refused);
            }
            let next = EntitlementHeadV1 {
                version: 1, generation: retained.entitlement_generation,
                digest: retained.entitlement_digest,
            };
            let advances = previous_head.is_none_or(|old| next.generation > old.generation);
            if records.len() != if advances { 3 } else { 2 }
                || previous_head.is_some_and(|old| next.generation < old.generation
                    || (next.generation == old.generation && next.digest != old.digest))
            {
                return Err($refused);
            }
            if advances {
                let head = &records[2];
                if head.namespace() != RecordNamespace::PublicCapabilityBootstrap
                    || head.key() != ENTITLEMENT_HEAD_KEY
                    || head.value().is_none_or(|value| value.len() > 2_048)
                {
                    return Err($refused);
                }
                let encoded: EntitlementHeadV1 = decode_canonical(
                    head.value().ok_or($refused)?,
                )?;
                if (encoded.version, encoded.generation, encoded.digest)
                    != (next.version, next.generation, next.digest)
                {
                    return Err($refused);
                }
            }
            Ok(next)
        }

        pub(crate) fn require_git_coverage_initial_from_state_v1(
            transaction: &JournalTransaction,
            state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        ) -> Result<(), InitialPublicCapabilityErrorV1> {
            let head = validate_bootstrap_records(state.iter()
                .filter(|((namespace, _), _)| *namespace == RecordNamespace::PublicCapabilityBootstrap)
                .map(|((_, key), value)| (key.as_slice(), value.as_slice())))?;
            if transaction.records().iter().take(2).any(|record| {
                state.keys().any(|(namespace, key)| {
                    *namespace == record.namespace() && key.as_slice() == record.key()
                })
            }) {
                return Err($refused);
            }
            require_git_coverage_initial_transaction_v1(transaction, head).map(|_| ())
        }

    };
}
