//! Borrows the common canonical broker fields before optional owned materialization.
//!
//! Both existing owned decoders and exact Storage Prepare comparisons use this
//! parser. Borrowed fields are DATA until the existing semantic validation or
//! equality with an already-validated original succeeds. Authentication remains
//! in the caller and always precedes payload parsing.

use super::*;

/// Keeps key text in its authenticated payload until an owned fence is needed.
pub(super) struct BorrowedFenceFieldsV1<'payload> {
    assignment: BrokerAssignment,
    node: NodeId,
    plan_digest: ObjectDigest,
    plan_expires_seconds: i64,
    stable_key_id_text: &'payload str,
    authority_generation: u64,
    authority_public_key: ObjectDigest,
    authority_usage: KeyUsage,
    local_lease_record: LocalLeaseRecord,
}

impl BorrowedFenceFieldsV1<'_> {
    pub(super) fn into_owned(self) -> Result<BrokerAuthorizationFenceV1, AuthorizationRecordError> {
        let stable_key_id = StableKeyId::new(self.stable_key_id_text.to_owned())
            .map_err(|_| AuthorizationRecordError::InvalidPayload)?;
        let ownership_authority = KeyReference::new(
            stable_key_id,
            self.authority_generation,
            self.authority_public_key,
            self.authority_usage,
        );
        BrokerAuthorizationFenceV1::new(
            self.assignment,
            self.node,
            self.plan_digest,
            self.plan_expires_seconds,
            ownership_authority,
            self.local_lease_record,
        )
    }

    pub(super) fn require_exact(
        self,
        expected: &BrokerAuthorizationFenceV1,
    ) -> Result<bool, AuthorizationRecordError> {
        validate_fence_fields(
            self.assignment,
            self.node,
            self.plan_digest,
            self.plan_expires_seconds,
            self.authority_generation,
            self.authority_public_key,
            self.authority_usage,
            &self.local_lease_record,
        )?;
        expected.validate()?;
        let authority = &expected.ownership_authority;
        Ok(self.assignment == expected.assignment
            && self.node == expected.node
            && self.plan_digest == expected.plan_digest
            && self.plan_expires_seconds == expected.plan_expires_seconds
            && self.stable_key_id_text == authority.stable_key_id().as_str()
            && self.authority_generation == authority.generation()
            && self.authority_public_key == authority.public_key_sha256()
            && self.authority_usage == authority.usage()
            && self.local_lease_record == expected.local_lease_record)
    }
}

/// Keeps the receipt borrowed while the fixed fields retain an empty Vec.
///
/// `Vec::new` allocates nothing. The existing owned decoder materializes the
/// receipt once before its unchanged semantic validator; the exact pending
/// comparison accepts only the actual empty-receipt Pending original.
pub(super) struct BorrowedEffectFieldsV1<'payload> {
    intent_without_receipt: BrokerEffectIntentV1,
    receipt: &'payload [u8],
}

impl BorrowedEffectFieldsV1<'_> {
    pub(super) fn into_owned(self) -> Result<BrokerEffectIntentV1, AuthorizationRecordError> {
        let mut intent = self.intent_without_receipt;
        intent.receipt = self.receipt.to_vec();
        intent.validate()?;
        Ok(intent)
    }

    pub(super) fn require_exact_pending(
        self,
        expected: &BrokerEffectIntentV1,
    ) -> Result<bool, AuthorizationRecordError> {
        self.intent_without_receipt
            .validate_with_receipt(self.receipt)?;
        expected.validate()?;
        if expected.status != BrokerEffectStatusV1::Pending || !expected.receipt.is_empty() {
            return Err(AuthorizationRecordError::InvalidPayload);
        }
        Ok(self.receipt.is_empty() && self.intent_without_receipt == *expected)
    }
}

pub(super) fn decode_fence_fields(
    bytes: &[u8],
    domain: BrokerDomain,
) -> Result<BorrowedFenceFieldsV1<'_>, AuthorizationRecordError> {
    let mut decoder = Decoder::new(bytes, payload_read_error);
    if decoder.array::<8>()? != *domain.fence_magic() || decoder.u16()? != FENCE_VERSION {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    let assignment = decode_assignment(&mut decoder)?;
    let node = NodeId::from_bytes(decoder.array::<16>()?);
    let plan_digest = ObjectDigest::from_bytes(decoder.array::<32>()?);
    let plan_expires_seconds = decoder.i64()?;
    let stable_key_id_length = decoder.u8()? as usize;
    if stable_key_id_length == 0 || stable_key_id_length > MAXIMUM_STABLE_KEY_ID_BYTES {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    let stable_key_id_text = std::str::from_utf8(decoder.bytes(stable_key_id_length)?)
        .map_err(|_| AuthorizationRecordError::InvalidPayload)?;
    let authority_generation = decoder.u64()?;
    let authority_public_key = ObjectDigest::from_bytes(decoder.array::<32>()?);
    let authority_usage = decode_key_usage(decoder.u8()?)?;
    let local_lease_record = decode_local_lease_record(decoder.bytes(LOCAL_LEASE_RECORD_BYTES)?)
        .map_err(|_| AuthorizationRecordError::InvalidPayload)?;
    decoder.finish()?;
    Ok(BorrowedFenceFieldsV1 {
        assignment,
        node,
        plan_digest,
        plan_expires_seconds,
        stable_key_id_text,
        authority_generation,
        authority_public_key,
        authority_usage,
        local_lease_record,
    })
}

pub(super) fn decode_effect_fields(
    bytes: &[u8],
    profile: EffectPayloadProfile,
) -> Result<BorrowedEffectFieldsV1<'_>, AuthorizationRecordError> {
    let magic = match profile {
        EffectPayloadProfile::Ordinary(domain) => domain.effect_magic(),
        EffectPayloadProfile::MountFuseIntent => fuse_intent::MAGIC,
    };
    let mut decoder = Decoder::new(bytes, payload_read_error);
    if decoder.array::<8>()? != *magic || decoder.u16()? != EFFECT_VERSION {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    let status = match decoder.u8()? {
        0 => BrokerEffectStatusV1::Pending,
        1 => BrokerEffectStatusV1::Complete,
        _ => return Err(AuthorizationRecordError::InvalidPayload),
    };
    let code = decoder.u8()?;
    let verb = match profile {
        EffectPayloadProfile::Ordinary(domain) => decode_verb(domain, code)?,
        EffectPayloadProfile::MountFuseIntent if code == 1 => {
            BrokerVerb::MountReserveFuseWorkerIntent
        }
        EffectPayloadProfile::MountFuseIntent => {
            return Err(AuthorizationRecordError::InvalidPayload);
        }
    };
    let target = decode_target(&mut decoder)?;
    let request_id = decoder.array::<16>()?;
    let transport_request_digest = ObjectDigest::from_bytes(decoder.array::<32>()?);
    let request_digest = ObjectDigest::from_bytes(decoder.array::<32>()?);
    let plan_digest = ObjectDigest::from_bytes(decoder.array::<32>()?);
    let lease_digest = ObjectDigest::from_bytes(decoder.array::<32>()?);
    let maximum_request_bytes = decoder.u32()?;
    let maximum_descriptors = decoder.u16()?;
    let plan_expires_seconds = decoder.i64()?;
    let authority_expires_seconds = decoder.i64()?;
    let host_boot_id = decoder.array::<16>()?;
    let fail_stop_boottime_nanoseconds = decoder.u64()?;
    let clock_provenance = decoder.array::<16>()?;
    let admitted_wall_seconds = decoder.i64()?;
    let admitted_boottime_nanoseconds = decoder.u64()?;
    let request_deadline_boottime_nanoseconds = decoder.u64()?;
    let effect_deadline_boottime_nanoseconds = decoder.u64()?;
    let local_lease_record = decode_local_lease_record(decoder.bytes(LOCAL_LEASE_RECORD_BYTES)?)
        .map_err(|_| AuthorizationRecordError::InvalidPayload)?;
    let receipt_length = decoder.u32()? as usize;
    if receipt_length > MAXIMUM_RECEIPT_BYTES {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    let receipt = decoder.bytes(receipt_length)?;
    decoder.finish()?;
    let intent = BrokerEffectIntentV1 {
        status,
        request_id,
        transport_request_digest,
        request_digest,
        plan_digest,
        lease_digest,
        verb,
        target,
        maximum_request_bytes,
        maximum_descriptors,
        plan_expires_seconds,
        authority_expires_seconds,
        host_boot_id,
        fail_stop_boottime_nanoseconds,
        clock_provenance,
        admitted_wall_seconds,
        admitted_boottime_nanoseconds,
        request_deadline_boottime_nanoseconds,
        effect_deadline_boottime_nanoseconds,
        local_lease_record,
        receipt: Vec::new(),
    };
    Ok(BorrowedEffectFieldsV1 {
        intent_without_receipt: intent,
        receipt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage_intent() -> BrokerEffectIntentV1 {
        let mut intent = super::super::tests::sample_intent();
        intent.verb = BrokerVerb::StoragePrepareCatalog;
        intent
    }

    fn storage_key() -> NodeJournalMacKey {
        NodeJournalMacKey::new(BrokerDomain::Storage, [61; 16], [62; 32]).unwrap()
    }

    #[test]
    fn exact_fence_comparison_borrows_the_maximum_key_text() {
        let key = storage_key();
        let intent = storage_intent();
        let expected = BrokerAuthorizationFenceV1::new(
            assignment_for_lease(&intent.local_lease_record),
            intent.local_lease_record.node(),
            intent.plan_digest,
            intent.plan_expires_seconds,
            KeyReference::new(
                StableKeyId::new("k".repeat(MAXIMUM_STABLE_KEY_ID_BYTES)).unwrap(),
                4,
                ObjectDigest::from_bytes([73; 32]),
                KeyUsage::OwnershipLease,
            ),
            intent.local_lease_record.clone(),
        )
        .unwrap();

        for namespace in [
            RecordNamespace::DesiredState,
            RecordNamespace::AuthorityPublication,
        ] {
            let encoded =
                seal_authorization_fence(&key, namespace, b"same-key", &expected).unwrap();
            let payload = open(
                &key,
                namespace,
                b"same-key",
                AuthenticatedValueKind::AuthorizationFence,
                &encoded,
            )
            .unwrap();
            let fields = decode_fence_fields(payload, BrokerDomain::Storage).unwrap();
            let key_text_start = fields.stable_key_id_text.as_ptr() as usize;
            assert!(
                (payload.as_ptr() as usize..payload.as_ptr() as usize + payload.len())
                    .contains(&key_text_start)
            );
            assert_eq!(fields.stable_key_id_text.len(), MAXIMUM_STABLE_KEY_ID_BYTES);

            assert!(
                require_exact_storage_prepare_fence(
                    &key,
                    namespace,
                    b"same-key",
                    &encoded,
                    &expected
                )
                .unwrap()
            );
            assert!(
                require_exact_storage_prepare_fence(
                    &key,
                    namespace,
                    b"moved-key",
                    &encoded,
                    &expected
                )
                .is_err()
            );
            let mut changed = expected.clone();
            changed.plan_expires_seconds -= 1;
            assert!(
                !require_exact_storage_prepare_fence(
                    &key,
                    namespace,
                    b"same-key",
                    &encoded,
                    &changed
                )
                .unwrap()
            );
            assert_eq!(
                open_authorization_fence(&key, namespace, b"same-key", &encoded).unwrap(),
                expected
            );
        }
    }

    fn assignment_for_lease(lease: &LocalLeaseRecord) -> BrokerAssignment {
        let assignment = lease.assignment();
        // The fence's Desired generation is independent of the lease assignment.
        BrokerAssignment::new(
            assignment.sandbox(),
            assignment.incarnation(),
            assignment.epoch(),
            DesiredGeneration::new(5),
            assignment.digest(),
        )
        .unwrap()
    }

    #[test]
    fn authenticated_completed_receipt_remains_borrowed_and_cannot_match_pending() {
        let key = storage_key();
        let pending = storage_intent();
        let completed = pending
            .clone()
            .complete(vec![37; MAXIMUM_RECEIPT_BYTES])
            .unwrap();
        let encoded = seal_effect_intent(
            &key,
            RecordNamespace::Effect,
            pending.request_id(),
            &completed,
        )
        .unwrap();
        let payload = open(
            &key,
            RecordNamespace::Effect,
            pending.request_id(),
            AuthenticatedValueKind::EffectIntent,
            &encoded,
        )
        .unwrap();

        let fields = decode_effect_fields(
            payload,
            EffectPayloadProfile::Ordinary(BrokerDomain::Storage),
        )
        .unwrap();
        eprintln!(
            "borrowed Storage comparison bytes: fence={}, effect={}; previous owned fence={}, effect={}",
            std::mem::size_of::<BorrowedFenceFieldsV1<'_>>(),
            std::mem::size_of::<BorrowedEffectFieldsV1<'_>>(),
            std::mem::size_of::<BrokerAuthorizationFenceV1>(),
            std::mem::size_of::<BrokerEffectIntentV1>(),
        );

        assert_eq!(fields.receipt.len(), MAXIMUM_RECEIPT_BYTES);
        assert_eq!(fields.intent_without_receipt.receipt.capacity(), 0);
        let receipt_start = fields.receipt.as_ptr() as usize;
        assert!(
            (payload.as_ptr() as usize..payload.as_ptr() as usize + payload.len())
                .contains(&receipt_start)
        );
        assert!(!fields.require_exact_pending(&pending).unwrap());
        assert!(
            !require_exact_storage_prepare_effect(&key, pending.request_id(), &encoded, &pending)
                .unwrap()
        );
        assert_eq!(
            open_effect_intent(
                &key,
                RecordNamespace::Effect,
                pending.request_id(),
                &encoded
            )
            .unwrap(),
            completed
        );
    }

    #[test]
    fn exact_pending_comparison_keeps_authentication_and_common_parser_refusals() {
        let key = storage_key();
        let expected = storage_intent();
        let encoded = seal_effect_intent(
            &key,
            RecordNamespace::Effect,
            expected.request_id(),
            &expected,
        )
        .unwrap();
        assert!(
            require_exact_storage_prepare_effect(&key, expected.request_id(), &encoded, &expected)
                .unwrap()
        );
        let mut different = expected.clone();
        different.maximum_request_bytes += 1;
        let different_bytes = seal_effect_intent(
            &key,
            RecordNamespace::Effect,
            different.request_id(),
            &different,
        )
        .unwrap();
        assert!(
            !require_exact_storage_prepare_effect(
                &key,
                expected.request_id(),
                &different_bytes,
                &expected
            )
            .unwrap()
        );
        assert!(
            require_exact_storage_prepare_effect(&key, &[99; 16], &encoded, &expected).is_err()
        );
        let mut tampered = encoded.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            require_exact_storage_prepare_effect(&key, expected.request_id(), &tampered, &expected)
                .is_err()
        );

        let original_payload = encode_effect(&expected, BrokerDomain::Storage).unwrap();
        for length in 0..original_payload.len() {
            let payload = &original_payload[..length];
            assert!(
                super::super::decode_effect_fields(
                    payload,
                    EffectPayloadProfile::Ordinary(BrokerDomain::Storage)
                )
                .is_err()
            );
            let encoded = seal(
                &key,
                RecordNamespace::Effect,
                expected.request_id(),
                AuthenticatedValueKind::EffectIntent,
                payload,
            )
            .unwrap();
            assert!(
                require_exact_storage_prepare_effect(
                    &key,
                    expected.request_id(),
                    &encoded,
                    &expected
                )
                .is_err()
            );
        }
        for (offset, replacement) in [(0, 0), (9, 2), (10, 3), (11, u8::MAX), (12, u8::MAX)] {
            let mut payload = original_payload.clone();
            payload[offset] = replacement;
            assert!(
                super::super::decode_effect_fields(
                    &payload,
                    EffectPayloadProfile::Ordinary(BrokerDomain::Storage)
                )
                .is_err()
            );
            let encoded = seal(
                &key,
                RecordNamespace::Effect,
                expected.request_id(),
                AuthenticatedValueKind::EffectIntent,
                &payload,
            )
            .unwrap();
            assert!(
                require_exact_storage_prepare_effect(
                    &key,
                    expected.request_id(),
                    &encoded,
                    &expected
                )
                .is_err()
            );
        }
    }
}
