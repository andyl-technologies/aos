//! Shares the canonical durable capability JSON and initial-read comparison.
//!
//! The concrete Domain registry retains every native writer, entitlement,
//! runtime provenance, live holder and mutation check. This codec and historical
//! comparison do not admit a capability or supply a signer/currentness grant.
//!
//! ```text
//! {version:1|2|3,state:0|1,capability:{...},issuance:null|{...},
//!  claims_digest:null|[32],runtime:null|{...},parent?:[16],handle?:[32]}
//! ```

/// Defines the existing private record codec with its concrete error binding.
#[macro_export]
macro_rules! define_provider_capability_record_data_recipe_v1 {
    (malformed: $malformed:expr, invalid_parent: $invalid_parent:expr,
     invalid_handle: $invalid_handle:expr, key_mismatch: $key_mismatch:expr,
     crosslink: $crosslink:expr, unsupported: $unsupported:path, limit: $limit:path) => {
        const RECORD_VERSION_V1: u16 = 1;
        const RECORD_VERSION_V2: u16 = 2;
        const RECORD_VERSION_V3: u16 = 3;
        const RECORD_FAMILY: &[u8] = b"capability/";
        const RECORD_KEY_BYTES: usize = RECORD_FAMILY.len() + 16;
        const MAXIMUM_RECORD_BYTES: usize = 16 * 1024 * 1024;
        
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum DurableCapabilityStateV1 {
            Active,
            Revoked,
        }
        
        #[derive(Debug, Deserialize, Eq, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct DurableCapabilityRecordWireV1 {
            version: u16,
            state: u8,
            capability: CapabilityRecord,
            issuance: Option<IssuanceDecisionMetadataV1>,
            claims_digest: Option<aos_sandbox_core::ObjectDigest>,
            runtime: Option<RuntimeIssuanceEvidenceV1>,
            #[serde(default)]
            parent: Option<CapabilityId>,
            #[serde(default)]
            handle: Option<[u8; 32]>,
        }
        
        struct DecodedCapabilityRecordV1 {
            state: DurableCapabilityStateV1,
            capability: CapabilityRecord,
            issuance: Option<(IssuanceDecisionMetadataV1, aos_sandbox_core::ObjectDigest)>,
            runtime: Option<RuntimeIssuanceEvidenceV1>,
            parent: Option<CapabilityId>,
            handle: Option<[u8; 32]>,
        }
        
        #[derive(Serialize)]
        #[serde(deny_unknown_fields)]
        struct DurableCapabilityRecordRefV1<'a> {
            version: u16,
            state: u8,
            capability: &'a CapabilityRecord,
            issuance: Option<&'a IssuanceDecisionMetadataV1>,
            claims_digest: Option<aos_sandbox_core::ObjectDigest>,
            runtime: Option<&'a RuntimeIssuanceEvidenceV1>,
            #[serde(skip_serializing_if = "Option::is_none")]
            parent: Option<CapabilityId>,
            #[serde(skip_serializing_if = "Option::is_none")]
            handle: Option<[u8; 32]>,
        }
        
        fn capability_key(id: CapabilityId) -> [u8; RECORD_KEY_BYTES] {
            let mut key = [0_u8; RECORD_KEY_BYTES];
            key[..RECORD_FAMILY.len()].copy_from_slice(RECORD_FAMILY);
            key[RECORD_FAMILY.len()..].copy_from_slice(id.as_bytes());
            key
        }
        
        fn capability_id_from_key(key: &[u8]) -> Result<CapabilityId, PublisherAuthorityError> {
            if key.len() != RECORD_KEY_BYTES || !key.starts_with(RECORD_FAMILY) {
                return Err($malformed);
            }
            let mut bytes = [0_u8; 16];
            bytes.copy_from_slice(&key[RECORD_FAMILY.len()..]);
            if bytes == [0; 16] {
                return Err($malformed);
            }
            Ok(CapabilityId::from_bytes(bytes))
        }
        
        fn decode_record(
            key: &[u8],
            bytes: &[u8],
            maximum_bytes: usize,
        ) -> Result<DecodedCapabilityRecordV1, PublisherAuthorityError> {
            let key_id = capability_id_from_key(key)?;
            if bytes.len() > maximum_bytes {
                return Err($limit("record bytes"));
            }
            let decoded: DurableCapabilityRecordWireV1 =
                serde_json::from_slice(bytes).map_err(|_| $malformed)?;
            if !matches!(
                decoded.version,
                RECORD_VERSION_V1 | RECORD_VERSION_V2 | RECORD_VERSION_V3
            ) {
                return Err($unsupported(decoded.version));
            }
            if (decoded.version == RECORD_VERSION_V1 && decoded.parent.is_some())
                || (decoded.version == RECORD_VERSION_V2 && decoded.parent.is_none())
            {
                return Err($invalid_parent);
            }
            if (decoded.version == RECORD_VERSION_V3) != decoded.handle.is_some()
                || decoded.handle == Some([0; 32])
            {
                return Err($invalid_handle);
            }
            let state = match decoded.state {
                0 => DurableCapabilityStateV1::Active,
                1 => DurableCapabilityStateV1::Revoked,
                _ => return Err($malformed),
            };
            if decoded.capability.id() != key_id {
                return Err($key_mismatch);
            }
            let issuance = match (decoded.issuance, decoded.claims_digest) {
                (None, None) => None,
                (Some(metadata), Some(claims_digest)) => {
                    if metadata.validate_for(&decoded.capability)? != claims_digest {
                        return Err($crosslink);
                    }
                    Some((metadata, claims_digest))
                }
                _ => return Err($crosslink),
            };
            if let Some(runtime) = decoded.runtime.as_ref() {
                let (metadata, _) = issuance
                    .as_ref()
                    .ok_or($crosslink)?;
                runtime.validate_for(metadata)?;
            }
            let canonical = encode_record(
                state,
                &decoded.capability,
                issuance.as_ref(),
                decoded.runtime.as_ref(),
                decoded.parent,
                decoded.handle,
                maximum_bytes,
            )?;
            if canonical != bytes {
                return Err($malformed);
            }
            Ok(DecodedCapabilityRecordV1 {
                state,
                capability: decoded.capability,
                issuance,
                runtime: decoded.runtime,
                parent: decoded.parent,
                handle: decoded.handle,
            })
        }
        
        // Closed canonical DATA projection for the enrolled initial-read recipe.
        // Signed entitlement and live holder/current policy checks remain at issuance.
        pub(crate) fn decode_git_coverage_initial_content_read_v1(
            key: &[u8],
            bytes: &[u8],
        ) -> Result<(CapabilityRecord, [u8; 32]), PublisherAuthorityError> {
            use aos_sandbox_core::{Operation, OperationSet, ResourceKind, Selector};
        
            let decoded = decode_record(
                key, bytes, MAXIMUM_RECORD_BYTES,
            )?;
            if decoded.state != DurableCapabilityStateV1::Active
                || decoded.parent.is_some()
                || decoded.issuance.is_some()
                || decoded.runtime.is_some()
                || decoded.capability.claims().grants.is_empty()
                || decoded.capability.claims().grants.iter().any(|grant| {
                    grant.resource_kind() != ResourceKind::GitObjectDatabase
                        || grant.operations() != OperationSet::one(Operation::ContentRead)
                        || !matches!(grant.selector(), Selector::Resource { resource }
                            if resource.as_bytes() != &[0; 16])
                })
            {
                return Err($malformed);
            }
            let handle = decoded.handle.ok_or($invalid_handle)?;
            Ok((decoded.capability, handle))
        }
        
        fn encode_record(
            state: DurableCapabilityStateV1,
            capability: &CapabilityRecord,
            issuance: Option<&(IssuanceDecisionMetadataV1, aos_sandbox_core::ObjectDigest)>,
            runtime: Option<&RuntimeIssuanceEvidenceV1>,
            parent: Option<CapabilityId>,
            handle: Option<[u8; 32]>,
            maximum_bytes: usize,
        ) -> Result<Vec<u8>, PublisherAuthorityError> {
            if runtime.is_some() && issuance.is_none() {
                return Err($crosslink);
            }
            let (metadata, claims_digest) = issuance
                .map(|(metadata, claims_digest)| (Some(metadata), Some(*claims_digest)))
                .unwrap_or((None, None));
            let record = DurableCapabilityRecordRefV1 {
                version: if handle.is_some() {
                    RECORD_VERSION_V3
                } else if parent.is_some() {
                    RECORD_VERSION_V2
                } else {
                    RECORD_VERSION_V1
                },
                state: state.wire_value(),
                capability,
                issuance: metadata,
                claims_digest,
                runtime,
                parent,
                handle,
            };
            let mut writer = BoundedWriter::new(maximum_bytes);
            if serde_json::to_writer(&mut writer, &record).is_err() {
                return if writer.exceeded {
                    Err($limit("record bytes"))
                } else {
                    Err($malformed)
                };
            }
            Ok(writer.bytes)
        }
        
        impl DurableCapabilityStateV1 {
            const fn wire_value(self) -> u8 {
                match self {
                    Self::Active => 0,
                    Self::Revoked => 1,
                }
            }
        }
        
        struct BoundedWriter {
            bytes: Vec<u8>,
            maximum_bytes: usize,
            exceeded: bool,
        }
        
        impl BoundedWriter {
            fn new(maximum_bytes: usize) -> Self {
                Self {
                    bytes: Vec::with_capacity(maximum_bytes.min(8 * 1024)),
                    maximum_bytes,
                    exceeded: false,
                }
            }
        }
        
        impl io::Write for BoundedWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                append_with_capped_doubling(&mut self.bytes, bytes, self.maximum_bytes).map_err(|error| {
                    match error {
                        BoundedAppendError::LimitExceeded => {
                            self.exceeded = true;
                            io::Error::other("publisher authority record is too large")
                        }
                        BoundedAppendError::Allocation(error) => io::Error::other(error),
                    }
                })
            }
        
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        
    };
}
