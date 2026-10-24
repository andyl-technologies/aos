//! Shares the immutable issuance DATA grammar and exact claims comparison.
//!
//! Decoded metadata records historical observations only. It never creates a
//! current holder, session, clock, publication pin or capability authority.
//!
//! ```text
//! issuance: {decision_id, session_id, boot_id, clock_provenance,
//!            observed_wall_seconds, observed_boottime_nanoseconds,
//!            policy_generation, controller_generation, cache_resource,
//!            isolation_policy}
//! ```

/// Defines the same private issuance schema and comparison bodies.
#[macro_export]
macro_rules! define_provider_issuance_data_recipe_v1 {
    (invalid_metadata: $invalid_metadata:expr, crosslink: $crosslink:expr,
     malformed: $malformed:expr) => {
        const CLAIMS_DIGEST_DOMAIN: &[u8] = b"aos.sandbox.publisher-capability-claims.v1\0";

        /// Records the controller-observed facts behind one local capability issuance.
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(deny_unknown_fields)]
        pub struct IssuanceDecisionMetadataV1 {
            decision_id: AuditId,
            session_id: [u8; 16],
            boot_id: [u8; 16],
            clock_provenance: [u8; 16],
            observed_wall_seconds: i64,
            observed_boottime_nanoseconds: u64,
            policy_generation: u64,
            controller_generation: u64,
            cache_resource: ResourceId,
            isolation_policy: ObjectDigest,
        }

        impl IssuanceDecisionMetadataV1 {
            /// Returns the boot identity paired with the clock observation.
            #[must_use]
            pub const fn boot_id(&self) -> [u8; 16] {
                self.boot_id
            }

            /// Returns the protected clock-reader configuration identity.
            #[must_use]
            pub const fn clock_provenance(&self) -> [u8; 16] {
                self.clock_provenance
            }

            /// Returns the observed Unix wall-clock second.
            #[must_use]
            pub const fn observed_wall_seconds(&self) -> i64 {
                self.observed_wall_seconds
            }

            /// Returns the paired `CLOCK_BOOTTIME` nanoseconds.
            #[must_use]
            pub const fn observed_boottime_nanoseconds(&self) -> u64 {
                self.observed_boottime_nanoseconds
            }

            pub(super) fn validate_for(
                &self,
                capability: &CapabilityRecord,
            ) -> Result<ObjectDigest, PublisherAuthorityError> {
                self.validate_fields()?;
                let claims = capability.claims();
                let expected_operations = OperationSet::one(Operation::Publish);
                let runtime_bound = claims
                    .sandbox
                    .is_some_and(|sandbox| sandbox.as_bytes() != &[0; 16])
                    && claims
                        .incarnation
                        .is_some_and(|incarnation| incarnation.as_bytes() != &[0; 16])
                    && claims
                        .assignment_epoch
                        .is_some_and(|epoch| epoch.get() != 0);
                let delegation_disabled = claims.delegation.remaining_depth() == 0
                    && claims.delegation.maximum_fanout() == 0
                    && claims.delegation.resources() == ResourceVector::ZERO;
                let claim_sentinels_absent = claims.issuer.as_bytes() != &[0; 16]
                    && claims.holder.as_bytes() != &[0; 16]
                    && claims.channel_binding.as_bytes() != &[0; 32]
                    && claims.project.as_bytes() != &[0; 16]
                    && claims.policy_digest.as_bytes() != &[0; 32]
                    && claims.revocation_scope.as_bytes() != &[0; 16]
                    && claims.revocation_generation.get() != 0;
                let grant_matches = claims.grants.len() == 1
                    && claims.grants[0].id().as_bytes() != &[0; 16]
                    && claims.grants[0].resource_kind() == ResourceKind::CachePublish
                    && claims.grants[0].operations() == expected_operations
                    && claims.grants[0].selector()
                        == &Selector::Resource {
                            resource: self.cache_resource,
                        }
                    && !claims.grants[0].delegable();
                if self.decision_id.as_bytes() != capability.id().as_bytes()
                    || claims.parent_decision != self.decision_id
                    || claims.issuer != claims.audience
                    || claims.root_subject != claims.holder
                    || self.observed_wall_seconds < claims.not_before
                    || self.observed_wall_seconds >= claims.expires_at
                    || !runtime_bound
                    || !delegation_disabled
                    || !claim_sentinels_absent
                    || !grant_matches
                {
                    return Err($crosslink);
                }
                capability_claims_digest(capability)
            }

            fn validate_fields(&self) -> Result<(), PublisherAuthorityError> {
                if self.decision_id.as_bytes() == &[0; 16]
                    || self.session_id == [0; 16]
                    || self.boot_id == [0; 16]
                    || self.clock_provenance == [0; 16]
                    || self.policy_generation == 0
                    || self.controller_generation == 0
                    || self.cache_resource.as_bytes() == &[0; 16]
                    || self.isolation_policy.as_bytes() == &[0; 32]
                {
                    return Err($invalid_metadata);
                }
                Ok(())
            }
        }

        pub(super) fn capability_claims_digest(
            capability: &CapabilityRecord,
        ) -> Result<ObjectDigest, PublisherAuthorityError> {
            let mut writer = ClaimsDigestWriter::new(MAXIMUM_RECORD_BYTES);
            serde_json::to_writer(&mut writer, capability)
                .map_err(|_| $malformed)?;
            Ok(ObjectDigest::from_bytes(writer.finish()))
        }

        struct ClaimsDigestWriter {
            digest: Sha256,
            bytes: usize,
            maximum_bytes: usize,
        }

        impl ClaimsDigestWriter {
            fn new(maximum_bytes: usize) -> Self {
                let mut digest = Sha256::new();
                digest.update(CLAIMS_DIGEST_DOMAIN);
                Self {
                    digest,
                    bytes: 0,
                    maximum_bytes,
                }
            }

            fn finish(self) -> [u8; 32] {
                self.digest.finalize().into()
            }
        }

        impl io::Write for ClaimsDigestWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let next = self
                    .bytes
                    .checked_add(bytes.len())
                    .ok_or_else(|| io::Error::other("capability claims exceed digest bound"))?;
                if next > self.maximum_bytes {
                    return Err(io::Error::other("capability claims exceed digest bound"));
                }
                self.digest.update(bytes);
                self.bytes = next;
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
    };
}
