//! Complete retained Attempt and Prepared history; no signed/current Native factories.

use aos_sandbox_model::ObjectDigest;

/// Owns a recorded packet, body, lease commitment and deadline as passive history.
#[derive(Clone, Eq, PartialEq)]
pub struct BrokerDispatchAttemptHistoryV1 {
    pub(super) template_digest: ObjectDigest,
    pub(super) lease_digest: ObjectDigest,
    pub(super) lease_generation: u64,
    pub(super) deadline_boottime_nanoseconds: u64,
    pub(super) body: Vec<u8>,
    pub(super) packet: Vec<u8>,
}

impl BrokerDispatchAttemptHistoryV1 {
    /// Returns the recorded template digest.
    #[must_use]
    pub const fn template_digest(&self) -> ObjectDigest {
        self.template_digest
    }

    /// Returns the recorded lease digest without verifying a signature.
    #[must_use]
    pub const fn lease_digest(&self) -> ObjectDigest {
        self.lease_digest
    }

    /// Returns the recorded lease generation.
    #[must_use]
    pub const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }

    /// Returns the recorded attempt-local BOOTTIME deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline_boottime_nanoseconds
    }

    /// Borrows the recorded body bytes without validating their deadline or fields.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Borrows recorded packet bytes without establishing transport eligibility.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Owns the supplied template, lease, deadline, body and packet fields.
    ///
    /// This performs no bounds, signature, field-coherence or currentness checks.
    pub fn from_durable_parts(
        template_digest: ObjectDigest,
        lease_digest: ObjectDigest,
        lease_generation: u64,
        deadline_boottime_nanoseconds: u64,
        body: Vec<u8>,
        packet: Vec<u8>,
    ) -> Self {
        Self {
            template_digest,
            lease_digest,
            lease_generation,
            deadline_boottime_nanoseconds,
            body,
            packet,
        }
    }
}

/// Owns retained dispatch commitments and preparation timing for an effect.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedAuthorityEffectHistoryV1 {
    pub(super) binding_digest: ObjectDigest,
    pub(super) publication_digest: ObjectDigest,
    pub(super) preparation_wall_seconds: i64,
    pub(super) preparation_boottime_nanoseconds: u64,
    pub(super) preparation_host_boot_id: [u8; 16],
    pub(super) attempt: BrokerDispatchAttemptHistoryV1,
}

impl PreparedAuthorityEffectHistoryV1 {
    /// Owns supplied binding, publication, preparation timing and attempt history.
    ///
    /// This does not establish a durable write, authenticate commitments or verify
    /// the preparation clock and attempt fields.
    pub const fn from_durable_parts(
        binding_digest: ObjectDigest,
        publication_digest: ObjectDigest,
        preparation_wall_seconds: i64,
        preparation_boottime_nanoseconds: u64,
        preparation_host_boot_id: [u8; 16],
        attempt: BrokerDispatchAttemptHistoryV1,
    ) -> Self {
        Self {
            binding_digest,
            publication_digest,
            preparation_wall_seconds,
            preparation_boottime_nanoseconds,
            preparation_host_boot_id,
            attempt,
        }
    }

    /// Returns the retained `binding_digest` DATA without a currentness claim.
    #[must_use]
    pub const fn binding_digest(&self) -> ObjectDigest {
        self.binding_digest
    }

    /// Returns the retained `publication_digest` DATA without a currentness claim.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.publication_digest
    }

    /// Returns the retained `preparation_wall_seconds` DATA without a currentness claim.
    #[must_use]
    pub const fn preparation_wall_seconds(&self) -> i64 {
        self.preparation_wall_seconds
    }

    /// Returns the retained `preparation_boottime_nanoseconds` DATA without a currentness claim.
    #[must_use]
    pub const fn preparation_boottime_nanoseconds(&self) -> u64 {
        self.preparation_boottime_nanoseconds
    }

    /// Returns the retained `preparation_host_boot_id` DATA without a currentness claim.
    #[must_use]
    pub const fn preparation_host_boot_id(&self) -> [u8; 16] {
        self.preparation_host_boot_id
    }

    /// Returns the retained `attempt` DATA without a currentness claim.
    #[must_use]
    pub const fn attempt(&self) -> &BrokerDispatchAttemptHistoryV1 {
        &self.attempt
    }
}

impl std::fmt::Debug for BrokerDispatchAttemptHistoryV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = formatter.debug_struct("BrokerDispatchAttemptV1");
        fields.field("template_digest", &self.template_digest);
        fields.field("lease_digest", &self.lease_digest);
        fields.field("lease_generation", &self.lease_generation);
        fields.field(
            "deadline_boottime_nanoseconds",
            &self.deadline_boottime_nanoseconds,
        );
        fields.field("body", &self.body);
        fields.field("packet", &self.packet);
        fields.finish()
    }
}

impl std::fmt::Debug for PreparedAuthorityEffectHistoryV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = formatter.debug_struct("PreparedAuthorityEffectV1");
        fields.field("binding_digest", &self.binding_digest);
        fields.field("publication_digest", &self.publication_digest);
        fields.field("preparation_wall_seconds", &self.preparation_wall_seconds);
        fields.field(
            "preparation_boottime_nanoseconds",
            &self.preparation_boottime_nanoseconds,
        );
        fields.field("preparation_host_boot_id", &self.preparation_host_boot_id);
        fields.field("attempt", &self.attempt);
        fields.finish()
    }
}
