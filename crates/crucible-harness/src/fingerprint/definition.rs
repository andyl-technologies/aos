//! Versioned execution-fingerprint definition.
//!
//! This module fixes the cadence and state set for the first Crucible execution
//! fingerprint. The definition digest is folded into every stream so two runs
//! cannot be compared under different sample positions or state coverage.

use super::hasher::FingerprintHasher;

/// The version tag folded into every execution-fingerprint definition digest.
pub const EXECUTION_FINGERPRINT_DEFINITION_VERSION: &str = "crucible-execution-fingerprint-v1";

/// The stable hash algorithm tag used by the fingerprint combiner.
pub const FINGERPRINT_HASH_ALGORITHM: &str = "crucible-stable-fingerprint-hash-v1";

/// The fixed canonical periodic sample interval in aggregate icount units.
pub const CANONICAL_FINGERPRINT_PERIOD_ICOUNT: u64 = 4096;

/// The register sub-digest algorithm expected from host observation.
pub const REGISTER_DIGEST_ALGORITHM: &str = "host-observed-architectural-register-digest-v1";

/// The memory sub-digest algorithm expected from host observation.
pub const MEMORY_DIGEST_ALGORITHM: &str = "host-observed-full-guest-memory-digest-v1";

/// The device-state sub-digest algorithm expected from host observation.
pub const DEVICE_DIGEST_ALGORITHM: &str = "host-observed-device-state-digest-v1";

/// A deterministic 256-bit digest represented as canonical bytes.
pub type FingerprintDigest = Vec<u8>;

/// The byte length of every execution-fingerprint digest.
pub const FINGERPRINT_DIGEST_BYTES: usize = 32;

/// The fixed icount-driven cadence for execution-fingerprint sampling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FingerprintCadence {
    period_icount: u64,
    sample_event_boundaries: bool,
}

impl FingerprintCadence {
    /// Builds the canonical Contract A cadence.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            period_icount: CANONICAL_FINGERPRINT_PERIOD_ICOUNT,
            sample_event_boundaries: true,
        }
    }

    /// Returns the fixed aggregate-icount sample period.
    #[must_use]
    pub fn period_icount(&self) -> u64 {
        self.period_icount
    }

    /// Returns whether deterministic event boundaries force extra samples.
    #[must_use]
    pub fn sample_event_boundaries(&self) -> bool {
        self.sample_event_boundaries
    }

    /// Returns true when `icount` falls on the periodic cadence.
    #[must_use]
    pub fn samples_periodic_icount(&self, icount: u64) -> bool {
        icount != 0 && icount.is_multiple_of(self.period_icount)
    }
}

/// The fixed memory state included in an execution fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryFingerprintScope {
    /// Hashes the full guest RAM image at the sample point.
    FullGuestMemory,
}

/// A deterministic event boundary that forces a fingerprint sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintEventBoundary {
    /// A scheduler horizon advanced.
    HorizonAdvance,
    /// An icount-stamped frame became visible.
    FrameDelivery,
    /// A scheduled signal effect boundary became visible.
    SignalEffectBoundary,
}

/// The reason one fingerprint sample is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintSampleTrigger {
    /// The sample is taken because the aggregate icount reached the period.
    Periodic,
    /// The sample is taken at a deterministic event boundary.
    Event(FingerprintEventBoundary),
}

/// The content-addressed execution-fingerprint definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintDefinition {
    cadence: FingerprintCadence,
    memory_scope: MemoryFingerprintScope,
    include_device_state: bool,
    include_rr_scheduler_state: bool,
}

impl FingerprintDefinition {
    /// Builds the fixed Contract A fingerprint definition.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            cadence: FingerprintCadence::canonical(),
            memory_scope: MemoryFingerprintScope::FullGuestMemory,
            include_device_state: true,
            include_rr_scheduler_state: true,
        }
    }

    /// Returns the fixed fingerprint-definition version tag.
    #[must_use]
    pub fn version(&self) -> &'static str {
        EXECUTION_FINGERPRINT_DEFINITION_VERSION
    }

    /// Returns the stable fingerprint hash algorithm tag.
    #[must_use]
    pub fn hash_algorithm(&self) -> &'static str {
        FINGERPRINT_HASH_ALGORITHM
    }

    /// Returns the expected register sub-digest algorithm tag.
    #[must_use]
    pub fn register_digest_algorithm(&self) -> &'static str {
        REGISTER_DIGEST_ALGORITHM
    }

    /// Returns the expected memory sub-digest algorithm tag.
    #[must_use]
    pub fn memory_digest_algorithm(&self) -> &'static str {
        MEMORY_DIGEST_ALGORITHM
    }

    /// Returns the expected device-state sub-digest algorithm tag.
    #[must_use]
    pub fn device_digest_algorithm(&self) -> &'static str {
        DEVICE_DIGEST_ALGORITHM
    }

    /// Returns the icount-driven sampling cadence.
    #[must_use]
    pub fn cadence(&self) -> FingerprintCadence {
        self.cadence
    }

    /// Returns the fixed memory state included in each sample.
    #[must_use]
    pub fn memory_scope(&self) -> MemoryFingerprintScope {
        self.memory_scope
    }

    /// Returns whether device state is included in each sample.
    #[must_use]
    pub fn include_device_state(&self) -> bool {
        self.include_device_state
    }

    /// Returns whether RR-scheduler state is included in each sample.
    #[must_use]
    pub fn include_rr_scheduler_state(&self) -> bool {
        self.include_rr_scheduler_state
    }

    /// Returns true when the sample trigger is valid at `icount`.
    #[must_use]
    pub fn accepts_sample(&self, icount: u64, trigger: FingerprintSampleTrigger) -> bool {
        match trigger {
            FingerprintSampleTrigger::Periodic => self.cadence.samples_periodic_icount(icount),
            FingerprintSampleTrigger::Event(event) => {
                self.cadence.sample_event_boundaries
                    && canonical_event_boundaries().contains(&event)
            }
        }
    }

    /// Computes the stable content digest for this definition.
    #[must_use]
    pub fn digest(&self) -> FingerprintDigest {
        let mut hasher = FingerprintHasher::new();
        hasher.write_tag("fingerprint-definition");
        hasher.write_bytes(self.version().as_bytes());
        hasher.write_bytes(self.hash_algorithm().as_bytes());
        hasher.write_bytes(self.register_digest_algorithm().as_bytes());
        hasher.write_bytes(self.memory_digest_algorithm().as_bytes());
        hasher.write_bytes(self.device_digest_algorithm().as_bytes());
        hasher.write_u64(FINGERPRINT_DIGEST_BYTES as u64);
        hasher.write_u64(self.cadence.period_icount);
        hasher.write_bool(self.cadence.sample_event_boundaries);
        write_event_boundary_set(&mut hasher);
        hasher.write_tag("full-guest-memory");
        hasher.write_bool(self.include_device_state);
        hasher.write_bool(self.include_rr_scheduler_state);
        hasher.finish()
    }
}

fn canonical_event_boundaries() -> [FingerprintEventBoundary; 3] {
    [
        FingerprintEventBoundary::HorizonAdvance,
        FingerprintEventBoundary::FrameDelivery,
        FingerprintEventBoundary::SignalEffectBoundary,
    ]
}

fn write_event_boundary_set(hasher: &mut FingerprintHasher) {
    let boundaries = canonical_event_boundaries();
    hasher.write_u64(boundaries.len() as u64);
    for boundary in boundaries {
        hasher.write_tag(match boundary {
            FingerprintEventBoundary::HorizonAdvance => "horizon-advance",
            FingerprintEventBoundary::FrameDelivery => "frame-delivery",
            FingerprintEventBoundary::SignalEffectBoundary => "signal-effect-boundary",
        });
    }
}
