//! Fixed source-issued closure receipts and exact acknowledgement correlation.
//!
//! These bytes describe the original native issuer's retained closure. Parsing
//! them cannot create a native permit, adopt a world, or arm a simulation node.
//! The issuer checks its actual source-owned objects and retains the complete
//! backend-qualified closure transcript before offering this receipt. The same
//! original actor retains the receipt, offered acknowledgement and byte-identical
//! consumed acknowledgement in its constructor-preallocated, nonrenewing slot.
//!
//! ```text
//! Receipt344: version/size:u32@0/4, scope32@8, epoch/process/barrier/cut:u64@40..64,
//! setup/profile/launch-or-implementation/queue-plan digests32@72/104/136/168,
//! clock88@200, closure digest32@288, object/edge counts:u64@320/328,
//! backend kind/closure codec version:u32@336/340.
//! ACK128: version/size:u32@0/4, scope32@8, epoch/cut:u64@40/48,
//! receipt digest32@56, queue-plan digest32@88, reserved-zero:u64@120.
//! Integers are big endian. Receipt digest: SHA256("CRUCIBLE-SOURCE-READY-V1\0" || body).
//! ```
//!
//! The profile digest uses the selected backend's actual profile codec and hash
//! domain. QEMU uses its public staged-profile digest; other implementations use
//! their own qualified profiles. The launch digest names the complete selected
//! launch or implementation descriptor. External implementations bind their
//! vendor identity and descriptor version there. Backend kind, closure codec
//! version, implementation/profile digests and closure digest together identify
//! the retained closure transcript grammar. Counts describe that transcript;
//! they confer no geometry permission or source ownership.

use crate::whole_control::{
    WHOLE_ACK_BYTES, WholeControlError, domain_digest, put_u32, put_u64, read_u32, read_u64,
};

/// Counts one complete fixed source-readiness receipt.
pub const SOURCE_READY_BYTES: usize = 344;
/// Counts the explicit clock observation within a source receipt.
pub const SOURCE_CLOCK_BYTES: usize = 88;

/// Identifies the implementation family whose native issuer owns the closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceBackend {
    /// Identifies a source-owned QEMU closure interpreter.
    Qemu,
    /// Identifies a source-owned gem5 closure interpreter.
    Gem5,
    /// Identifies a source-owned KVM closure interpreter.
    Kvm,
    /// Identifies an external vendor using an implementation-qualified descriptor.
    External,
}

impl SourceBackend {
    fn number(self) -> u32 {
        match self {
            Self::Qemu => 1,
            Self::Gem5 => 2,
            Self::Kvm => 3,
            Self::External => 4,
        }
    }

    fn decode(number: u32) -> Result<Self, WholeControlError> {
        match number {
            1 => Ok(Self::Qemu),
            2 => Ok(Self::Gem5),
            3 => Ok(Self::Kvm),
            4 => Ok(Self::External),
            _ => Err(WholeControlError::Body),
        }
    }
}

/// Identifies the issuer-qualified projection used for the observed native clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceClockMode {
    /// Describes a native counter with the issuer's retained bias projection.
    NativeBiased,
    /// Describes an issuer-owned parked affine projection.
    ParkedAffine,
    /// Describes another backend's independently checked observed clock.
    IndependentObserved,
}

impl SourceClockMode {
    fn number(self) -> u32 {
        match self {
            Self::NativeBiased => 0,
            Self::ParkedAffine => 2,
            Self::IndependentObserved => 3,
        }
    }

    fn decode(number: u32) -> Result<Self, WholeControlError> {
        match number {
            0 => Ok(Self::NativeBiased),
            2 => Ok(Self::ParkedAffine),
            3 => Ok(Self::IndependentObserved),
            _ => Err(WholeControlError::Body),
        }
    }
}

/// Retains explicit original clock facts without importing a native structure.
///
/// The native issuer validates its actual projection and current source cut.
/// This codec checks only supported tags and scalar shape; it does not derive
/// instructions from semantic time or assume a common slope across backends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceClockObservation {
    /// Retains the original native counter under the selected clock projection.
    /// Its units are defined by the retained backend-qualified profile codec.
    pub raw: u64,
    /// Retains the actual observed semantic timestamp in picoseconds.
    pub semantic_ps: u64,
    /// Retains the original simulator's semantic bias in picoseconds.
    pub sim_bias_ps: u64,
    /// Retains the native counter anchor for the selected projection.
    pub anchor_raw: u64,
    /// Retains the semantic anchor in picoseconds.
    pub anchor_ps: u64,
    /// Retains the projection's original parked semantic timestamp.
    pub park_ps: u64,
    /// Retains the backend-defined signed high bias half, zero when unused.
    pub bias_high: i64,
    /// Retains the backend-defined low bias half, zero when unused.
    pub bias_low: u64,
    /// Retains the original public logical-coordinate offset in picoseconds.
    pub logical_offset_ps: u64,
    /// Selects the issuer-qualified clock projection.
    pub mode: SourceClockMode,
    /// Retains the declared instruction slope, or zero for an independent clock.
    pub instruction_ps: u32,
    /// Retains the original native clock shift.
    pub time_shift: u32,
    /// Retains the picosecond-to-nanosecond divisor, exactly 1000.
    pub ns_divisor: u32,
}

impl SourceClockObservation {
    fn validate(&self) -> Result<(), WholeControlError> {
        if self.time_shift > 63
            || self.ns_divisor != 1000
            || (self.mode != SourceClockMode::IndependentObserved && self.instruction_ps == 0)
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }

    fn encode_into(&self, body: &mut [u8]) {
        for (offset, value) in [
            (0, self.raw),
            (8, self.semantic_ps),
            (16, self.sim_bias_ps),
            (24, self.anchor_raw),
            (32, self.anchor_ps),
            (40, self.park_ps),
            (48, self.bias_high as u64),
            (56, self.bias_low),
            (64, self.logical_offset_ps),
        ] {
            put_u64(body, offset, value);
        }
        put_u32(body, 72, self.mode.number());
        put_u32(body, 76, self.instruction_ps);
        put_u32(body, 80, self.time_shift);
        put_u32(body, 84, self.ns_divisor);
    }

    fn decode(body: &[u8]) -> Result<Self, WholeControlError> {
        let clock = Self {
            raw: read_u64(body, 0),
            semantic_ps: read_u64(body, 8),
            sim_bias_ps: read_u64(body, 16),
            anchor_raw: read_u64(body, 24),
            anchor_ps: read_u64(body, 32),
            park_ps: read_u64(body, 40),
            bias_high: read_u64(body, 48) as i64,
            bias_low: read_u64(body, 56),
            logical_offset_ps: read_u64(body, 64),
            mode: SourceClockMode::decode(read_u32(body, 72))?,
            instruction_ps: read_u32(body, 76),
            time_shift: read_u32(body, 80),
            ns_divisor: read_u32(body, 84),
        };
        clock.validate()?;
        Ok(clock)
    }
}

/// Binds a receipt to the complete originally selected native implementation.
///
/// This public correlation value supplies no authority. Its caller obtains the
/// expected values from the same retained constructor and authenticated native
/// source owner; it cannot replace that owner's closure permit or currentness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReadyBinding {
    /// Retains the original constructor scope.
    pub scope: [u8; 32],
    /// Retains the original native epoch.
    pub native_epoch: u64,
    /// Retains the original process generation.
    pub process_generation: u64,
    /// Retains the original barrier generation.
    pub barrier_generation: u64,
    /// Commits the complete original setup body with SHA-256.
    pub setup_digest: [u8; 32],
    /// Commits the actual backend-qualified selected profile.
    pub profile_digest: [u8; 32],
    /// Commits the complete original launch or implementation descriptor.
    pub launch_digest: [u8; 32],
    /// Commits the complete original source-issued queue plan.
    pub queue_plan_digest: [u8; 32],
    /// Identifies the actual native implementation family.
    pub backend: SourceBackend,
    /// Selects the backend/implementation-qualified closure transcript grammar.
    pub closure_codec_version: u32,
}

impl SourceReadyBinding {
    fn validate(&self) -> Result<(), WholeControlError> {
        if self.scope == [0; 32]
            || self.native_epoch == 0
            || self.process_generation == 0
            || self.barrier_generation == 0
            || self.setup_digest == [0; 32]
            || self.profile_digest == [0; 32]
            || self.launch_digest == [0; 32]
            || self.queue_plan_digest == [0; 32]
            || self.closure_codec_version == 0
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }
}

/// Describes one native-issued complete closure at its nonrenewing source cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReadyReceipt {
    /// Correlates the same original constructor and implementation.
    pub binding: SourceReadyBinding,
    /// Retains the source-issued original cut; it is never a caller-minted slot.
    pub source_cut: u64,
    /// Retains the original source-owned clock observation at that cut.
    pub clock: SourceClockObservation,
    /// Commits the complete retained backend-qualified native closure transcript.
    pub closure_digest: [u8; 32],
    /// Describes the actual retained closure's object census without authority.
    pub closure_object_count: u64,
    /// Describes the actual retained closure's edge census without authority.
    pub closure_edge_count: u64,
}

impl SourceReadyReceipt {
    /// Encodes the complete receipt into fixed portable bytes.
    ///
    /// # Errors
    /// Rejects absent original correlations, unsupported clock shape, an absent
    /// closure transcript, or a zero source cut or object census.
    pub fn encode(&self) -> Result<[u8; SOURCE_READY_BYTES], WholeControlError> {
        self.validate()?;
        let mut body = [0; SOURCE_READY_BYTES];
        put_u32(&mut body, 0, 1);
        put_u32(&mut body, 4, SOURCE_READY_BYTES as u32);
        body[8..40].copy_from_slice(&self.binding.scope);
        for (offset, value) in [
            (40, self.binding.native_epoch),
            (48, self.binding.process_generation),
            (56, self.binding.barrier_generation),
            (64, self.source_cut),
            (320, self.closure_object_count),
            (328, self.closure_edge_count),
        ] {
            put_u64(&mut body, offset, value);
        }
        for (offset, digest) in [
            (72, &self.binding.setup_digest),
            (104, &self.binding.profile_digest),
            (136, &self.binding.launch_digest),
            (168, &self.binding.queue_plan_digest),
            (288, &self.closure_digest),
        ] {
            body[offset..offset + 32].copy_from_slice(digest);
        }
        self.clock.encode_into(&mut body[200..288]);
        put_u32(&mut body, 336, self.binding.backend.number());
        put_u32(&mut body, 340, self.binding.closure_codec_version);
        Ok(body)
    }

    /// Decodes one complete retained source receipt without granting readiness.
    ///
    /// # Errors
    /// Rejects malformed lengths, versions, absent correlations and unsupported
    /// clock or implementation tags before returning any interpreted receipt.
    pub fn decode(body: &[u8]) -> Result<Self, WholeControlError> {
        if body.len() != SOURCE_READY_BYTES
            || read_u32(body, 0) != 1
            || read_u32(body, 4) as usize != SOURCE_READY_BYTES
        {
            return Err(WholeControlError::Body);
        }
        let receipt = Self {
            binding: SourceReadyBinding {
                scope: array32(body, 8),
                native_epoch: read_u64(body, 40),
                process_generation: read_u64(body, 48),
                barrier_generation: read_u64(body, 56),
                setup_digest: array32(body, 72),
                profile_digest: array32(body, 104),
                launch_digest: array32(body, 136),
                queue_plan_digest: array32(body, 168),
                backend: SourceBackend::decode(read_u32(body, 336))?,
                closure_codec_version: read_u32(body, 340),
            },
            source_cut: read_u64(body, 64),
            clock: SourceClockObservation::decode(&body[200..288])?,
            closure_digest: array32(body, 288),
            closure_object_count: read_u64(body, 320),
            closure_edge_count: read_u64(body, 328),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Hashes every original receipt byte under the public readiness domain.
    ///
    /// # Errors
    /// Rejects invalid receipt shape before computing its digest.
    pub fn digest(&self) -> Result<[u8; 32], WholeControlError> {
        Ok(domain_digest(
            b"CRUCIBLE-SOURCE-READY-V1\0",
            &self.encode()?,
        ))
    }

    /// Checks the complete original immutable constructor and backend binding.
    ///
    /// This check does not validate native currentness, clock projection or the
    /// closure transcript. The original issuer owns those checks and its permit.
    ///
    /// # Errors
    /// Rejects malformed or changed constructor, implementation or codec values.
    pub fn validate_against(&self, binding: &SourceReadyBinding) -> Result<(), WholeControlError> {
        self.validate()?;
        binding.validate()?;
        if &self.binding != binding {
            return Err(WholeControlError::Correlation);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), WholeControlError> {
        self.binding.validate()?;
        self.clock.validate()?;
        if self.source_cut == 0 || self.closure_digest == [0; 32] || self.closure_object_count == 0
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }
}

/// Correlates the exact native-issued receipt and its original source cut.
///
/// The consumed acknowledgement uses these same 128 bytes in a distinct frame
/// kind. Only the original native issuer can consume it against its retained
/// receipt and current cut; equality cannot substitute for that native action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceReadyAcknowledgement {
    /// Retains the same original constructor scope.
    pub scope: [u8; 32],
    /// Retains the same original native epoch.
    pub native_epoch: u64,
    /// Retains the exact native-issued source cut.
    pub source_cut: u64,
    /// Commits every byte of the retained original receipt.
    pub receipt_digest: [u8; 32],
    /// Commits the same original source-issued queue plan.
    pub queue_plan_digest: [u8; 32],
}

impl SourceReadyAcknowledgement {
    /// Builds correlation bytes for one complete native-issued receipt.
    ///
    /// # Errors
    /// Rejects malformed receipt shape. No source permit is created.
    pub fn for_receipt(receipt: &SourceReadyReceipt) -> Result<Self, WholeControlError> {
        Ok(Self {
            scope: receipt.binding.scope,
            native_epoch: receipt.binding.native_epoch,
            source_cut: receipt.source_cut,
            receipt_digest: receipt.digest()?,
            queue_plan_digest: receipt.binding.queue_plan_digest,
        })
    }

    /// Encodes the complete acknowledgement into explicit fixed bytes.
    ///
    /// # Errors
    /// Rejects absent original receipt correlations.
    pub fn encode(&self) -> Result<[u8; WHOLE_ACK_BYTES], WholeControlError> {
        self.validate()?;
        let mut body = [0; WHOLE_ACK_BYTES];
        put_u32(&mut body, 0, 1);
        put_u32(&mut body, 4, WHOLE_ACK_BYTES as u32);
        body[8..40].copy_from_slice(&self.scope);
        put_u64(&mut body, 40, self.native_epoch);
        put_u64(&mut body, 48, self.source_cut);
        body[56..88].copy_from_slice(&self.receipt_digest);
        body[88..120].copy_from_slice(&self.queue_plan_digest);
        Ok(body)
    }

    /// Decodes one complete acknowledgement without a consumed-state transition.
    ///
    /// # Errors
    /// Rejects malformed lengths, versions, reserved bytes and correlations.
    pub fn decode(body: &[u8]) -> Result<Self, WholeControlError> {
        if body.len() != WHOLE_ACK_BYTES
            || read_u32(body, 0) != 1
            || read_u32(body, 4) as usize != WHOLE_ACK_BYTES
            || read_u64(body, 120) != 0
        {
            return Err(WholeControlError::Body);
        }
        let acknowledgement = Self {
            scope: array32(body, 8),
            native_epoch: read_u64(body, 40),
            source_cut: read_u64(body, 48),
            receipt_digest: array32(body, 56),
            queue_plan_digest: array32(body, 88),
        };
        acknowledgement.validate()?;
        Ok(acknowledgement)
    }

    /// Checks every original acknowledgement byte against the retained receipt.
    ///
    /// # Errors
    /// Rejects changed scope, epoch, cut, receipt bytes or queue-plan correlation.
    pub fn validate_against(&self, receipt: &SourceReadyReceipt) -> Result<(), WholeControlError> {
        if self != &Self::for_receipt(receipt)? {
            return Err(WholeControlError::Correlation);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), WholeControlError> {
        if self.scope == [0; 32]
            || self.native_epoch == 0
            || self.source_cut == 0
            || self.receipt_digest == [0; 32]
            || self.queue_plan_digest == [0; 32]
        {
            return Err(WholeControlError::Body);
        }
        Ok(())
    }
}

fn array32(body: &[u8], offset: usize) -> [u8; 32] {
    let mut value = [0; 32];
    value.copy_from_slice(&body[offset..offset + 32]);
    value
}

#[cfg(test)]
#[path = "source_ready_tests.rs"]
mod tests;
