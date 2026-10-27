//! Shape-only authorization and accepted-frontier snapshots.

use super::*;

/// Exact bytes in the atomic authorization table.
pub const NATIVE_CONSOLE_AUTHORIZATION_BYTES: usize = 128;
/// Exact bytes appended to the future coordinated node slot.
pub const NATIVE_CONSOLE_FRONTIER_BYTES: usize = 128;

/// Original phase authorization, without proof of that phase's authority.
///
/// The adapter must authenticate `phase_token` against the existing grant,
/// setup, restore or idle-service owner. Decoding or incrementing an incarnation
/// cannot establish that authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeConsoleAuthorization {
    /// Even, nonzero publication generation of this table snapshot.
    pub publication: u64,
    /// Physical authentication tuple.
    pub owner: NativeConsoleOwner,
    /// Checkpointed canonical console generation, separate from restore ACKs.
    pub logical_generation: u64,
    /// Original authorized advance publication; distinct from later clamps.
    pub advance: u64,
    /// Last accepted cumulative node sequence, already drained.
    pub prior_sequence: u64,
    /// Physical ring cursor through that last accepted prefix.
    pub prior_ring_end: u64,
    /// Fixed positive allowance; consumer reads cannot replenish it.
    pub allowance: u32,
    /// Original phase transaction token, interpreted only by its actual owner.
    pub phase_token: u64,
    /// Closed original phase label.
    pub phase: NativeConsolePhase,
}

impl NativeConsoleAuthorization {
    /// Encodes a shape-valid original authorization snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for an unpublished/odd generation, absent
    /// owner, an odd advance publication or a zero/out-of-capacity allowance.
    pub fn encode(self) -> Result<[u8; NATIVE_CONSOLE_AUTHORIZATION_BYTES], NativeConsoleError> {
        self.owner.validate()?;
        if self.publication == 0
            || self.publication & 1 != 0
            || self.advance & 1 != 0
            || self.allowance == 0
            || self.allowance > NATIVE_CONSOLE_CAPACITY
        {
            return Err(NativeConsoleError::Field);
        }
        let mut out = [0; NATIVE_CONSOLE_AUTHORIZATION_BYTES];
        put64(&mut out, 0, self.publication);
        out[8..24].copy_from_slice(&self.owner.region);
        for (at, value) in [
            (24, self.owner.process),
            (32, self.owner.authorization),
            (40, self.logical_generation),
            (48, self.advance),
            (56, self.prior_sequence),
            (64, self.prior_ring_end),
            (80, self.phase_token),
        ] {
            put64(&mut out, at, value);
        }
        put32(&mut out, 72, self.allowance);
        put32(&mut out, 76, self.owner.slot);
        out[88] = self.phase as u8;
        Ok(out)
    }

    /// Decodes one stable authorization snapshot, without phase authentication.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for malformed lengths, reserved bytes,
    /// generations, ownership or allowance fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeConsoleError> {
        exact(bytes, NATIVE_CONSOLE_AUTHORIZATION_BYTES)?;
        if bytes[89..].iter().any(|value| *value != 0) {
            return Err(NativeConsoleError::Framing);
        }
        let mut region = [0; 16];
        region.copy_from_slice(&bytes[8..24]);
        let value = Self {
            publication: get64(bytes, 0),
            owner: NativeConsoleOwner {
                slot: get32(bytes, 76),
                region,
                process: get64(bytes, 24),
                authorization: get64(bytes, 32),
            },
            logical_generation: get64(bytes, 40),
            advance: get64(bytes, 48),
            prior_sequence: get64(bytes, 56),
            prior_ring_end: get64(bytes, 64),
            allowance: get32(bytes, 72),
            phase_token: get64(bytes, 80),
            phase: bytes[88].try_into()?,
        };
        value.encode()?;
        Ok(value)
    }
}

/// A completed-boundary frontier that must be joined to the original odd ACK.
///
/// This value is only a codec snapshot. The later host adapter must authenticate
/// the existing backing, discovery, capture, command frontier and even request
/// through the original completed-boundary acceptance path before consuming it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeConsoleFrontier {
    /// Cumulative sealed node sequence; zero is valid before any output.
    pub sequence: u64,
    /// Exact physical ring end through the accepted prefix.
    pub ring_end: u64,
    /// Accepted boundary logical picoseconds.
    pub logical_ps: u64,
    /// Accepted boundary raw executed prefix.
    pub raw_prefix: u64,
    /// Physical authentication tuple.
    pub owner: NativeConsoleOwner,
    /// Accepted clamp's advance snapshot, not the emission authorization's.
    pub accepted_advance: u64,
    /// Checkpointed canonical console generation, separate from restore ACKs.
    pub logical_generation: u64,
    /// Original even control request; zero is valid after wrap.
    pub request: u32,
    /// Full transport plan hash, including its admitted physical slot.
    pub plan_hash: [u8; 32],
}

impl NativeConsoleFrontier {
    /// Encodes the exact sealed frontier shape, without forging an ACK.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for absent owner/hash, an odd request
    /// or an odd in-progress accepted advance publication.
    pub fn encode(self) -> Result<[u8; NATIVE_CONSOLE_FRONTIER_BYTES], NativeConsoleError> {
        self.owner.validate()?;
        if self.request & 1 != 0 || self.accepted_advance & 1 != 0 || self.plan_hash == [0; 32] {
            return Err(NativeConsoleError::Field);
        }
        let mut out = [0; NATIVE_CONSOLE_FRONTIER_BYTES];
        for (at, value) in [
            (0, self.sequence),
            (8, self.ring_end),
            (16, self.logical_ps),
            (24, self.raw_prefix),
            (32, self.owner.authorization),
            (40, self.accepted_advance),
            (48, self.logical_generation),
            (56, self.owner.process),
        ] {
            put64(&mut out, at, value);
        }
        out[64..80].copy_from_slice(&self.owner.region);
        put32(&mut out, 80, self.owner.slot);
        put32(&mut out, 84, self.request);
        out[88..120].copy_from_slice(&self.plan_hash);
        put32(&mut out, 120, 1);
        Ok(out)
    }

    /// Decodes an exact sealed frontier shape, rejecting unpublished values.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for malformed lengths, reserved bytes,
    /// seal flag, request or owner fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeConsoleError> {
        exact(bytes, NATIVE_CONSOLE_FRONTIER_BYTES)?;
        if get32(bytes, 120) != 1 || bytes[124..].iter().any(|value| *value != 0) {
            return Err(NativeConsoleError::Framing);
        }
        let mut region = [0; 16];
        region.copy_from_slice(&bytes[64..80]);
        let mut plan_hash = [0; 32];
        plan_hash.copy_from_slice(&bytes[88..120]);
        let value = Self {
            sequence: get64(bytes, 0),
            ring_end: get64(bytes, 8),
            logical_ps: get64(bytes, 16),
            raw_prefix: get64(bytes, 24),
            owner: NativeConsoleOwner {
                slot: get32(bytes, 80),
                region,
                process: get64(bytes, 56),
                authorization: get64(bytes, 32),
            },
            accepted_advance: get64(bytes, 40),
            logical_generation: get64(bytes, 48),
            request: get32(bytes, 84),
            plan_hash,
        };
        value.encode()?;
        Ok(value)
    }
}

/// Private per-binding allowance state, independent of host drain timing.
///
/// It receives only already-authenticated authorizations from an adapter. The
/// ledger does not prove that a larger incarnation is a genuine new grant.
#[derive(Clone, Debug, Default)]
pub struct NativeConsoleAllowance {
    authorization: Option<NativeConsoleAuthorization>,
    remaining: u32,
    sequence: u64,
}

impl NativeConsoleAllowance {
    /// Admits or reobserves an already-authenticated authorization.
    ///
    /// Same-incarnation reobservation is idempotent and cannot refill bytes;
    /// its entire original body must match, excluding seqlock generation.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for malformed authorization, changed or
    /// older incarnations, physical rebind without a fresh ledger, or a new
    /// grant whose prior accepted/drained sequence is not the current sequence.
    pub fn observe(
        &mut self,
        authorization: NativeConsoleAuthorization,
        accepted_sequence: u64,
        drained_ring_end: u64,
    ) -> Result<(), NativeConsoleError> {
        authorization.encode()?;
        if let Some(previous) = self.authorization {
            if authorization.owner.authorization == previous.owner.authorization {
                let same = NativeConsoleAuthorization {
                    publication: previous.publication,
                    ..authorization
                };
                return if same == previous {
                    Ok(())
                } else {
                    Err(NativeConsoleError::Binding)
                };
            }
            if authorization.owner.authorization < previous.owner.authorization
                || authorization.owner.slot != previous.owner.slot
                || authorization.owner.region != previous.owner.region
                || authorization.owner.process != previous.owner.process
                || authorization.logical_generation != previous.logical_generation
            {
                return Err(NativeConsoleError::Binding);
            }
            if accepted_sequence != self.sequence {
                return Err(NativeConsoleError::Sequence);
            }
        }
        if authorization.prior_sequence != accepted_sequence
            || authorization.prior_ring_end != drained_ring_end
        {
            return Err(NativeConsoleError::Sequence);
        }
        self.sequence = accepted_sequence;
        self.remaining = authorization.allowance;
        self.authorization = Some(authorization);
        Ok(())
    }

    /// Checks the whole operation's allowance before byte publication.
    ///
    /// This check does not roll back write-side UART state that may already have
    /// changed before the original transmit operation reaches its preflight.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for an absent grant, exhausted allowance,
    /// or sequence overflow. Success is capacity validation, not execution permission.
    pub fn preflight(&self, bytes: u32) -> Result<(), NativeConsoleError> {
        if self.authorization.is_none()
            || bytes > self.remaining
            || self.sequence.checked_add(u64::from(bytes)).is_none()
        {
            return Err(NativeConsoleError::Sequence);
        }
        Ok(())
    }

    /// Charges an already-published complete operation against its original grant.
    ///
    /// # Errors
    ///
    /// Returns [`NativeConsoleError`] for allowance exhaustion or overflow;
    /// refusal leaves the ledger unchanged.
    pub fn charge(&mut self, bytes: u32) -> Result<(), NativeConsoleError> {
        self.preflight(bytes)?;
        self.remaining -= bytes;
        self.sequence += u64::from(bytes);
        Ok(())
    }

    /// Returns the original grant's remaining allowance, unaffected by drains.
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        self.remaining
    }
}
