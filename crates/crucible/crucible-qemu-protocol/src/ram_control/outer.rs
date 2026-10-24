//! Encodes operational original-start caps without guest or model clock state.
//!
//! ```text
//! u32 schema = 1; bytes[32] cap_id; u64 revision;
//! u64 original_monotonic_ns; u8 allowance_present; u64 allowance_ns;
//! u8 state (0 running, 1 expired, 2 canceled)
//! ```

use super::RamControlError;

/// Fixed canonical original-start cap record length.
pub const RAM_CONTROL_OUTER_BYTES: usize = 62;

/// Sticky operational disposition of one original-start outer cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RamControlOuterState {
    /// Operations may continue under the applicable allowances.
    Running,
    /// An original-start allowance expired and cannot be revived.
    Expired,
    /// Explicit operational cancellation prevents continuation.
    Canceled,
}

/// Binds local pager containment to the host's immutable monotonic original start.
///
/// This integer coordinate belongs exclusively to operational supervision on
/// the same host kernel as the authenticated Unix endpoint. It never contributes
/// to guest time, deterministic state, page identity or replay decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamControlOuterCap {
    /// Independently authenticated original cap identity.
    pub cap_id: [u8; 32],
    /// Nonreused amendment revision; zero is initial admission.
    pub revision: u64,
    /// Immutable local CLOCK_MONOTONIC original start in nanoseconds.
    pub original_monotonic_ns: u64,
    /// Original-start allowance; absent means explicitly unlimited.
    pub allowance_ns: Option<u64>,
    /// Sticky host disposition at the supplied revision.
    pub state: RamControlOuterState,
}

impl RamControlOuterCap {
    /// Checks canonical scalar bounds before admission or encoding.
    ///
    /// # Errors
    /// Refuses zero identity/start, zero allowance or deadline overflow.
    pub fn validate(self) -> Result<(), RamControlError> {
        if self.cap_id == [0; 32]
            || self.original_monotonic_ns == 0
            || self.allowance_ns.is_some_and(|allowance| {
                allowance == 0 || self.original_monotonic_ns.checked_add(allowance).is_none()
            })
        {
            return Err(RamControlError::InvalidFrame);
        }
        Ok(())
    }
}

/// Encodes one bounded canonical operational cap for launch or live synchronization.
///
/// # Errors
/// Refuses a malformed identity, original start or allowance.
pub fn encode_ram_control_outer(
    cap: RamControlOuterCap,
) -> Result<[u8; RAM_CONTROL_OUTER_BYTES], RamControlError> {
    cap.validate()?;
    let mut bytes = [0; RAM_CONTROL_OUTER_BYTES];
    bytes[..4].copy_from_slice(&1_u32.to_be_bytes());
    bytes[4..36].copy_from_slice(&cap.cap_id);
    bytes[36..44].copy_from_slice(&cap.revision.to_be_bytes());
    bytes[44..52].copy_from_slice(&cap.original_monotonic_ns.to_be_bytes());
    bytes[52] = u8::from(cap.allowance_ns.is_some());
    bytes[53..61].copy_from_slice(&cap.allowance_ns.unwrap_or(0).to_be_bytes());
    bytes[61] = match cap.state {
        RamControlOuterState::Running => 0,
        RamControlOuterState::Expired => 1,
        RamControlOuterState::Canceled => 2,
    };
    Ok(bytes)
}

/// Decodes a fixed cap record before any allocation.
///
/// # Errors
/// Refuses wrong length/version, unknown state, noncanonical optional allowance
/// or invalid bounded scalars.
pub fn decode_ram_control_outer(bytes: &[u8]) -> Result<RamControlOuterCap, RamControlError> {
    let bytes: &[u8; RAM_CONTROL_OUTER_BYTES] = bytes
        .try_into()
        .map_err(|_| RamControlError::InvalidFrame)?;
    if bytes[..4] != 1_u32.to_be_bytes() {
        return Err(RamControlError::UnsupportedVersion(u32::from_be_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| RamControlError::InvalidFrame)?,
        )));
    }
    let scalar = |offset: usize| -> Result<u64, RamControlError> {
        Ok(u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| RamControlError::InvalidFrame)?,
        ))
    };
    let allowance = scalar(53)?;
    let allowance_ns = match (bytes[52], allowance) {
        (0, 0) => None,
        (1, allowance) if allowance > 0 => Some(allowance),
        _ => return Err(RamControlError::InvalidFrame),
    };
    let state = match bytes[61] {
        0 => RamControlOuterState::Running,
        1 => RamControlOuterState::Expired,
        2 => RamControlOuterState::Canceled,
        _ => return Err(RamControlError::InvalidFrame),
    };
    let cap = RamControlOuterCap {
        cap_id: bytes[4..36]
            .try_into()
            .map_err(|_| RamControlError::InvalidFrame)?,
        revision: scalar(36)?,
        original_monotonic_ns: scalar(44)?,
        allowance_ns,
        state,
    };
    cap.validate()?;
    Ok(cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_cap_requires_canonical_bounds_and_every_byte() {
        let cap = RamControlOuterCap {
            cap_id: [1; 32],
            revision: 0,
            original_monotonic_ns: 12,
            allowance_ns: Some(90),
            state: RamControlOuterState::Running,
        };
        let bytes = encode_ram_control_outer(cap)
            .unwrap_or_else(|error| panic!("canonical cap must encode/decode: {error}"));
        assert_eq!(
            decode_ram_control_outer(&bytes)
                .unwrap_or_else(|error| panic!("canonical cap must encode/decode: {error}")),
            cap
        );
        for length in 0..bytes.len() {
            assert!(decode_ram_control_outer(&bytes[..length]).is_err());
        }
        let mut malformed = bytes;
        malformed[52] = 0;
        assert!(decode_ram_control_outer(&malformed).is_err());
        malformed = bytes;
        malformed[61] = 3;
        assert!(decode_ram_control_outer(&malformed).is_err());
        assert!(
            encode_ram_control_outer(RamControlOuterCap {
                original_monotonic_ns: u64::MAX,
                ..cap
            })
            .is_err()
        );
        assert!(
            encode_ram_control_outer(RamControlOuterCap {
                allowance_ns: Some(0),
                ..cap
            })
            .is_err()
        );
    }
}
