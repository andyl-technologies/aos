//! Full issued-body custody paired with an original control request.
//!
//! The host commits this table before releasing the even request. Native
//! acceptance must join that request to the original coherent clamp and its
//! installed resource owner. No field supplies a native clock observation,
//! runnable phase, closed-RR receipt, or host ledger retirement authority.

use super::*;

/// Exact bytes in one paired-clamp table, including its publication word.
pub const NATIVE_CONSOLE_CLAMP_BYTES: usize = 256;

/// Current paired-control framing version; older frames are refused.
pub const NATIVE_CONSOLE_CLAMP_SCHEMA_VERSION: u16 = 2;

/// Closed control dispositions; neither value grants native execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NativeConsoleControlKind {
    /// Accepts a prefix against the complete original issued authorization.
    Acceptance = 1,
    /// Observes an already accepted, drained prefix without issuing a grant.
    Observation = 2,
}

/// Host custody needed to authenticate an original settled control invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeConsoleClamp {
    /// Nonzero even publication of the single host writer.
    pub publication: u64,
    /// Exact even advance supplied by the original clamp writer.
    pub advance: u64,
    /// Original even request; zero remains valid after its existing wrap.
    pub request: u32,
    /// Original odd capture request, or zero when no capture was requested.
    pub capture: u32,
    /// Original fault-command frontier paired with the request.
    pub fault_frontier: u64,
    /// Original scheduler ceiling, never a substituted emitted coordinate.
    pub ceiling: u64,
    /// Original stop encoding: ceiling (0) or authenticated idle (1).
    pub stop: u8,
    /// Required disposition, authenticated independently by the native owner.
    pub kind: NativeConsoleControlKind,
    /// Full issued body for acceptance; observation encodes no authorization.
    ///
    /// An observation requires an already accepted native prefix and its real
    /// CLOSED scope. Absence never authenticates initial setup or execution.
    pub last_issued: Option<NativeConsoleAuthorization>,
}

impl NativeConsoleClamp {
    /// Encodes the exact shape without authenticating a control invocation.
    ///
    /// # Errors
    ///
    /// Refuses odd or absent publication, odd advance/request, invalid capture,
    /// an unknown stop encoding, or an invalid full authorization body.
    pub fn encode(self) -> Result<[u8; NATIVE_CONSOLE_CLAMP_BYTES], NativeConsoleError> {
        if self.publication == 0
            || self.publication & 1 != 0
            || self.advance & 1 != 0
            || self.request & 1 != 0
            || (self.capture != 0 && self.capture & 1 == 0)
            || self.stop > 1
            || !matches!(
                (self.kind, self.last_issued),
                (NativeConsoleControlKind::Acceptance, Some(_))
                    | (NativeConsoleControlKind::Observation, None)
            )
        {
            return Err(NativeConsoleError::Field);
        }

        let mut out = [0; NATIVE_CONSOLE_CLAMP_BYTES];
        put64(&mut out, 0, self.publication);
        out[8..12].copy_from_slice(b"NCCP");
        put16(&mut out, 12, NATIVE_CONSOLE_CLAMP_SCHEMA_VERSION);
        put16(&mut out, 14, NATIVE_CONSOLE_CLAMP_BYTES as u16);
        put64(&mut out, 16, self.advance);
        put32(&mut out, 24, self.request);
        put32(&mut out, 28, self.capture);
        put64(&mut out, 32, self.fault_frontier);
        put64(&mut out, 40, self.ceiling);
        out[49] = self.stop;
        out[50] = self.kind as u8;
        if let Some(body) = self.last_issued {
            out[48] = 1;
            out[64..192].copy_from_slice(&body.encode()?);
        }
        Ok(out)
    }

    /// Decodes one complete paired control without authenticating its custody.
    ///
    /// # Errors
    ///
    /// Refuses a different frame, length, reserved byte, presence tag, scalar
    /// shape, or malformed nested authorization. Decoding grants no authority.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeConsoleError> {
        exact(bytes, NATIVE_CONSOLE_CLAMP_BYTES)?;
        if &bytes[8..12] != b"NCCP"
            || get16(bytes, 12) != NATIVE_CONSOLE_CLAMP_SCHEMA_VERSION
            || get16(bytes, 14) != NATIVE_CONSOLE_CLAMP_BYTES as u16
            || bytes[51..64].iter().any(|value| *value != 0)
            || bytes[192..].iter().any(|value| *value != 0)
        {
            return Err(NativeConsoleError::Framing);
        }
        let last_issued = match bytes[48] {
            0 if bytes[64..192].iter().all(|value| *value == 0) => None,
            1 => Some(NativeConsoleAuthorization::decode(&bytes[64..192])?),
            _ => return Err(NativeConsoleError::Framing),
        };
        let kind = match bytes[50] {
            1 => NativeConsoleControlKind::Acceptance,
            2 => NativeConsoleControlKind::Observation,
            _ => return Err(NativeConsoleError::Field),
        };
        let value = Self {
            publication: get64(bytes, 0),
            advance: get64(bytes, 16),
            request: get32(bytes, 24),
            capture: get32(bytes, 28),
            fault_frontier: get64(bytes, 32),
            ceiling: get64(bytes, 40),
            stop: bytes[49],
            kind,
            last_issued,
        };
        value.encode()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_zero_auth_is_preserved_without_inventing_initial_authority()
    -> Result<(), NativeConsoleError> {
        let value = NativeConsoleClamp {
            publication: 2,
            advance: 4,
            request: 0,
            capture: 0,
            fault_frontier: 0,
            ceiling: 100,
            stop: 0,
            kind: NativeConsoleControlKind::Observation,
            last_issued: None,
        };
        let mut bytes = value.encode()?;
        let expected_header: [u8; 64] = [
            2, 0, 0, 0, 0, 0, 0, 0, 78, 67, 67, 80, 2, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(bytes[..64], expected_header);
        assert_eq!(bytes[64..], [0; 192]);
        assert_eq!(NativeConsoleClamp::decode(&bytes)?, value);
        bytes[64] = 1;
        assert!(NativeConsoleClamp::decode(&bytes).is_err());
        Ok(())
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    #[test]
    fn control_kind_version_and_authorization_presence_are_closed() -> Result<(), NativeConsoleError>
    {
        let observation = NativeConsoleClamp {
            publication: 2,
            advance: 4,
            request: 6,
            capture: 3,
            fault_frontier: 7,
            ceiling: 100,
            stop: 0,
            kind: NativeConsoleControlKind::Observation,
            last_issued: None,
        };
        let encoded = observation.encode()?;
        for (offset, value) in [(12, 1), (50, 0), (50, 3), (50, 1), (51, 1), (64, 1)] {
            let mut corrupt = encoded;
            corrupt[offset] = value;
            assert!(NativeConsoleClamp::decode(&corrupt).is_err());
        }
        assert!(
            NativeConsoleClamp {
                kind: NativeConsoleControlKind::Acceptance,
                ..observation
            }
            .encode()
            .is_err()
        );
        let authorization = NativeConsoleAuthorization {
            publication: 2,
            owner: NativeConsoleOwner {
                slot: 0,
                region: [4; 16],
                process: 8,
                authorization: 10,
            },
            logical_generation: 0,
            advance: 4,
            prior_sequence: 0,
            prior_ring_end: 0,
            allowance: 2,
            phase_token: 0,
            phase: NativeConsolePhase::ColdSetup,
        };
        let acceptance = NativeConsoleClamp {
            kind: NativeConsoleControlKind::Acceptance,
            last_issued: Some(authorization),
            ..observation
        };
        let encoded = acceptance.encode()?;
        assert_eq!(encoded[48..51], [1, 0, 1]);
        assert_eq!(encoded[64..192], authorization.encode()?);
        assert_eq!(NativeConsoleClamp::decode(&encoded)?, acceptance);
        assert!(
            NativeConsoleClamp {
                kind: NativeConsoleControlKind::Observation,
                ..acceptance
            }
            .encode()
            .is_err()
        );
        Ok(())
    }
}
