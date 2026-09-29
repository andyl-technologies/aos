//! Owns the finite PRE-ROOT framing, with no proof or authority constructors.
//!
//! ```text
//! bootstrap32: AOSCRS01 | nonce16 | absolute-BOOTTIME-u64
//! header48: AOSCRF01 | version-u16 | phase-u8 | zero5 | nonce16 |
//!           same-deadline-u64 | payload-length-u32 | zero4
//! STATE: Current-digest32 | Candidate-digest32 | generation-u64 |
//!        candidate-length-u32 | canonical-Candidate
//! ```

use super::ConsumerReadFlightErrorV1 as Error;

/// Discriminates only the additive PRE-ROOT state-first request.
pub const CONSUMER_READ_BOOTSTRAP_MAGIC_V1: &[u8; 8] = b"AOSCRS01";
pub(super) const HEADER_BYTES: usize = 48;
pub(super) const STATE_PREFIX_BYTES: usize = 76;
const FRAME_MAGIC: &[u8; 8] = b"AOSCRF01";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum Phase {
    Hello = 1,
    Select = 2,
    State = 3,
    Continue = 4,
    Abort = 5,
    Aborted = 6,
    Denied = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Correlation {
    pub(super) nonce: [u8; 16],
    pub(super) deadline: u64,
}

impl Correlation {
    pub(super) fn from_bootstrap(bytes: &[u8; 32]) -> Result<Self, Error> {
        if &bytes[..8] != CONSUMER_READ_BOOTSTRAP_MAGIC_V1 {
            return Err(Error::Protocol);
        }
        let result = Self {
            nonce: take(bytes, 8)?,
            deadline: u64::from_be_bytes(take(bytes, 24)?),
        };
        if result.nonce == [0; 16] || result.deadline == 0 {
            return Err(Error::Protocol);
        }
        Ok(result)
    }

    pub(super) fn bootstrap(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(CONSUMER_READ_BOOTSTRAP_MAGIC_V1);
        bytes[8..24].copy_from_slice(&self.nonce);
        bytes[24..].copy_from_slice(&self.deadline.to_be_bytes());
        bytes
    }

    pub(super) fn header(self, phase: Phase, length: usize) -> Result<[u8; HEADER_BYTES], Error> {
        let length = u32::try_from(length).map_err(|_| Error::Protocol)?;
        let mut bytes = [0; HEADER_BYTES];
        bytes[..8].copy_from_slice(FRAME_MAGIC);
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[10] = phase as u8;
        bytes[16..32].copy_from_slice(&self.nonce);
        bytes[32..40].copy_from_slice(&self.deadline.to_be_bytes());
        bytes[40..44].copy_from_slice(&length.to_be_bytes());
        Ok(bytes)
    }

    pub(super) fn decode_header(self, bytes: &[u8]) -> Result<(Phase, usize), Error> {
        if bytes.len() != HEADER_BYTES
            || bytes[..8] != *FRAME_MAGIC
            || bytes[8..10] != 1_u16.to_be_bytes()
            || bytes[11..16] != [0; 5]
            || bytes[44..48] != [0; 4]
            || take::<16>(bytes, 16)? != self.nonce
            || u64::from_be_bytes(take(bytes, 32)?) != self.deadline
        {
            return Err(Error::Protocol);
        }
        let phase = match bytes[10] {
            1 => Phase::Hello,
            2 => Phase::Select,
            3 => Phase::State,
            4 => Phase::Continue,
            5 => Phase::Abort,
            6 => Phase::Aborted,
            7 => Phase::Denied,
            _ => return Err(Error::Protocol),
        };
        let length = u32::from_be_bytes(take(bytes, 40)?) as usize;
        let exact = match phase {
            Phase::Hello => Some(16),
            Phase::Select => Some(32),
            Phase::State => None,
            _ => Some(0),
        };
        if exact.is_some_and(|expected| length != expected)
            || (phase == Phase::State
                && !(STATE_PREFIX_BYTES..=maximum_state_bytes()?).contains(&length))
        {
            return Err(Error::Protocol);
        }
        Ok((phase, length))
    }
}

pub(super) fn maximum_state_bytes() -> Result<usize, Error> {
    super::super::protected_owner::policy_state_journal_limits()
        .maximum_record_bytes
        .checked_add(STATE_PREFIX_BYTES)
        .ok_or(Error::Protocol)
}

pub(super) fn take<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset.checked_add(N).ok_or(Error::Protocol)?;
    bytes
        .get(offset..end)
        .ok_or(Error::Protocol)?
        .try_into()
        .map_err(|_| Error::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn correlation() -> Correlation {
        Correlation {
            nonce: [3; 16],
            deadline: 0x0102030405060708,
        }
    }

    #[test]
    fn exact_wire_layout_and_closed_phase_lengths() {
        let identity = correlation();
        assert_eq!(&identity.bootstrap()[..8], b"AOSCRS01");
        assert_eq!(&identity.bootstrap()[24..], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            Correlation::from_bootstrap(&identity.bootstrap()).unwrap(),
            identity
        );
        for (phase, length) in [
            (Phase::Hello, 16),
            (Phase::Select, 32),
            (Phase::State, 76),
            (Phase::State, maximum_state_bytes().unwrap()),
            (Phase::Continue, 0),
            (Phase::Abort, 0),
            (Phase::Aborted, 0),
            (Phase::Denied, 0),
        ] {
            let header = identity.header(phase, length).unwrap();
            assert_eq!(
                &header[..16],
                &[
                    b'A',
                    b'O',
                    b'S',
                    b'C',
                    b'R',
                    b'F',
                    b'0',
                    b'1',
                    0,
                    1,
                    phase as u8,
                    0,
                    0,
                    0,
                    0,
                    0
                ]
            );
            assert_eq!(identity.decode_header(&header).unwrap(), (phase, length));
        }
        for (phase, length) in [
            (Phase::Hello, 15),
            (Phase::Select, 33),
            (Phase::Continue, 1),
            (Phase::State, 75),
            (Phase::State, maximum_state_bytes().unwrap() + 1),
        ] {
            assert!(
                identity
                    .decode_header(&identity.header(phase, length).unwrap())
                    .is_err()
            );
        }
        if let Ok(header) = identity.header(Phase::State, usize::MAX) {
            assert!(identity.decode_header(&header).is_err());
        }
    }

    #[test]
    fn alternate_identity_version_reserved_phase_and_trailing_bytes_refuse() {
        let identity = correlation();
        let canonical = identity.header(Phase::Abort, 0).unwrap();
        for offset in [0, 8, 9, 10, 11, 12, 15, 16, 31, 32, 39, 40, 43, 44, 47] {
            let mut altered = canonical;
            altered[offset] ^= 0x80;
            assert!(identity.decode_header(&altered).is_err(), "offset {offset}");
        }
        assert!(identity.decode_header(&canonical[..47]).is_err());
        let mut trailing = canonical.to_vec();
        trailing.push(0);
        assert!(identity.decode_header(&trailing).is_err());
        for offset in [8, 24] {
            let mut bootstrap = identity.bootstrap();
            let end = if offset == 8 { 24 } else { 32 };
            bootstrap[offset..end].fill(0);
            assert!(Correlation::from_bootstrap(&bootstrap).is_err());
        }
    }
}
