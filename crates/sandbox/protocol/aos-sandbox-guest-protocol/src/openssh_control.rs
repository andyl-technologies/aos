//! Bounded control data on the original authenticated SSH monitor session.
//!
//! ```text
//! AOSMCQ05 | sequence:u64be | action:u8 | reserved[7] | length:u32be | payload
//! action 1: signal:u8
//! action 2: rows:u16be | columns:u16be | xpixel:u16be | ypixel:u16be
//! action 3: geometry[8] | terminal-length:u16be | terminal | modes-length:u16be | modes
//! ```
//!
//! This format contains no selected process, route, grant, certificate or
//! expiry. The actual measured root monitor owns its sequence. Parsing never
//! substitutes for retained monitor custody or current Controller/Host policy;
//! a successful effect also requires the existing Guest owner's shared barrier
//! and durable original-session reservation. The V4 terminal format is unchanged.

use crate::openssh_session::{OpenSshSessionActionV4, OpenSshSessionRequestV4};

/// Bounds RFC 4254 terminal-mode data before parsing or allocation.
pub const OPENSSH_CONTROL_MAXIMUM_MODES_BYTES_V5: usize = 1024;

/// Bounds the client's terminal label, which never modifies original execution environment.
pub const OPENSSH_CONTROL_MAXIMUM_TERMINAL_BYTES_V5: usize = 128;

/// Bounds one complete private monitor request before parsing or allocation.
pub const OPENSSH_CONTROL_MAXIMUM_REQUEST_BYTES_V5: usize = 28
    + 8
    + 2
    + OPENSSH_CONTROL_MAXIMUM_TERMINAL_BYTES_V5
    + 2
    + OPENSSH_CONTROL_MAXIMUM_MODES_BYTES_V5;

/// Retains exact native PTY geometry without truncating SSH unsigned values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenSshPtyGeometryV5 {
    /// Native row count; zero means unspecified only during initial PTY setup.
    pub rows: u16,
    /// Native column count; zero means unspecified only during initial PTY setup.
    pub columns: u16,
    /// Native horizontal pixel count.
    pub xpixel: u16,
    /// Native vertical pixel count.
    pub ypixel: u16,
}

/// Selects a fixed original-execution effect, never a process or execution factory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenSshControlActionV5 {
    /// Delivers one of the unchanged seven public control signals.
    Signal(u8),
    /// Resizes the original retained PTY.
    Resize(OpenSshPtyGeometryV5),
    /// Installs client mode settings on the original retained PTY before relay readiness.
    Pty {
        /// Exact original PTY geometry.
        geometry: OpenSshPtyGeometryV5,
        /// Client terminal label only; original admitted TERM/environment stays unchanged.
        terminal: String,
        /// Bounded RFC 4254 modes, interpreted only by the retained PTY owner.
        modes: Vec<u8>,
    },
}

/// Carries one root-owned original-session sequence and bounded control data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenSshControlRequestV5 {
    /// Strictly increasing original-session sequence, not a permission witness.
    pub sequence: u64,
    /// Closed action on the original execution.
    pub action: OpenSshControlActionV5,
}

impl OpenSshPtyGeometryV5 {
    fn require_resize(self) -> Result<(), InvalidOpenSshControlV5> {
        OpenSshSessionRequestV4 {
            sequence: 1,
            action: OpenSshSessionActionV4::Resize {
                rows: self.rows,
                columns: self.columns,
                xpixel: self.xpixel,
                ypixel: self.ypixel,
            },
        }
        .encode()
        .map_err(|_| InvalidOpenSshControlV5)?;
        Ok(())
    }

    fn encode(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        for (index, value) in [self.rows, self.columns, self.xpixel, self.ypixel]
            .into_iter()
            .enumerate()
        {
            bytes[index * 2..index * 2 + 2].copy_from_slice(&value.to_be_bytes());
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, InvalidOpenSshControlV5> {
        let bytes: &[u8; 8] = bytes.try_into().map_err(|_| InvalidOpenSshControlV5)?;
        let geometry = Self {
            rows: u16::from_be_bytes([bytes[0], bytes[1]]),
            columns: u16::from_be_bytes([bytes[2], bytes[3]]),
            xpixel: u16::from_be_bytes([bytes[4], bytes[5]]),
            ypixel: u16::from_be_bytes([bytes[6], bytes[7]]),
        };
        Ok(geometry)
    }
}

impl OpenSshControlRequestV5 {
    /// Encodes exact bounded data without creating original-session custody.
    ///
    /// # Errors
    /// Rejects zero/exhausted sequence, unsupported signal, invalid resize geometry,
    /// oversized/invalid terminal label or malformed terminal modes.
    pub fn encode(&self) -> Result<Vec<u8>, InvalidOpenSshControlV5> {
        if self.sequence == 0 || self.sequence == u64::MAX {
            return Err(InvalidOpenSshControlV5);
        }
        let (code, payload) = match &self.action {
            OpenSshControlActionV5::Signal(signal) => {
                OpenSshSessionRequestV4 {
                    sequence: self.sequence,
                    action: OpenSshSessionActionV4::Signal(*signal),
                }
                .encode()
                .map_err(|_| InvalidOpenSshControlV5)?;
                (1, vec![*signal])
            }
            OpenSshControlActionV5::Resize(geometry) => {
                geometry.require_resize()?;
                (2, geometry.encode().to_vec())
            }
            OpenSshControlActionV5::Pty {
                geometry,
                terminal,
                modes,
            } => {
                if terminal.len() > OPENSSH_CONTROL_MAXIMUM_TERMINAL_BYTES_V5
                    || terminal.as_bytes().contains(&0)
                {
                    return Err(InvalidOpenSshControlV5);
                }
                decode_terminal_modes_v5(modes)?;
                let mut payload = geometry.encode().to_vec();
                append_section(&mut payload, terminal.as_bytes())?;
                append_section(&mut payload, modes)?;
                (3, payload)
            }
        };
        let mut bytes = Vec::with_capacity(28 + payload.len());
        bytes.extend_from_slice(b"AOSMCQ05");
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.push(code);
        bytes.extend_from_slice(&[0; 7]);
        bytes.extend_from_slice(
            &u32::try_from(payload.len())
                .map_err(|_| InvalidOpenSshControlV5)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    /// Decodes canonical data without authenticating its sender or authorizing an effect.
    ///
    /// # Errors
    /// Rejects unknown versions/actions, padding, partial/trailing data,
    /// invalid bounds or a noncanonical request.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidOpenSshControlV5> {
        if !(28..=OPENSSH_CONTROL_MAXIMUM_REQUEST_BYTES_V5).contains(&bytes.len())
            || bytes.get(..8) != Some(b"AOSMCQ05".as_slice())
        {
            return Err(InvalidOpenSshControlV5);
        }
        let sequence = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| InvalidOpenSshControlV5)?,
        );
        let length = u32::from_be_bytes(
            bytes[24..28]
                .try_into()
                .map_err(|_| InvalidOpenSshControlV5)?,
        ) as usize;
        if length != bytes.len() - 28 {
            return Err(InvalidOpenSshControlV5);
        }
        let payload = &bytes[28..];
        let action = match bytes[16] {
            1 if payload.len() == 1 => OpenSshControlActionV5::Signal(payload[0]),
            2 => OpenSshControlActionV5::Resize(OpenSshPtyGeometryV5::decode(payload)?),
            3 => {
                let geometry =
                    OpenSshPtyGeometryV5::decode(payload.get(..8).ok_or(InvalidOpenSshControlV5)?)?;
                let mut remainder = &payload[8..];
                let terminal = String::from_utf8(section(&mut remainder)?.to_vec())
                    .map_err(|_| InvalidOpenSshControlV5)?;
                let modes = section(&mut remainder)?.to_vec();
                if !remainder.is_empty() {
                    return Err(InvalidOpenSshControlV5);
                }
                OpenSshControlActionV5::Pty {
                    geometry,
                    terminal,
                    modes,
                }
            }
            _ => return Err(InvalidOpenSshControlV5),
        };
        let request = Self { sequence, action };
        if request.encode()? != bytes {
            return Err(InvalidOpenSshControlV5);
        }
        Ok(request)
    }
}

/// Reads bounded RFC 4254 terminal-mode pairs without mutating a terminal.
///
/// Empty data changes no modes. Opcode zero terminates the string; opcodes
/// 160..=255 stop interpretation as required by the SSH format. Unknown
/// opcodes 1..=159 retain their u32 value and may be ignored by a platform.
/// The exact original bytes, including an uninterpreted future suffix, remain
/// part of the control commitment.
///
/// # Errors
/// Rejects oversized data, partial u32 values, a missing terminator or bytes
/// following the explicit zero terminator.
pub fn decode_terminal_modes_v5(bytes: &[u8]) -> Result<Vec<(u8, u32)>, InvalidOpenSshControlV5> {
    if bytes.len() > OPENSSH_CONTROL_MAXIMUM_MODES_BYTES_V5 {
        return Err(InvalidOpenSshControlV5);
    }
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut modes = Vec::new();
    let mut remainder = bytes;
    while let Some((&code, rest)) = remainder.split_first() {
        match code {
            0 if rest.is_empty() => return Ok(modes),
            0 => return Err(InvalidOpenSshControlV5),
            160..=255 => return Ok(modes),
            _ => {
                let value = rest.get(..4).ok_or(InvalidOpenSshControlV5)?;
                modes.push((
                    code,
                    u32::from_be_bytes(value.try_into().map_err(|_| InvalidOpenSshControlV5)?),
                ));
                remainder = &rest[4..];
            }
        }
    }
    Err(InvalidOpenSshControlV5)
}

/// Reports an opaque malformed data record without leaking ticket or process custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("OpenSSH original control record rejected")]
pub struct InvalidOpenSshControlV5;

fn append_section(bytes: &mut Vec<u8>, section: &[u8]) -> Result<(), InvalidOpenSshControlV5> {
    bytes.extend_from_slice(
        &u16::try_from(section.len())
            .map_err(|_| InvalidOpenSshControlV5)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(section);
    Ok(())
}

fn section<'a>(remainder: &mut &'a [u8]) -> Result<&'a [u8], InvalidOpenSshControlV5> {
    let length = remainder.get(..2).ok_or(InvalidOpenSshControlV5)?;
    let length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let value = remainder
        .get(2..2 + length)
        .ok_or(InvalidOpenSshControlV5)?;
    *remainder = &remainder[2 + length..];
    Ok(value)
}

#[cfg(test)]
mod tests {
    //! Canonical data boundaries, not original-session authority fixtures.

    use super::*;

    #[test]
    fn bounded_original_actions_round_trip_without_process_selection() {
        let geometry = OpenSshPtyGeometryV5 {
            rows: 24,
            columns: 80,
            xpixel: 640,
            ypixel: 480,
        };
        for action in [
            OpenSshControlActionV5::Signal(15),
            OpenSshControlActionV5::Resize(geometry),
            OpenSshControlActionV5::Pty {
                geometry,
                terminal: "xterm-256color".into(),
                modes: vec![53, 0, 0, 0, 0, 0],
            },
        ] {
            let request = OpenSshControlRequestV5 {
                sequence: 3,
                action,
            };
            let bytes = request.encode().unwrap();
            assert_eq!(OpenSshControlRequestV5::decode(&bytes).unwrap(), request);
            for length in 0..bytes.len() {
                assert!(OpenSshControlRequestV5::decode(&bytes[..length]).is_err());
            }
            for index in [0, 17, 23, 24, 27] {
                let mut foreign = bytes.clone();
                foreign[index] ^= 1;
                assert!(OpenSshControlRequestV5::decode(&foreign).is_err());
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(OpenSshControlRequestV5::decode(&trailing).is_err());
        }
    }

    #[test]
    fn terminal_modes_follow_rfc_bounds_without_a_generic_parser_factory() {
        assert_eq!(decode_terminal_modes_v5(&[]).unwrap(), []);
        assert_eq!(decode_terminal_modes_v5(&[0]).unwrap(), []);
        assert_eq!(
            decode_terminal_modes_v5(&[53, 0, 0, 0, 1, 0]).unwrap(),
            [(53, 1)]
        );
        assert_eq!(
            decode_terminal_modes_v5(&[159, 0, 0, 0, 7, 0]).unwrap(),
            [(159, 7)]
        );
        assert_eq!(decode_terminal_modes_v5(&[160, 1, 2]).unwrap(), []);
        for invalid in [&[0, 1][..], &[53], &[53, 0, 0, 0], &[53, 0, 0, 0, 0]] {
            assert!(decode_terminal_modes_v5(invalid).is_err());
        }
        assert!(
            decode_terminal_modes_v5(&vec![0; OPENSSH_CONTROL_MAXIMUM_MODES_BYTES_V5 + 1]).is_err()
        );
    }
}
