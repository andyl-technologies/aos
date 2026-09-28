//! Canonical nonauthorizing requests on the original private SSH monitor session.
//!
//! ```text
//! AOSMCT04 | sequence:u64be | action:u8 | reserved[7] | arguments[8]
//! AOSMCA04 | sequence:u64be | state:u8 | reserved[7] | waitstatus:u32be | reserved[4]
//! AOSIOE04 | waitstatus:u32be
//! ```
//!
//! Only the measured root monitor's retained connection can nominate a control
//! for its own already-authenticated session. Signal/resize still require fresh
//! held Controller/Host authority and durable Guest sequence reservation. A
//! terminal read is nonauthorizing and returns only the original owned process
//! waitstatus after recursive subtree emptiness; relay exit is never its source.

/// Exact private monitor record size, checked before parsing or allocation.
pub const OPENSSH_SESSION_RECORD_BYTES_V4: usize = 32;

/// Selects one fixed operation without accepting a PID, PGID or another route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenSshSessionActionV4 {
    /// Delivers one of the unchanged seven public control signals.
    Signal(u8),
    /// Resizes the original PTY without silently truncating unsigned geometry.
    Resize {
        /// Positive original PTY row count.
        rows: u16,
        /// Positive original PTY column count.
        columns: u16,
        /// Exact bounded horizontal pixel count.
        xpixel: u16,
        /// Exact bounded vertical pixel count.
        ypixel: u16,
    },
    /// Reads the exact original terminal waitstatus without mutating execution.
    Terminal,
}

/// Correlates one canonical action with the original session's next sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenSshSessionRequestV4 {
    /// Strictly increasing per-original-session sequence, never an authorizer.
    pub sequence: u64,
    /// Closed original-session control or nonauthorizing terminal read.
    pub action: OpenSshSessionActionV4,
}

/// Carries only the kernel waitstatus of the original execution leader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OriginalExecutionWaitStatusV4(u32);

/// Returns data on the original monitor connection without granting I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenSshSessionStateV4 {
    /// The original execution has not yet reached a proved terminal state.
    Pending,
    /// The original owned subtree is empty and its leader status was retained.
    Terminal(OriginalExecutionWaitStatusV4),
}

/// Correlates a data reply with one original private monitor request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenSshSessionReplyV4 {
    /// Exact request sequence, never a current-policy authorization witness.
    pub sequence: u64,
    /// Original owned terminal data or a nonterminal observation.
    pub state: OpenSshSessionStateV4,
}

impl OpenSshSessionReplyV4 {
    /// Encodes a bounded, nonauthorizing original-session reply.
    ///
    /// # Errors
    /// Rejects the zero sequence sentinel.
    pub fn encode(self) -> Result<[u8; OPENSSH_SESSION_RECORD_BYTES_V4], InvalidOpenSshSessionV4> {
        if self.sequence == 0 {
            return Err(InvalidOpenSshSessionV4);
        }
        let mut bytes = [0; OPENSSH_SESSION_RECORD_BYTES_V4];
        bytes[..8].copy_from_slice(b"AOSMCA04");
        bytes[8..16].copy_from_slice(&self.sequence.to_be_bytes());
        if let OpenSshSessionStateV4::Terminal(status) = self.state {
            bytes[16] = 1;
            bytes[24..28].copy_from_slice(&status.raw().to_be_bytes());
        }
        Ok(bytes)
    }

    /// Decodes an exact canonical reply, not a substitute for sender custody.
    ///
    /// # Errors
    /// Rejects unknown versions/states, malformed status, padding or bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidOpenSshSessionV4> {
        let bytes: &[u8; OPENSSH_SESSION_RECORD_BYTES_V4] =
            bytes.try_into().map_err(|_| InvalidOpenSshSessionV4)?;
        if &bytes[..8] != b"AOSMCA04" {
            return Err(InvalidOpenSshSessionV4);
        }
        let sequence = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| InvalidOpenSshSessionV4)?,
        );
        let state = match bytes[16] {
            0 => OpenSshSessionStateV4::Pending,
            1 => OpenSshSessionStateV4::Terminal(OriginalExecutionWaitStatusV4::new(
                u32::from_be_bytes(
                    bytes[24..28]
                        .try_into()
                        .map_err(|_| InvalidOpenSshSessionV4)?,
                ),
            )?),
            _ => return Err(InvalidOpenSshSessionV4),
        };
        let reply = Self { sequence, state };
        if reply.encode()?.as_slice() != bytes {
            return Err(InvalidOpenSshSessionV4);
        }
        Ok(reply)
    }
}

impl OriginalExecutionWaitStatusV4 {
    /// Validates a complete Linux exited/signaled status, not stopped/continued.
    ///
    /// # Errors
    /// Rejects reserved bits, stopped/continued status, or an invalid signal.
    pub fn new(raw: u32) -> Result<Self, InvalidOpenSshSessionV4> {
        let signal = raw & 0x7f;
        if raw & !0xffff != 0
            || (signal == 0 && raw & 0xff != 0)
            || (signal != 0 && (signal > 64 || raw & !0xff != 0))
        {
            return Err(InvalidOpenSshSessionV4);
        }
        Ok(Self(raw))
    }

    /// Returns the byte-exact kernel status for the protected monitor response.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns the exact ordinary exit code, only for normal exit.
    #[must_use]
    pub const fn exit_code(self) -> Option<u8> {
        if self.0 & 0x7f == 0 {
            Some((self.0 >> 8) as u8)
        } else {
            None
        }
    }

    /// Returns the exact Linux terminating signal, only for signal termination.
    #[must_use]
    pub const fn signal(self) -> Option<u8> {
        let signal = (self.0 & 0x7f) as u8;
        if signal == 0 { None } else { Some(signal) }
    }

    /// Reports the original kernel core-dump status bit without a file claim.
    #[must_use]
    pub const fn core_dumped(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// Encodes terminal data for the original one-use I/O connection.
    #[must_use]
    pub fn encode_io_terminal(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[..8].copy_from_slice(b"AOSIOE04");
        bytes[8..].copy_from_slice(&self.raw().to_be_bytes());
        bytes
    }

    /// Decodes original terminal data without authenticating the channel.
    ///
    /// # Errors
    /// Rejects partial/trailing data, unknown versions or nonterminal status.
    pub fn decode_io_terminal(bytes: &[u8]) -> Result<Self, InvalidOpenSshSessionV4> {
        if bytes.len() != 12 || bytes.get(..8) != Some(b"AOSIOE04".as_slice()) {
            return Err(InvalidOpenSshSessionV4);
        }
        Self::new(u32::from_be_bytes(
            bytes[8..].try_into().map_err(|_| InvalidOpenSshSessionV4)?,
        ))
    }
}

impl OpenSshSessionRequestV4 {
    /// Encodes exactly one bounded request without authenticating its sender.
    ///
    /// # Errors
    /// Rejects zero sequence, non-public control signal, or zero row/column.
    pub fn encode(self) -> Result<[u8; OPENSSH_SESSION_RECORD_BYTES_V4], InvalidOpenSshSessionV4> {
        if self.sequence == 0 {
            return Err(InvalidOpenSshSessionV4);
        }
        let mut bytes = [0; OPENSSH_SESSION_RECORD_BYTES_V4];
        bytes[..8].copy_from_slice(b"AOSMCT04");
        bytes[8..16].copy_from_slice(&self.sequence.to_be_bytes());
        match self.action {
            OpenSshSessionActionV4::Signal(code)
                if matches!(code, 1 | 2 | 3 | 9 | 10 | 12 | 15) =>
            {
                bytes[16] = 1;
                bytes[24] = code;
            }
            OpenSshSessionActionV4::Resize {
                rows,
                columns,
                xpixel,
                ypixel,
            } if rows != 0 && columns != 0 => {
                bytes[16] = 2;
                for (chunk, value) in bytes[24..]
                    .chunks_exact_mut(2)
                    .zip([rows, columns, xpixel, ypixel])
                {
                    chunk.copy_from_slice(&value.to_be_bytes());
                }
            }
            OpenSshSessionActionV4::Terminal => bytes[16] = 3,
            _ => return Err(InvalidOpenSshSessionV4),
        }
        Ok(bytes)
    }

    /// Decodes a byte-exact canonical request, not authorization or custody.
    ///
    /// # Errors
    /// Rejects unknown versions/actions, partial/trailing bytes or reserved data.
    pub fn decode(bytes: &[u8]) -> Result<Self, InvalidOpenSshSessionV4> {
        let bytes: &[u8; OPENSSH_SESSION_RECORD_BYTES_V4] =
            bytes.try_into().map_err(|_| InvalidOpenSshSessionV4)?;
        if &bytes[..8] != b"AOSMCT04" {
            return Err(InvalidOpenSshSessionV4);
        }
        let sequence = u64::from_be_bytes(
            bytes[8..16]
                .try_into()
                .map_err(|_| InvalidOpenSshSessionV4)?,
        );
        let field = |offset| -> Result<u16, InvalidOpenSshSessionV4> {
            Ok(u16::from_be_bytes(
                bytes[offset..offset + 2]
                    .try_into()
                    .map_err(|_| InvalidOpenSshSessionV4)?,
            ))
        };
        let action = match bytes[16] {
            1 => OpenSshSessionActionV4::Signal(bytes[24]),
            2 => OpenSshSessionActionV4::Resize {
                rows: field(24)?,
                columns: field(26)?,
                xpixel: field(28)?,
                ypixel: field(30)?,
            },
            3 => OpenSshSessionActionV4::Terminal,
            _ => return Err(InvalidOpenSshSessionV4),
        };
        let request = Self { sequence, action };
        if request.encode()?.as_slice() != bytes {
            return Err(InvalidOpenSshSessionV4);
        }
        Ok(request)
    }
}

/// Rejects malformed private session data without echoing raw control records.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("invalid original SSH session record")]
pub struct InvalidOpenSshSessionV4;

#[cfg(test)]
mod tests {
    //! Canonical shape and exact terminal classification; no authority fixture.
    use super::*;

    #[test]
    fn control_vocabulary_is_not_the_terminal_signal_vocabulary() {
        let terminal = OriginalExecutionWaitStatusV4::new(11 | 0x80).unwrap();
        assert_eq!(terminal.signal(), Some(11));
        assert!(terminal.core_dumped());
        assert!(
            OpenSshSessionRequestV4 {
                sequence: 1,
                action: OpenSshSessionActionV4::Signal(11)
            }
            .encode()
            .is_err()
        );
        for raw in [0x7f, 0xffff, 65, 128, 0x10009, 0x0109] {
            assert!(OriginalExecutionWaitStatusV4::new(raw).is_err());
        }
        assert_eq!(
            OriginalExecutionWaitStatusV4::new(17 << 8)
                .unwrap()
                .exit_code(),
            Some(17)
        );
    }

    #[test]
    fn exact_control_record_rejects_padding_partial_and_substitution() {
        let request = OpenSshSessionRequestV4 {
            sequence: 7,
            action: OpenSshSessionActionV4::Signal(15),
        };
        let bytes = request.encode().unwrap();
        assert_eq!(OpenSshSessionRequestV4::decode(&bytes).unwrap(), request);
        for length in 0..bytes.len() {
            assert!(OpenSshSessionRequestV4::decode(&bytes[..length]).is_err());
        }
        for index in [0, 17, 25, 31] {
            let mut foreign = bytes;
            foreign[index] ^= 1;
            assert!(OpenSshSessionRequestV4::decode(&foreign).is_err());
        }
    }

    #[test]
    fn terminal_replies_require_exact_original_status_and_correlation_shape() {
        let status = OriginalExecutionWaitStatusV4::new(11 | 0x80).unwrap();
        let reply = OpenSshSessionReplyV4 {
            sequence: 3,
            state: OpenSshSessionStateV4::Terminal(status),
        };
        let bytes = reply.encode().unwrap();
        assert_eq!(OpenSshSessionReplyV4::decode(&bytes).unwrap(), reply);
        assert_eq!(
            OriginalExecutionWaitStatusV4::decode_io_terminal(&status.encode_io_terminal())
                .unwrap(),
            status
        );
        for index in [0, 17, 28, 31] {
            let mut foreign = bytes;
            foreign[index] ^= 1;
            assert!(OpenSshSessionReplyV4::decode(&foreign).is_err());
        }
        for length in 0..bytes.len() {
            assert!(OpenSshSessionReplyV4::decode(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(OpenSshSessionReplyV4::decode(&trailing).is_err());
        let mut foreign = bytes;
        foreign[8..16].fill(0);
        assert!(OpenSshSessionReplyV4::decode(&foreign).is_err());
        foreign = bytes;
        foreign[16] = 2;
        assert!(OpenSshSessionReplyV4::decode(&foreign).is_err());

        let pending = OpenSshSessionReplyV4 {
            sequence: 4,
            state: OpenSshSessionStateV4::Pending,
        };
        let mut bytes = pending.encode().unwrap();
        bytes[27] = 9;
        assert!(OpenSshSessionReplyV4::decode(&bytes).is_err());
        assert!(OriginalExecutionWaitStatusV4::decode_io_terminal(b"AOSIOE04\0\0\0\x7f").is_err());
    }

    #[test]
    fn terminal_data_retains_native_signals_without_a_shared_unknown_value() {
        for signal in 1..=64 {
            for core in [0, 0x80] {
                let status = OriginalExecutionWaitStatusV4::new(signal | core).unwrap();
                let reply = OpenSshSessionReplyV4 {
                    sequence: 1,
                    state: OpenSshSessionStateV4::Terminal(status),
                };

                assert_eq!(status.signal(), Some(signal as u8));
                assert_eq!(
                    OpenSshSessionReplyV4::decode(&reply.encode().unwrap()).unwrap(),
                    reply
                );
                assert_eq!(
                    OriginalExecutionWaitStatusV4::decode_io_terminal(&status.encode_io_terminal())
                        .unwrap(),
                    status
                );
            }
        }
    }
}
