//! Closed, bounded held Storage output readback session.
//!
//! Every packet is a canonical fixed-size seqpacket. The proof describes one
//! zero-byte AOSEOR03 row while Storage retains its writer; settle and abort only end the
//! read-only flight. Neither outcome grants ReserveOutput or a Host effect.
//!
//! ```text
//! begin    = AOSEOHS1 | version:u16be | reserved:u16be | nonce[32]
//!            | deadline:u64be | execution[16] | create[16] | AOSEOR03-digest[32]
//!            | head:u64be | assignment[32] | claim[32]
//!            | admitted:u64be | stdout:u64be | stderr:u64be
//! proof    = AOSEOHP1 | version:u16be | reserved:u16be
//!            | canonical ExistingOutputResponseV1[236]
//! terminal = AOSEOHT1 | version:u16be | reserved:u16be | mode:u8 | zero[7]
//!            | nonce[32] | begin-digest[32] | proof-digest[32]
//!            | head:u64be | caller-settlement-digest[32]
//! ack      = AOSEOHA1 | version:u16be | reserved:u16be | mode:u8 | zero[7]
//!            | nonce[32] | terminal-digest[32] | proof-digest[32] | head:u64be
//! ```

use sha2::{Digest as _, Sha256};

use crate::storage_existing_output::{ExistingOutputResponseV1, RESPONSE_BYTES};

const BEGIN_MAGIC: &[u8; 8] = b"AOSEOHS1";
const PROOF_MAGIC: &[u8; 8] = b"AOSEOHP1";
const TERMINAL_MAGIC: &[u8; 8] = b"AOSEOHT1";
const ACK_MAGIC: &[u8; 8] = b"AOSEOHA1";
const VERSION: [u8; 2] = 1_u16.to_be_bytes();
const BEGIN_DOMAIN: &[u8] = b"aos.sandbox.storage.held-output-begin.v1\0";
const PROOF_DOMAIN: &[u8] = b"aos.sandbox.storage.held-output-proof.v1\0";
const TERMINAL_DOMAIN: &[u8] = b"aos.sandbox.storage.held-output-terminal.v1\0";

/// Exact held-session begin size.
pub const BEGIN_BYTES: usize = 212;
/// Exact held-session proof size.
pub const PROOF_BYTES: usize = 12 + RESPONSE_BYTES;
/// Exact held-session terminal size.
pub const TERMINAL_BYTES: usize = 156;
/// Exact held-session acknowledgement size.
pub const ACK_BYTES: usize = 124;

/// Rejects a malformed or mismatched held-output packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Storage held-output packet is invalid")]
pub struct HeldOutputSessionProtocolErrorV1;

/// Selects an exact retained row and previously observed Storage head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeldOutputBeginV1 {
    /// Fresh nonzero challenge for this connection.
    pub nonce: [u8; 32],
    /// Absolute kernel boottime deadline for the complete flight.
    pub deadline_boottime_nanoseconds: u64,
    /// Execution identity.
    pub execution: [u8; 16],
    /// Accepted Create identity.
    pub create: [u8; 16],
    /// Exact AOSEOR03 record digest.
    pub record_digest: [u8; 32],
    /// Exact prior Storage journal head.
    pub expected_journal_sequence: u64,
    /// Retained assignment digest.
    pub assignment_digest: [u8; 32],
    /// Retained v2 output claim digest.
    pub claim_digest: [u8; 32],
    /// Logical admitted byte count.
    pub admitted_bytes: u64,
    /// Maximum stdout capture bytes.
    pub maximum_stdout_bytes: u64,
    /// Maximum stderr capture bytes.
    pub maximum_stderr_bytes: u64,
}

/// Distinguishes caller settlement from an explicit abort.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeldOutputTerminalModeV1 {
    /// The caller finished its own cut; Storage still grants no effect.
    Settle,
    /// The caller abandoned its own cut.
    Abort,
}

impl HeldOutputTerminalModeV1 {
    const fn byte(self) -> u8 {
        match self {
            Self::Settle => 1,
            Self::Abort => 2,
        }
    }

    fn from_byte(byte: u8) -> Result<Self, HeldOutputSessionProtocolErrorV1> {
        match byte {
            1 => Ok(Self::Settle),
            2 => Ok(Self::Abort),
            _ => Err(HeldOutputSessionProtocolErrorV1),
        }
    }
}

/// Storage's exact row/head proof, valid only during the live held flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeldOutputProofV1 {
    /// Canonical protected-row readback bound to the held begin digest.
    pub row: ExistingOutputResponseV1,
}

/// Caller terminal frame that cannot authorize Storage mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeldOutputTerminalV1 {
    /// Caller disposition of its own read-only cut.
    pub mode: HeldOutputTerminalModeV1,
    /// Original begin nonce.
    pub nonce: [u8; 32],
    /// Digest of the complete canonical begin packet.
    pub begin_digest: [u8; 32],
    /// Digest of Storage's exact canonical proof packet.
    pub proof_digest: [u8; 32],
    /// Original held Storage journal head.
    pub journal_sequence: u64,
    /// Nonzero caller cut digest for Settle, zero for Abort.
    pub caller_settlement_digest: [u8; 32],
}

/// Read-only acknowledgement that Storage accepted the terminal frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeldOutputAckV1 {
    /// Accepted caller disposition.
    pub mode: HeldOutputTerminalModeV1,
    /// Original begin nonce.
    pub nonce: [u8; 32],
    /// Digest of the exact caller terminal packet.
    pub terminal_digest: [u8; 32],
    /// Digest of Storage's exact proof packet.
    pub proof_digest: [u8; 32],
    /// Held Storage journal head.
    pub journal_sequence: u64,
}

fn take<const N: usize>(
    bytes: &[u8],
    start: usize,
) -> Result<[u8; N], HeldOutputSessionProtocolErrorV1> {
    bytes
        .get(start..start + N)
        .ok_or(HeldOutputSessionProtocolErrorV1)?
        .try_into()
        .map_err(|_| HeldOutputSessionProtocolErrorV1)
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize()
        .into()
}

fn valid_header(bytes: &[u8], magic: &[u8; 8], length: usize) -> bool {
    bytes.len() == length
        && bytes.get(..8) == Some(magic)
        && bytes.get(8..10) == Some(VERSION.as_slice())
        && bytes.get(10..12) == Some([0; 2].as_slice())
}

impl HeldOutputBeginV1 {
    /// Encodes a canonical, exact held-row request.
    ///
    /// # Errors
    ///
    /// Rejects zero identities, deadline, or head, and any capture byte claim.
    pub fn encode(self) -> Result<[u8; BEGIN_BYTES], HeldOutputSessionProtocolErrorV1> {
        if self.nonce == [0; 32]
            || self.deadline_boottime_nanoseconds == 0
            || self.execution == [0; 16]
            || self.create == [0; 16]
            || self.record_digest == [0; 32]
            || self.expected_journal_sequence == 0
            || self.assignment_digest == [0; 32]
            || self.claim_digest == [0; 32]
            || self.admitted_bytes != 0
            || self.maximum_stdout_bytes != 0
            || self.maximum_stderr_bytes != 0
        {
            return Err(HeldOutputSessionProtocolErrorV1);
        }

        let mut bytes = [0; BEGIN_BYTES];
        bytes[..8].copy_from_slice(BEGIN_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION);
        bytes[12..44].copy_from_slice(&self.nonce);
        bytes[44..52].copy_from_slice(&self.deadline_boottime_nanoseconds.to_be_bytes());
        bytes[52..68].copy_from_slice(&self.execution);
        bytes[68..84].copy_from_slice(&self.create);
        bytes[84..116].copy_from_slice(&self.record_digest);
        bytes[116..124].copy_from_slice(&self.expected_journal_sequence.to_be_bytes());
        bytes[124..156].copy_from_slice(&self.assignment_digest);
        bytes[156..188].copy_from_slice(&self.claim_digest);
        bytes[188..196].copy_from_slice(&self.admitted_bytes.to_be_bytes());
        bytes[196..204].copy_from_slice(&self.maximum_stdout_bytes.to_be_bytes());
        bytes[204..212].copy_from_slice(&self.maximum_stderr_bytes.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes exactly one canonical begin packet.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, version, reserved bits, or malformed fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, HeldOutputSessionProtocolErrorV1> {
        if !valid_header(bytes, BEGIN_MAGIC, BEGIN_BYTES) {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        let begin = Self {
            nonce: take(bytes, 12)?,
            deadline_boottime_nanoseconds: u64::from_be_bytes(take(bytes, 44)?),
            execution: take(bytes, 52)?,
            create: take(bytes, 68)?,
            record_digest: take(bytes, 84)?,
            expected_journal_sequence: u64::from_be_bytes(take(bytes, 116)?),
            assignment_digest: take(bytes, 124)?,
            claim_digest: take(bytes, 156)?,
            admitted_bytes: u64::from_be_bytes(take(bytes, 188)?),
            maximum_stdout_bytes: u64::from_be_bytes(take(bytes, 196)?),
            maximum_stderr_bytes: u64::from_be_bytes(take(bytes, 204)?),
        };
        if begin.encode()?.as_slice() != bytes {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        Ok(begin)
    }

    /// Returns the domain-separated digest of this canonical begin packet.
    ///
    /// # Errors
    ///
    /// Rejects malformed begin fields.
    pub fn digest(self) -> Result<[u8; 32], HeldOutputSessionProtocolErrorV1> {
        Ok(digest(BEGIN_DOMAIN, &self.encode()?))
    }
}

impl HeldOutputProofV1 {
    /// Encodes Storage's canonical row proof.
    ///
    /// # Errors
    ///
    /// Rejects a malformed protected-row response.
    pub fn encode(self) -> Result<[u8; PROOF_BYTES], HeldOutputSessionProtocolErrorV1> {
        let mut bytes = [0; PROOF_BYTES];
        bytes[..8].copy_from_slice(PROOF_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION);
        bytes[12..].copy_from_slice(
            &self
                .row
                .encode()
                .map_err(|_| HeldOutputSessionProtocolErrorV1)?,
        );
        Ok(bytes)
    }

    /// Decodes exactly one canonical Storage proof.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, version, reserved bits, or malformed row fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, HeldOutputSessionProtocolErrorV1> {
        if !valid_header(bytes, PROOF_MAGIC, PROOF_BYTES) {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        let proof = Self {
            row: ExistingOutputResponseV1::decode(&bytes[12..])
                .map_err(|_| HeldOutputSessionProtocolErrorV1)?,
        };
        if proof.encode()?.as_slice() != bytes {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        Ok(proof)
    }

    /// Checks every accepted-row field against the exact caller challenge.
    ///
    /// # Errors
    ///
    /// Rejects any stale, swapped, or differently challenged row or head.
    pub fn verify_begin(
        self,
        begin: HeldOutputBeginV1,
    ) -> Result<(), HeldOutputSessionProtocolErrorV1> {
        if self.row.nonce != begin.nonce
            || self.row.request_digest != begin.digest()?
            || self.row.execution != begin.execution
            || self.row.create != begin.create
            || self.row.assignment_digest != begin.assignment_digest
            || self.row.claim_digest != begin.claim_digest
            || self.row.record_digest != begin.record_digest
            || self.row.admitted_bytes != begin.admitted_bytes
            || self.row.maximum_stdout_bytes != begin.maximum_stdout_bytes
            || self.row.maximum_stderr_bytes != begin.maximum_stderr_bytes
            || self.row.journal_sequence != begin.expected_journal_sequence
        {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        Ok(())
    }

    /// Returns the domain-separated digest of this exact proof packet.
    ///
    /// # Errors
    ///
    /// Rejects malformed protected-row fields.
    pub fn digest(self) -> Result<[u8; 32], HeldOutputSessionProtocolErrorV1> {
        Ok(digest(PROOF_DOMAIN, &self.encode()?))
    }
}

impl HeldOutputTerminalV1 {
    /// Constructs a terminal bound to one verified held proof.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched proof or invalid settle/abort digest.
    pub fn new(
        begin: HeldOutputBeginV1,
        proof: HeldOutputProofV1,
        mode: HeldOutputTerminalModeV1,
        caller_settlement_digest: [u8; 32],
    ) -> Result<Self, HeldOutputSessionProtocolErrorV1> {
        proof.verify_begin(begin)?;
        let terminal = Self {
            mode,
            nonce: begin.nonce,
            begin_digest: begin.digest()?,
            proof_digest: proof.digest()?,
            journal_sequence: proof.row.journal_sequence,
            caller_settlement_digest,
        };
        terminal.encode()?;
        Ok(terminal)
    }

    /// Encodes one canonical caller disposition.
    ///
    /// # Errors
    ///
    /// Rejects missing bindings or a nonzero Abort/zero Settle digest.
    pub fn encode(self) -> Result<[u8; TERMINAL_BYTES], HeldOutputSessionProtocolErrorV1> {
        if self.nonce == [0; 32]
            || self.begin_digest == [0; 32]
            || self.proof_digest == [0; 32]
            || self.journal_sequence == 0
            || (self.mode == HeldOutputTerminalModeV1::Settle
                && self.caller_settlement_digest == [0; 32])
            || (self.mode == HeldOutputTerminalModeV1::Abort
                && self.caller_settlement_digest != [0; 32])
        {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        let mut bytes = [0; TERMINAL_BYTES];
        bytes[..8].copy_from_slice(TERMINAL_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION);
        bytes[12] = self.mode.byte();
        bytes[20..52].copy_from_slice(&self.nonce);
        bytes[52..84].copy_from_slice(&self.begin_digest);
        bytes[84..116].copy_from_slice(&self.proof_digest);
        bytes[116..124].copy_from_slice(&self.journal_sequence.to_be_bytes());
        bytes[124..156].copy_from_slice(&self.caller_settlement_digest);
        Ok(bytes)
    }

    /// Decodes exactly one canonical terminal frame.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, version, reserved bytes, or disposition fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, HeldOutputSessionProtocolErrorV1> {
        if !valid_header(bytes, TERMINAL_MAGIC, TERMINAL_BYTES) || bytes[13..20] != [0; 7] {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        let terminal = Self {
            mode: HeldOutputTerminalModeV1::from_byte(bytes[12])?,
            nonce: take(bytes, 20)?,
            begin_digest: take(bytes, 52)?,
            proof_digest: take(bytes, 84)?,
            journal_sequence: u64::from_be_bytes(take(bytes, 116)?),
            caller_settlement_digest: take(bytes, 124)?,
        };
        if terminal.encode()?.as_slice() != bytes {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        Ok(terminal)
    }

    /// Verifies this terminal against the live begin and Storage proof.
    ///
    /// # Errors
    ///
    /// Rejects a terminal replayed from a different row, head, or challenge.
    pub fn verify_proof(
        self,
        begin: HeldOutputBeginV1,
        proof: HeldOutputProofV1,
    ) -> Result<(), HeldOutputSessionProtocolErrorV1> {
        proof.verify_begin(begin)?;
        if self.nonce != begin.nonce
            || self.begin_digest != begin.digest()?
            || self.proof_digest != proof.digest()?
            || self.journal_sequence != proof.row.journal_sequence
        {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        self.encode()?;
        Ok(())
    }

    /// Returns the domain-separated digest of this terminal packet.
    ///
    /// # Errors
    ///
    /// Rejects malformed terminal fields.
    pub fn digest(self) -> Result<[u8; 32], HeldOutputSessionProtocolErrorV1> {
        Ok(digest(TERMINAL_DOMAIN, &self.encode()?))
    }
}

impl HeldOutputAckV1 {
    /// Constructs the read-only acknowledgement of one verified terminal.
    ///
    /// # Errors
    ///
    /// Rejects a terminal not bound to the live held proof.
    pub fn new(
        begin: HeldOutputBeginV1,
        proof: HeldOutputProofV1,
        terminal: HeldOutputTerminalV1,
    ) -> Result<Self, HeldOutputSessionProtocolErrorV1> {
        terminal.verify_proof(begin, proof)?;
        Ok(Self {
            mode: terminal.mode,
            nonce: begin.nonce,
            terminal_digest: terminal.digest()?,
            proof_digest: proof.digest()?,
            journal_sequence: proof.row.journal_sequence,
        })
    }

    /// Encodes the exact terminal acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects absent bindings or an invalid journal head.
    pub fn encode(self) -> Result<[u8; ACK_BYTES], HeldOutputSessionProtocolErrorV1> {
        if self.nonce == [0; 32]
            || self.terminal_digest == [0; 32]
            || self.proof_digest == [0; 32]
            || self.journal_sequence == 0
        {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        let mut bytes = [0; ACK_BYTES];
        bytes[..8].copy_from_slice(ACK_MAGIC);
        bytes[8..10].copy_from_slice(&VERSION);
        bytes[12] = self.mode.byte();
        bytes[20..52].copy_from_slice(&self.nonce);
        bytes[52..84].copy_from_slice(&self.terminal_digest);
        bytes[84..116].copy_from_slice(&self.proof_digest);
        bytes[116..124].copy_from_slice(&self.journal_sequence.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes exactly one canonical acknowledgement.
    ///
    /// # Errors
    ///
    /// Rejects wrong length, version, reserved bytes, or absent bindings.
    pub fn decode(bytes: &[u8]) -> Result<Self, HeldOutputSessionProtocolErrorV1> {
        if !valid_header(bytes, ACK_MAGIC, ACK_BYTES) || bytes[13..20] != [0; 7] {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        let ack = Self {
            mode: HeldOutputTerminalModeV1::from_byte(bytes[12])?,
            nonce: take(bytes, 20)?,
            terminal_digest: take(bytes, 52)?,
            proof_digest: take(bytes, 84)?,
            journal_sequence: u64::from_be_bytes(take(bytes, 116)?),
        };
        if ack.encode()?.as_slice() != bytes {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        Ok(ack)
    }

    /// Checks this acknowledgement against the exact caller terminal.
    ///
    /// # Errors
    ///
    /// Rejects a swapped or replayed acknowledgement.
    pub fn verify_terminal(
        self,
        begin: HeldOutputBeginV1,
        proof: HeldOutputProofV1,
        terminal: HeldOutputTerminalV1,
    ) -> Result<(), HeldOutputSessionProtocolErrorV1> {
        terminal.verify_proof(begin, proof)?;
        if self.mode != terminal.mode
            || self.nonce != begin.nonce
            || self.terminal_digest != terminal.digest()?
            || self.proof_digest != proof.digest()?
            || self.journal_sequence != proof.row.journal_sequence
        {
            return Err(HeldOutputSessionProtocolErrorV1);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begin() -> HeldOutputBeginV1 {
        HeldOutputBeginV1 {
            nonce: [1; 32],
            deadline_boottime_nanoseconds: 99,
            execution: [2; 16],
            create: [3; 16],
            record_digest: [4; 32],
            expected_journal_sequence: 7,
            assignment_digest: [5; 32],
            claim_digest: [6; 32],
            admitted_bytes: 0,
            maximum_stdout_bytes: 0,
            maximum_stderr_bytes: 0,
        }
    }

    fn proof(begin: HeldOutputBeginV1) -> HeldOutputProofV1 {
        HeldOutputProofV1 {
            row: ExistingOutputResponseV1 {
                nonce: begin.nonce,
                request_digest: begin.digest().unwrap(),
                execution: begin.execution,
                create: begin.create,
                assignment_digest: begin.assignment_digest,
                claim_digest: begin.claim_digest,
                record_digest: begin.record_digest,
                admitted_bytes: begin.admitted_bytes,
                maximum_stdout_bytes: begin.maximum_stdout_bytes,
                maximum_stderr_bytes: begin.maximum_stderr_bytes,
                journal_sequence: begin.expected_journal_sequence,
            },
        }
    }

    #[test]
    fn exact_zero_byte_session_round_trips_both_terminals() {
        let begin = begin();
        let proof = proof(begin);
        assert_eq!(
            HeldOutputBeginV1::decode(&begin.encode().unwrap()).unwrap(),
            begin
        );
        assert_eq!(
            HeldOutputProofV1::decode(&proof.encode().unwrap()).unwrap(),
            proof
        );
        proof.verify_begin(begin).unwrap();

        for (mode, settlement) in [
            (HeldOutputTerminalModeV1::Settle, [7; 32]),
            (HeldOutputTerminalModeV1::Abort, [0; 32]),
        ] {
            let terminal = HeldOutputTerminalV1::new(begin, proof, mode, settlement).unwrap();
            let decoded = HeldOutputTerminalV1::decode(&terminal.encode().unwrap()).unwrap();
            decoded.verify_proof(begin, proof).unwrap();
            let ack = HeldOutputAckV1::new(begin, proof, terminal).unwrap();
            let decoded_ack = HeldOutputAckV1::decode(&ack.encode().unwrap()).unwrap();
            decoded_ack.verify_terminal(begin, proof, terminal).unwrap();
        }
    }

    #[test]
    fn replayed_or_mutated_begin_proof_terminal_and_ack_fail_closed() {
        let begin = begin();
        let proof = proof(begin);
        let terminal =
            HeldOutputTerminalV1::new(begin, proof, HeldOutputTerminalModeV1::Settle, [7; 32])
                .unwrap();
        let ack = HeldOutputAckV1::new(begin, proof, terminal).unwrap();

        let mut stale = begin;
        stale.nonce = [9; 32];
        assert!(proof.verify_begin(stale).is_err());
        assert!(terminal.verify_proof(stale, proof).is_err());
        assert!(ack.verify_terminal(stale, proof, terminal).is_err());
        stale = begin;
        stale.expected_journal_sequence += 1;
        assert!(proof.verify_begin(stale).is_err());
        let mut swapped = proof;
        swapped.row.claim_digest = [8; 32];
        assert!(swapped.verify_begin(begin).is_err());
        assert!(terminal.verify_proof(begin, swapped).is_err());

        let mut bytes = begin.encode().unwrap();
        bytes[10] = 1;
        assert!(HeldOutputBeginV1::decode(&bytes).is_err());
        let mut bytes = terminal.encode().unwrap();
        bytes[13] = 1;
        assert!(HeldOutputTerminalV1::decode(&bytes).is_err());
        let mut bytes = ack.encode().unwrap();
        bytes[8] = 2;
        assert!(HeldOutputAckV1::decode(&bytes).is_err());
        assert!(
            HeldOutputTerminalV1::new(begin, proof, HeldOutputTerminalModeV1::Abort, [7; 32])
                .is_err()
        );
        assert!(
            HeldOutputTerminalV1::new(begin, proof, HeldOutputTerminalModeV1::Settle, [0; 32])
                .is_err()
        );
        let mut capture = begin;
        capture.admitted_bytes = 1;
        capture.maximum_stdout_bytes = 1;
        assert!(capture.encode().is_err());
    }
}
