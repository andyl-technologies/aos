//! Encodes the fixed first Root Open body as nonauthorizing historical DATA.
//!
//! ```text
//! AOSXPO01 | OpenQuery[112] | RootNonce[16] | boot[16] |
//! started:u64be | cutoff:u64be | authority-names[48] | policy-names[48] |
//! authority-NEXT:u64be | policy-NEXT:u64be | Root-profile-digest[32] |
//! Root-recipient[16] | Root-producer[16] | Root-pid:u32be |
//! Controller-pid:u32be | Controller-uid:u32be | Controller-gid:u32be
//! ```
//!
//! Seed and Ready remain untrusted correlation, even in a checksum-valid Root
//! record. No body field proves an original writer, peer, clock or current cut.

mod hello;

pub use hello::{RootHelloDataV1, ROOT_HELLO_FRAME_BYTES_V1};

use super::super::protected_names::ProtectedJournalNamesV1;
use super::{HistoryErrorV1, nonzero, reader};
use super::transport::{OPEN_BYTES, OpenQueryV1};

/// Holds the exact first Root Open body width.
pub const ROOT_OPEN_BODY_BYTES_V1: usize = 360;

/// Describes the fixed Root Open body without admitting any live invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootOpenBodyDataV1 {
    /// The complete original untrusted Controller correlation.
    pub open: OpenQueryV1,
    /// Root's original independent challenge, never renewed at a phase.
    pub root_nonce: [u8; 16],
    /// The original paired kernel sample's boot identifier.
    pub boot: [u8; 16],
    /// The original paired BOOTTIME sample in nanoseconds.
    pub started: u64,
    /// The immutable upper cutoff for this Root invocation in nanoseconds.
    pub cutoff: u64,
    /// The actual authority writer's preappend physical-name coordinates.
    pub authority_names: ProtectedJournalNamesV1,
    /// The independently held compiler-state writer's physical names.
    pub policy_names: ProtectedJournalNamesV1,
    /// The authority writer's NEXT before this record's atomic append.
    pub authority_next: u64,
    /// The compiler-state writer's unchanged original NEXT.
    pub policy_next: u64,
    /// The independently retained Root startup profile's measured digest.
    pub root_profile: [u8; 32],
    /// The recipient invocation joined to the actual RootR delivery.
    pub root_recipient: [u8; 16],
    /// The actual PID1 resource-image producer invocation.
    pub root_producer: [u8; 16],
    /// The actual selected Root process identifier.
    pub root_pid: u32,
    /// The original accepted socket creator's Controller process identifier.
    pub controller_pid: u32,
    /// The independently selected Controller user identifier.
    pub controller_uid: u32,
    /// The independently selected Controller group identifier.
    pub controller_gid: u32,
}

impl RootOpenBodyDataV1 {
    /// Decodes an exact fixed body without allocating or issuing authority.
    ///
    /// # Errors
    /// Rejects nonexact width, wrong magic, zero identities, malformed physical
    /// coordinates, invalid Open correlation or a nonincreasing cutoff.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryErrorV1> {
        let mut input = reader(bytes);
        if input.array::<8>()? != *b"AOSXPO01" {
            return Err(HistoryErrorV1::Malformed);
        }

        let value = Self {
            open: OpenQueryV1::decode(input.bytes(OPEN_BYTES)?)?,
            root_nonce: input.array()?,
            boot: input.array()?,
            started: input.u64()?,
            cutoff: input.u64()?,
            authority_names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            policy_names: ProtectedJournalNamesV1::from_bytes(input.bytes(48)?)
                .map_err(|_| HistoryErrorV1::Malformed)?,
            authority_next: input.u64()?,
            policy_next: input.u64()?,
            root_profile: input.array()?,
            root_recipient: input.array()?,
            root_producer: input.array()?,
            root_pid: input.u32()?,
            controller_pid: input.u32()?,
            controller_uid: input.u32()?,
            controller_gid: input.u32()?,
        };
        input.finish()?;

        value.validate()?;
        Ok(value)
    }

    /// Encodes the exact fixed body without allocation or authority issuance.
    ///
    /// # Errors
    /// Rejects invalid correlation/identities, physical coordinates or cutoff.
    pub fn encode(self) -> Result<[u8; ROOT_OPEN_BODY_BYTES_V1], HistoryErrorV1> {
        self.validate()?;

        let mut bytes = [0; ROOT_OPEN_BODY_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSXPO01");
        bytes[8..120].copy_from_slice(&self.open.encode()?);
        bytes[120..136].copy_from_slice(&self.root_nonce);
        bytes[136..152].copy_from_slice(&self.boot);

        bytes[152..160].copy_from_slice(&self.started.to_be_bytes());
        bytes[160..168].copy_from_slice(&self.cutoff.to_be_bytes());

        bytes[168..216].copy_from_slice(&self.authority_names.to_bytes());
        bytes[216..264].copy_from_slice(&self.policy_names.to_bytes());
        bytes[264..272].copy_from_slice(&self.authority_next.to_be_bytes());
        bytes[272..280].copy_from_slice(&self.policy_next.to_be_bytes());

        bytes[280..312].copy_from_slice(&self.root_profile);
        bytes[312..328].copy_from_slice(&self.root_recipient);
        bytes[328..344].copy_from_slice(&self.root_producer);

        bytes[344..348].copy_from_slice(&self.root_pid.to_be_bytes());
        bytes[348..352].copy_from_slice(&self.controller_pid.to_be_bytes());
        bytes[352..356].copy_from_slice(&self.controller_uid.to_be_bytes());
        bytes[356..360].copy_from_slice(&self.controller_gid.to_be_bytes());

        Ok(bytes)
    }

    fn validate(self) -> Result<(), HistoryErrorV1> {
        self.open.encode()?;
        nonzero(&self.root_nonce)?;
        nonzero(&self.boot)?;
        nonzero(&self.root_profile)?;
        nonzero(&self.root_recipient)?;
        nonzero(&self.root_producer)?;

        ProtectedJournalNamesV1::from_bytes(&self.authority_names.to_bytes())
            .map_err(|_| HistoryErrorV1::Malformed)?;
        ProtectedJournalNamesV1::from_bytes(&self.policy_names.to_bytes())
            .map_err(|_| HistoryErrorV1::Malformed)?;

        if self.cutoff <= self.started
            || self.authority_next == 0
            || self.policy_next == 0
            || self.root_pid == 0
            || self.controller_pid == 0
            || self.controller_uid == 0
            || self.controller_gid == 0
        {
            return Err(HistoryErrorV1::Malformed);
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn body() -> RootOpenBodyDataV1 {
        RootOpenBodyDataV1 {
            open: OpenQueryV1 {
                controller_nonce: [1; 16],
                lane: [2; 16],
                seed: [3; 32],
                ready: [4; 32]
            },
            root_nonce: [5; 16],
            boot: [6; 16],
            started: 100,
            cutoff: 200,
            authority_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            policy_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (7, 8), (9, 10)),
            authority_next: 11,
            policy_next: 1,
            root_profile: [12; 32],
            root_recipient: [13; 16],
            root_producer: [14; 16],
            root_pid: 15,
            controller_pid: 16,
            controller_uid: 17,
            controller_gid: 18,
        }
    }

    #[test]
    fn fixed_root_open_body_preserves_all_original_coordinates() {
        let original = body();
        let bytes = original.encode().unwrap();

        assert_eq!(bytes.len(), 360);
        assert_eq!(RootOpenBodyDataV1::decode(&bytes).unwrap(), original);
        assert!(RootOpenBodyDataV1::decode(&bytes[..359]).is_err());

        let mut changed = bytes;
        changed[120..136].fill(0);
        assert!(RootOpenBodyDataV1::decode(&changed).is_err());

        let mut changed = bytes;
        changed[160..168].copy_from_slice(&original.started.to_be_bytes());
        assert!(RootOpenBodyDataV1::decode(&changed).is_err());

        let mut changed = bytes;
        changed[216..264].fill(0);
        assert!(RootOpenBodyDataV1::decode(&changed).is_err());
    }
}
