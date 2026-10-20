//! Owns historical directory, journal and lock device/inode DATA.
//!
//! These six numbers describe physical names; they retain no descriptors or
//! lock/currentness proof. Native identity sampling and protected custody remain
//! with the physical owner. Unchecked assembly preserves historical claims;
//! byte decoding rejects zero identities in the established order.
//!
//! ```text
//! directory(device:u64be, inode:u64be) |
//! journal(device:u64be, inode:u64be) | lock(device:u64be, inode:u64be)
//! session-completion = names48 | next-sequence:u64be | held-file-bytes:u64be
//! ```

use super::ProtectedHistoryDataErrorV1;

/// Describes historical directory, journal and lock device/inode pairs.
///
/// Device/inode equality is necessary for a same-cut proof, but does not by
/// itself prove a held flock or authorize a policy effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedJournalNamesV1 {
    directory: (u64, u64),
    journal: (u64, u64),
    lock: (u64, u64),
}

impl ProtectedJournalNamesV1 {
    /// Assembles unchecked historical fields without validating custody or joins.
    pub const fn from_historical_fields(
        directory: (u64, u64),
        journal: (u64, u64),
        lock: (u64, u64),
    ) -> Self {
        Self {
            directory,
            journal,
            lock,
        }
    }

    /// Returns the historical directory device/inode pair.
    pub const fn directory(self) -> (u64, u64) {
        self.directory
    }

    /// Returns the historical journal device/inode pair.
    pub const fn journal(self) -> (u64, u64) {
        self.journal
    }

    /// Returns the historical lock device/inode pair.
    pub const fn lock(self) -> (u64, u64) {
        self.lock
    }

    /// Encodes the directory, journal, and lock device/inode pairs.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 48] {
        let mut bytes = [0; 48];
        for (index, (device, inode)) in [self.directory, self.journal, self.lock]
            .into_iter()
            .enumerate()
        {
            let offset = index * 16;
            bytes[offset..offset + 8].copy_from_slice(&device.to_be_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&inode.to_be_bytes());
        }
        bytes
    }

    /// Decodes nonzero physical-name pairs from an untrusted claim.
    ///
    /// # Errors
    ///
    /// Rejects a truncated or empty physical identity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != 48 {
            return Err(ProtectedHistoryDataErrorV1::Malformed);
        }
        let mut pairs = [(0, 0); 3];
        for (index, pair) in pairs.iter_mut().enumerate() {
            let offset = index * 16;
            let device = u64::from_be_bytes(
                bytes[offset..offset + 8]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            );
            let inode = u64::from_be_bytes(
                bytes[offset + 8..offset + 16]
                    .try_into()
                    .map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?,
            );
            if device == 0 || inode == 0 {
                return Err(ProtectedHistoryDataErrorV1::Malformed);
            }
            *pair = (device, inode);
        }
        Ok(Self {
            directory: pairs[0],
            journal: pairs[1],
            lock: pairs[2],
        })
    }
}

/// Describes the established 64-byte protected Session completion position.
///
/// This passive format contains physical names and a whole-file boundary. It
/// contains no transaction identity or COMMIT digest and creates no native
/// custody, healthy writer, completed Session, query loan or effect authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionCompletionPositionDataV4 {
    names: ProtectedJournalNamesV1,
    next: u64,
    end: u64,
}

impl SessionCompletionPositionDataV4 {
    /// Assembles checked passive position DATA from its actual native supplier.
    ///
    /// # Errors
    /// Rejects a zero physical name, next sequence or held file length.
    pub fn from_native_data_v4(names: ProtectedJournalNamesV1, next: u64, end: u64)
        -> Result<Self, ProtectedHistoryDataErrorV1> {
        ProtectedJournalNamesV1::from_bytes(&names.to_bytes())?;
        if next == 0 || end == 0 { return Err(ProtectedHistoryDataErrorV1::Malformed); }
        Ok(Self { names, next, end })
    }

    /// Returns the six historical native name coordinates.
    #[must_use]
    pub const fn names_v4(self) -> ProtectedJournalNamesV1 { self.names }

    /// Returns the next sequence after the completed receipt append.
    #[must_use]
    pub const fn next_sequence_v4(self) -> u64 { self.next }

    /// Returns the exact held file length after that receipt append.
    #[must_use]
    pub const fn held_bytes_v4(self) -> u64 { self.end }

    /// Encodes the unchanged names48/next8/held-length8 wire layout.
    #[must_use]
    pub fn encode_v4(self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..48].copy_from_slice(&self.names.to_bytes());
        bytes[48..56].copy_from_slice(&self.next.to_be_bytes());
        bytes[56..].copy_from_slice(&self.end.to_be_bytes());
        bytes
    }

    /// Decodes only the complete established Session position layout.
    ///
    /// # Errors
    /// Rejects another width or a zero physical name, sequence or file length.
    pub fn decode_v4(bytes: &[u8]) -> Result<Self, ProtectedHistoryDataErrorV1> {
        if bytes.len() != 64 { return Err(ProtectedHistoryDataErrorV1::Malformed); }
        Self::from_native_data_v4(ProtectedJournalNamesV1::from_bytes(&bytes[..48])?,
            u64::from_be_bytes(bytes[48..56].try_into().map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?),
            u64::from_be_bytes(bytes[56..].try_into().map_err(|_| ProtectedHistoryDataErrorV1::Malformed)?))
    }
}
