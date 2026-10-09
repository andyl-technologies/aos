use super::ProtectedHistoryDataErrorV1;

/// Identifies the three fixed physical names shared by a Source writer and signer view.
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

    pub const fn directory(self) -> (u64, u64) {
        self.directory
    }

    pub const fn journal(self) -> (u64, u64) {
        self.journal
    }

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
