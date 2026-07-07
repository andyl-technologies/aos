//! QMP-safe snapshot tags derived from checkpoint content addresses.

use crucible::{Checkpoint, ContentHash};

/// QMP snapshot tag derived from a checkpoint content address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpSnapshotTag {
    tag: String,
}

impl QmpSnapshotTag {
    /// Derives a QMP-safe snapshot tag from a checkpoint handle.
    #[must_use]
    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Self {
        Self::from_checkpoint_content_address(checkpoint.id)
    }

    /// Derives a QMP-safe snapshot tag from a checkpoint content address.
    #[must_use]
    pub fn from_checkpoint_content_address(address: ContentHash) -> Self {
        Self {
            tag: format!("crucible-{}", lowercase_hex(&address.bytes)),
        }
    }

    /// Returns the QMP snapshot tag string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.tag
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    encoded
}
