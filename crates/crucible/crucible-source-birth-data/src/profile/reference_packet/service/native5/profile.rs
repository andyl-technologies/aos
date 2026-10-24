//! Selects a closed byte representation and distinct encoded reservation bounds.
//!
//! These portable values never install a codec or grant capture/restoration.
//! The actual service and source factory bind the same immutable selection to
//! original kernel, registrar, policy and storage owners before publication.

use super::*;

/// Selects the original array, compact-byte or complete owning edition.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "encoding", rename_all = "snake_case", deny_unknown_fields)]
pub enum PacketNative5CaptureProfile {
    /// Preserves the existing array codec and shared protocol bound.
    #[default]
    OriginalArrays6,
    /// Selects compact seven with independently charged original allocations.
    CompactBytes7 {
        /// Bounds the native pending-Capture protocol body before publication.
        native_before_protocol_bytes: U64,
        /// Bounds the native protocol body after the complete literal suffix.
        native_after_protocol_bytes: U64,
        /// Bounds the same original host's fully settled protocol body.
        host_protocol_bytes: U64,
    },
    /// Selects complete owning protocol eleven with independently charged banks.
    ///
    /// This data variant cannot activate the installed serializer or issuer.
    OwnedProtocol11 {
        /// Bounds the original native pending-Capture owning protocol body.
        native_before_protocol_bytes: U64,
        /// Bounds the native owning protocol body after the complete suffix.
        native_after_protocol_bytes: U64,
        /// Bounds the original host owning protocol body and retained histories.
        host_protocol_bytes: U64,
    },
}

impl PacketNative5CaptureProfile {
    /// Identifies the original layout for backward-compatible serialization.
    pub fn is_original_arrays(&self) -> bool {
        matches!(self, Self::OriginalArrays6)
    }

    /// Checks finite positive selected bounds without allocating or installing.
    ///
    /// # Errors
    /// Refuses zero or greater-than-512-MiB independently selected bounds.
    pub fn validate(&self) -> Result<(), ProviderError> {
        if let Self::CompactBytes7 {
            native_before_protocol_bytes,
            native_after_protocol_bytes,
            host_protocol_bytes,
        }
        | Self::OwnedProtocol11 {
            native_before_protocol_bytes,
            native_after_protocol_bytes,
            host_protocol_bytes,
        } = self
        {
            for bytes in [
                native_before_protocol_bytes,
                native_after_protocol_bytes,
                host_protocol_bytes,
            ] {
                if bytes.get() == 0 || bytes.get() > 512 * 1024 * 1024 {
                    return Err(ProviderError::ResourceExhausted(
                        "native5 compact protocol bounds",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns the selected native-before bound without asserting allocation.
    pub fn native_before_bytes(&self, storage: &PacketNative5StorageLimits) -> U64 {
        match self {
            Self::OriginalArrays6 => storage.protocol_snapshot_bytes,
            Self::CompactBytes7 {
                native_before_protocol_bytes,
                ..
            }
            | Self::OwnedProtocol11 {
                native_before_protocol_bytes,
                ..
            } => *native_before_protocol_bytes,
        }
    }

    /// Returns the distinct native-after bound without asserting allocation.
    pub fn native_after_bytes(&self, storage: &PacketNative5StorageLimits) -> U64 {
        match self {
            Self::OriginalArrays6 => storage.protocol_snapshot_bytes,
            Self::CompactBytes7 {
                native_after_protocol_bytes,
                ..
            }
            | Self::OwnedProtocol11 {
                native_after_protocol_bytes,
                ..
            } => *native_after_protocol_bytes,
        }
    }

    /// Returns the selected settled-host bound without asserting allocation.
    pub fn host_bytes(&self, storage: &PacketNative5StorageLimits) -> U64 {
        match self {
            Self::OriginalArrays6 => storage.protocol_snapshot_bytes,
            Self::CompactBytes7 {
                host_protocol_bytes,
                ..
            }
            | Self::OwnedProtocol11 {
                host_protocol_bytes,
                ..
            } => *host_protocol_bytes,
        }
    }
}
