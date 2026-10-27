//! Defines the separate seven-bank Native17 roster without widening transfer12.
//!
//! ```text
//! [native_protocol,native_control,native_anchor,owner_state,journal,
//!  normalization,semantic_spend]
//! ```
//!
//! Baseline Blob bodies remain unchanged. The genuine installed17 native input
//! lease selects this exact ordered roster; a portable role label grants no
//! bank, current original, allocator credit, consumption or installation right.

use super::*;

/// Identifies an exact bank in the separately authenticated Native17 input lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNativeImport18InputRole {
    /// Retains the actual complete native-after graph.
    NativeProtocol,
    /// Retains the actual complete modeled Control17 object.
    NativeControl,
    /// Retains the unchanged captured-cut anchor.
    NativeAnchor,
    /// Retains Snapshot17 with the actual embedded native-before graph.
    OwnerState,
    /// Retains the exact completed final Source Journal17.
    Journal,
    /// Retains the distinct actual fresh-target normalization body.
    Normalization,
    /// Retains real logical used IDs and pending input/ACK associations.
    SemanticSpend,
}

impl PacketNativeImport18InputRole {
    /// Lists the exact native receive and independently retained SDK upload order.
    pub const ALL: [Self; 7] = [
        Self::NativeProtocol,
        Self::NativeControl,
        Self::NativeAnchor,
        Self::OwnerState,
        Self::Journal,
        Self::Normalization,
        Self::SemanticSpend,
    ];

    /// Returns the explicit wire ordinal without depending on Rust enum layout.
    pub const fn ordinal_data(self) -> usize {
        match self {
            Self::NativeProtocol => 0,
            Self::NativeControl => 1,
            Self::NativeAnchor => 2,
            Self::OwnerState => 3,
            Self::Journal => 4,
            Self::Normalization => 5,
            Self::SemanticSpend => 6,
        }
    }

    /// Borrows the exact reference from the complete already-joined input DATA.
    ///
    /// The issuer separately authenticates the full Prepare and binding against
    /// its actual private token. This projection performs no validation, parser,
    /// allocation, reference substitution or native custody transition.
    pub fn reference_data<'a>(
        self,
        request: &'a PacketCompleteRestorePrepareRequest,
        binding: &'a PacketNativeImport18Binding,
    ) -> &'a ContentRef {
        match self {
            Self::NativeProtocol => &request.native_protocol,
            Self::NativeControl => &request.native_control,
            Self::NativeAnchor => &request.native_anchor,
            Self::OwnerState => &request.restoration.owner_state,
            Self::Journal => &request.restoration.journal,
            Self::Normalization => &binding.normalization,
            Self::SemanticSpend => &binding.semantic_spend,
        }
    }

    /// Returns the original independent role ceiling as DATA, without admission.
    pub const fn maximum_bytes_data(self, binding: &PacketNativeImport18Binding) -> U64 {
        match self {
            Self::NativeProtocol => binding.limits.role_maximums[1],
            Self::NativeControl => binding.limits.role_maximums[2],
            Self::NativeAnchor => binding.limits.role_maximums[3],
            Self::OwnerState => binding.limits.role_maximums[0],
            Self::Journal => binding.limits.role_maximums[4],
            Self::Normalization => binding.normalization_maximum,
            Self::SemanticSpend => binding.semantic_spend_maximum,
        }
    }
}

/// Hashes all seven exact references and role ceilings in the native receive order.
///
/// The independent binding digest also authenticates the complete original
/// Prepare allocation. This roster never treats the older six-bank digest as
/// a seven-bank receipt or creates an input lease.
///
/// # Errors
/// Refuses binding validation or independently admitted canonical construction.
pub fn native_import18_input_roster_digest_data(
    request: &PacketCompleteRestorePrepareRequest,
    binding: &PacketNativeImport18Binding,
) -> Result<Bytes, ProviderError> {
    binding.validate_data()?;
    let rows = PacketNativeImport18InputRole::ALL.map(|role| {
        (
            role,
            role.reference_data(request, binding),
            role.maximum_bytes_data(binding),
        )
    });
    let bytes = bounded(
        &rows,
        super::super::transfer::MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
    )?;
    let mut hash =
        blake3::Hasher::new_derive_key("source-owned.packet-native-import-input-roster/18");
    hash.update(&bytes);
    Ok(Bytes::new(hash.finalize().as_bytes().to_vec()))
}
