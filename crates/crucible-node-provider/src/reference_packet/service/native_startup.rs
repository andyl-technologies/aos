//! Describes the distinct baseline and pre-MAC native allocation action.
//!
//! ```text
//! {"schema":"source-owned.packet-native-startup-allocation/14",
//!  "private_bootstrap":{"retained_requested_bytes":"...",
//!   "maximum_simultaneous_transient_bytes":"...",
//!   "declared_counter_scratch_bytes":"..."},
//!  "native_birth":{"retained_requested_bytes":"...",
//!   "maximum_simultaneous_transient_bytes":"...",
//!   "declared_counter_scratch_bytes":"..."},"restore_prepare":null}
//! ```
//!
//! Binding14 has all seventeen Binding13 keys and `native_startup_allocation`.
//! Its report allocation is literal null exactly when neither report selector
//! is selected. A distinct resource-admitted private bootstrap entry and boot6
//! must require Binding14; existing boot5/Binding13 paths do not accept it.
//! These revision checks are mandatory consumer work, not effects of this DTO.
//!
//! The actual installed ResourceLimits action must admit these prospective
//! owners before Source writes them into its same private birth. Native code
//! must obtain its private construction scope through that actual original
//! channel/boot association before using a row. Decoding a row, receiving a
//! byte ceiling, or validating arithmetic cannot issue that scope.

use crate::ProviderError;
use crucible_node_contract::U64;
use serde::{Deserialize, Serialize};

/// Names the closed native baseline/pre-MAC allowance grammar.
pub const PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA: &str =
    "source-owned.packet-native-startup-allocation/14";

/// Names the distinct Source binding required by the resource-admitted path.
pub const PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA: &str =
    "source-owned.packet-canonical-ack-source-binding/14";

/// Names the distinct private boot required by the resource-admitted path.
pub const PACKET_NATIVE_STARTUP_PRIVATE_BOOT_SCHEMA: &str =
    "source-owned.packet-canonical-ack-private-boot/6";

/// Carries separately admitted requested owners for one concrete native phase.
///
/// Baseline owners are counted as new owners of this action, independently of
/// report publication growth. The complete simultaneous transient phase and
/// its declared counter scratch remain separate terms. Requested bytes do not
/// certify allocator rounding, compiler stack frames or kernel resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeStartupAllocationRow {
    /// Includes all independently retained owners added by this phase.
    pub retained_requested_bytes: U64,
    /// Includes the entire simultaneously live construction phase.
    pub maximum_simultaneous_transient_bytes: U64,
    /// Includes the actual fixed observer, projection and counter layouts.
    pub declared_counter_scratch_bytes: U64,
}

impl PacketNativeStartupAllocationRow {
    /// Checks a positive complete phase and its checked requested sum.
    ///
    /// # Errors
    /// Refuses a missing retained, transient or counter term, or overflow.
    pub fn requested_peak_data(&self) -> Result<u64, ProviderError> {
        if self.retained_requested_bytes.get() == 0
            || self.maximum_simultaneous_transient_bytes.get() == 0
            || self.declared_counter_scratch_bytes.get() == 0
        {
            return Err(invalid());
        }
        self.retained_requested_bytes
            .get()
            .checked_add(self.maximum_simultaneous_transient_bytes.get())
            .and_then(|bytes| bytes.checked_add(self.declared_counter_scratch_bytes.get()))
            .ok_or_else(invalid)
    }

    /// Checks every actual component against its independently admitted term.
    ///
    /// The caller authenticates its actual original construction scope first;
    /// this method compares data and grants no permission.
    ///
    /// # Errors
    /// Refuses invalid rows or any widened component, without scalar refunds.
    pub fn authenticate_actual_data(&self, actual: &Self) -> Result<(), ProviderError> {
        self.requested_peak_data()?;
        actual.requested_peak_data()?;
        if actual.retained_requested_bytes > self.retained_requested_bytes
            || actual.maximum_simultaneous_transient_bytes
                > self.maximum_simultaneous_transient_bytes
            || actual.declared_counter_scratch_bytes > self.declared_counter_scratch_bytes
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Retains the exact nullable Prepare row alongside both required baseline rows.
///
/// The bootstrap row includes only the new private pre-parser/raw bank owners;
/// native birth excludes those already retained owners. Prepare likewise counts
/// only owners added to the actual inactive target. Report publication remains
/// the independent Binding13 allocation object. No omitted/unknown phase may be
/// filled with zero to construct this value or pass the actual issuer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeStartupAllocation {
    /// Names exactly the version fourteen closed allocation grammar.
    pub schema: String,
    /// Accounts the original private pre-parser/raw bank construction.
    pub private_bootstrap: PacketNativeStartupAllocationRow,
    /// Accounts actual native model, Control, Hello, SDK and service construction.
    pub native_birth: PacketNativeStartupAllocationRow,
    /// Accounts one pre-MAC Prepare construction, or literal null when unselected.
    #[serde(deserialize_with = "required_nullable")]
    pub restore_prepare: Option<PacketNativeStartupAllocationRow>,
}

impl PacketNativeStartupAllocation {
    /// Checks the exact class and its immutable Prepare-selection correspondence.
    ///
    /// Callers derive `prepare_selected` from their authenticated actual launch;
    /// this borrowed Boolean is a data comparison, never a construction permit.
    ///
    /// # Errors
    /// Refuses another schema, mismatched selection, missing terms or overflow.
    pub fn validate_data(&self, prepare_selected: bool) -> Result<(), ProviderError> {
        if self.schema != PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA
            || self.restore_prepare.is_some() != prepare_selected
        {
            return Err(invalid());
        }
        self.requested_peak_data().map(|_| ())
    }

    /// Sums retained owners and the largest complete sequential scratch phase.
    ///
    /// All retained owners conservatively coexist. Each transient-plus-counter
    /// phase finishes before the next starts; no individual term is discarded.
    ///
    /// # Errors
    /// Refuses another schema, invalid complete rows or checked overflow.
    pub fn requested_peak_data(&self) -> Result<u64, ProviderError> {
        if self.schema != PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA {
            return Err(invalid());
        }
        let mut retained = 0u64;
        let mut phase = 0u64;
        for row in [
            Some(self.private_bootstrap),
            Some(self.native_birth),
            self.restore_prepare,
        ]
        .into_iter()
        .flatten()
        {
            row.requested_peak_data()?;
            retained = retained
                .checked_add(row.retained_requested_bytes.get())
                .ok_or_else(invalid)?;
            phase = phase.max(
                row.maximum_simultaneous_transient_bytes
                    .get()
                    .checked_add(row.declared_counter_scratch_bytes.get())
                    .ok_or_else(invalid)?,
            );
        }
        retained.checked_add(phase).ok_or_else(invalid)
    }
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("original native startup allocation data")
}

mod storage;
pub use storage::{
    PacketNativeBirthRetainedOverlapData,
    PacketNativeBirthStartupInputs, PacketNativeBirthStartupStorageData,
    original_native_birth_startup_counter_scratch_data, original_native_birth_startup_storage_data,
    original_native_preflight_birth_startup_storage_data,
    original_native_private_boot_fields_storage_data,
};

pub(crate) mod contract_value;

mod preamble;
pub use preamble::{
    ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES, PacketNativeStartupPreambleData,
    authenticate_original_native_startup_preamble_data,
    decode_original_native_startup_preamble_data, encode_original_native_startup_preamble_data,
};

// The authenticated fixed prefix precedes all dynamic private reader banks.
// This floor is not the full native birth quote; the original typed launch and
// boot are recounted separately before that phase starts.
pub(crate) fn original_native_private_bootstrap_floor_data() -> Result<usize, ProviderError> {
    use crate::transport::original_frames::original_frame_slot_layout;
    (1024usize * 1024 + 512 * 1024 + 8)
        .checked_add(original_native_private_invocation_backing_data()?)
        .and_then(|bytes|bytes.checked_add(original_native_private_bank_shared_layout_data().ok()?))
        .and_then(|bytes| bytes.checked_add(4usize.checked_mul(original_frame_slot_layout())?))
        .and_then(|bytes| bytes.checked_add(
            crate::reference_packet::service::ack_emitter::original_native_private_bootstrap_layout()))
        .ok_or_else(invalid)
}

pub(crate) mod data_equality;

pub(crate) fn original_native_private_bank_shared_layout_data() -> Result<usize, ProviderError> {
    use crate::transport::original_frames::OriginalFrameReservation;
    use std::{
        cell::RefCell,
        mem::{align_of, size_of},
    };
    size_of::<RefCell<OriginalFrameReservation>>()
        .checked_add(
            crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                align_of::<RefCell<OriginalFrameReservation>>(),
            )?,
        )
        .ok_or_else(invalid)
}

// Selected Linux/std source: ArgsOs owns the three invocation strings and its
// Vec slots; Stdin initializes one DEFAULT_BUF_SIZE buffer. The real launcher
// fixes argv to executable/socket/flag with both path extents at most 4096.
// These are requested Rust backings, not kernel or physical process memory.
pub(crate) fn original_native_private_invocation_backing_data() -> Result<usize, ProviderError> {
    if !cfg!(all(target_os = "linux", target_pointer_width = "64")) {
        return Err(invalid());
    }
    let slots = 4usize
        .checked_mul(std::mem::size_of::<std::ffi::OsString>())
        .ok_or_else(invalid)?;
    8192usize
        .checked_add(2 * 4096 + "--original-native-startup14".len())
        .and_then(|bytes| bytes.checked_add(slots))
        .ok_or_else(invalid)
}

pub(crate) use storage::{
    OriginalHostInitialLifecycleShapes, original_host_initial_codec_schema_storage_data,
    original_host_initial_lifecycle_shapes_data,
};

pub(crate) use storage::{
    original_native_coordinator_decode_counter_scratch_data,
    original_native_coordinator_decode_storage_data,
};

#[path = "native_startup/invocation.rs"]
mod invocation;
pub use invocation::{
    PacketNativeInvocationPurposeData, original_native_invocation_counter_scratch_data,
};

#[path = "native_startup/invocation_launch.rs"]
mod invocation_launch;
pub use invocation_launch::{PacketNative6InvocationLaunch, PacketNative6InvocationLaunchView};

/// Names the purpose-aware Source binding; legacy binding14 stays exact.
pub const PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA: &str =
    "source-owned.packet-canonical-ack-source-binding/15";

/// Names the purpose-aware private boot; legacy boot6 stays exact.
pub const PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA: &str =
    "source-owned.packet-canonical-ack-private-boot/7";

#[path = "native_startup/invocation_preamble.rs"]
mod invocation_preamble;
pub use invocation_preamble::{
    ORIGINAL_NATIVE_INVOCATION_PREAMBLE_BYTES, PacketNativeInvocationPreambleData,
    authenticate_original_native_invocation_preamble_data,
    decode_original_native_invocation_preamble_data,
    encode_original_native_invocation_preamble_data,
};

pub use invocation::{
    PacketNativeInvocationLaunchIdentityData, original_native_invocation_launch_identity_data,
    write_original_native_invocation_launch_data,
};

pub use invocation::{
    PacketNativeInvocationConstructionStorageData,
    original_native_invocation_construction_storage_data,
};

pub(crate) use storage::original_native_invocation_baseline_storage_data;

mod pre_dom;
pub(crate) use pre_dom::OriginalNativeFramePreflight;

pub(in crate::reference_packet::service) use storage::original_private_launch_backing_data;
