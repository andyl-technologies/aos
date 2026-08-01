//! Deterministic launch-profile mode enums and their canonical renderings.
//!
//! These small value enums name the determinism-relevant policy choices a
//! launch profile pins (icount shift, machine reset, disk image, guest backing
//! state, guest core content, and host input), and their [`fmt::Display`]
//! implementations render the stable tokens that appear in a profile's
//! canonical hash material. They are re-exported from the `launch` module, so
//! callers refer to them at their original paths.

use std::fmt;

/// The requested icount shift setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcountShiftSetting {
    /// A fixed integer shift used in `ns = icount << shift`.
    Fixed(u8),
    /// QEMU's host-speed-adaptive icount mode.
    Auto,
}

/// The reset discipline for RAM and emulated device state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineResetMode {
    /// RAM and device reset values are fixed before the genesis run starts.
    Deterministic,
    /// Reset state is left to backend or host defaults.
    HostProvided,
}

/// The backing-image write policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskImageMode {
    /// The guest is launched without a block device.
    NoBlockDevice,
    /// Guest writes land in a copy-on-write overlay.
    CopyOnWriteOverlay,
    /// Guest writes may mutate the backing image.
    WritableBacking,
}

/// The identity policy for guest backing state at genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestBackingStateMode {
    /// No guest block backing exists.
    NoBlockDevice,
    /// Each run starts from byte-identical read-only genesis backing state.
    ByteIdenticalGenesis,
    /// The genesis backing state may be host-provided or mutable across runs.
    HostMutableGenesis,
}

/// The core-operation policy for Crucible content inside the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestCoreContentMode {
    /// Core operation uses host-side launch, plugin, patch, firmware, and cmdline inputs only.
    HostSideOnly,
    /// Core operation requires Crucible-provided files, agents, or payloads inside the guest.
    GuestInjectedContent,
}

/// The host interactive input policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputPolicy {
    /// No keyboard, mouse, monitor, or serial input is accepted from the host.
    NoInteractiveInput,
    /// Host interactive input devices may be enabled.
    HostInteractive,
}

impl fmt::Display for MachineResetMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deterministic => f.write_str("deterministic"),
            Self::HostProvided => f.write_str("host-provided"),
        }
    }
}

impl fmt::Display for DiskImageMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBlockDevice => f.write_str("no-block-device"),
            Self::CopyOnWriteOverlay => f.write_str("copy-on-write-overlay"),
            Self::WritableBacking => f.write_str("writable-backing"),
        }
    }
}

impl fmt::Display for GuestBackingStateMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBlockDevice => f.write_str("no-block-device"),
            Self::ByteIdenticalGenesis => f.write_str("byte-identical-genesis"),
            Self::HostMutableGenesis => f.write_str("host-mutable-genesis"),
        }
    }
}

impl fmt::Display for GuestCoreContentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostSideOnly => f.write_str("host-side-only"),
            Self::GuestInjectedContent => f.write_str("guest-injected-content"),
        }
    }
}

impl fmt::Display for InputPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInteractiveInput => f.write_str("no-interactive-input"),
            Self::HostInteractive => f.write_str("host-interactive"),
        }
    }
}
