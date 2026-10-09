//! Exact native control kinds, roles, and section tags.

use super::Result;
use super::codec::invalid;

/// Names one actual role, not a journal authority or a transferable capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeHeldOwnerV1 {
    /// The original Root Mount owner.
    Root = 1,
    /// The fixed SourceProvider owner.
    Provider = 2,
    /// The dedicated Storage hold owner.
    Storage = 3,
}

impl NativeHeldOwnerV1 {
    /// Decodes only the three explicitly assigned roles.
    ///
    /// # Errors
    ///
    /// Rejects every unassigned owner byte.
    pub fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Root),
            2 => Ok(Self::Provider),
            3 => Ok(Self::Storage),
            _ => Err(invalid("owner")),
        }
    }
}

/// Names the closed native hot and descriptor-free recovery controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeHeldControlKindV1 {
    /// Retains Root's five known original fields before Acquire can escape.
    RootPrepared = 1,
    /// Reports the original Storage-held offer before its one-FD packet.
    StorageHeld = 2,
    /// Reports the committed Source outcome before its one-FD packet.
    ProviderHeld = 3,
    /// Reports genuine Root-local original-FD acceptance, not manager custody.
    RootAccepted = 4,
    /// Relays the exact original Root disposition on the original Storage child.
    ProviderRelay = 5,
    /// Reports durable Storage settlement without retiring its interest.
    StorageSettled = 6,
    /// Reports durable Source and Storage settlement to Root.
    ProviderSettled = 7,
    /// Reports an irreversible Closed disposition without a custody claim.
    RootClosed = 8,
    /// Queries historical state under current Root-role authentication.
    RootRecoveryQuery = 9,
    /// Reports Source historical state, optionally with an exact Storage child.
    ProviderRecoveryState = 10,
    /// Forwards the unchanged signed Root query to the actual Storage owner.
    ProviderStorageRecoveryQuery = 11,
    /// Reports descriptor-free Storage issuance and settlement state.
    StorageRecoveryState = 12,
    /// Proves Root recorded terminal settlement; it releases only pin waits.
    RootTerminalRecorded = 13,
}

impl NativeHeldControlKindV1 {
    /// Decodes only the thirteen explicitly assigned control kinds.
    ///
    /// # Errors
    ///
    /// Rejects every unassigned kind byte.
    pub fn from_byte(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::RootPrepared),
            2 => Ok(Self::StorageHeld),
            3 => Ok(Self::ProviderHeld),
            4 => Ok(Self::RootAccepted),
            5 => Ok(Self::ProviderRelay),
            6 => Ok(Self::StorageSettled),
            7 => Ok(Self::ProviderSettled),
            8 => Ok(Self::RootClosed),
            9 => Ok(Self::RootRecoveryQuery),
            10 => Ok(Self::ProviderRecoveryState),
            11 => Ok(Self::ProviderStorageRecoveryQuery),
            12 => Ok(Self::StorageRecoveryState),
            13 => Ok(Self::RootTerminalRecorded),
            _ => Err(invalid("control kind")),
        }
    }

    /// Returns the fixed sender role implied by this kind.
    #[must_use]
    pub const fn sender(self) -> NativeHeldOwnerV1 {
        match self {
            Self::RootPrepared
            | Self::RootAccepted
            | Self::RootClosed
            | Self::RootRecoveryQuery
            | Self::RootTerminalRecorded => NativeHeldOwnerV1::Root,
            Self::ProviderHeld
            | Self::ProviderRelay
            | Self::ProviderSettled
            | Self::ProviderRecoveryState
            | Self::ProviderStorageRecoveryQuery => NativeHeldOwnerV1::Provider,
            Self::StorageHeld | Self::StorageSettled | Self::StorageRecoveryState => {
                NativeHeldOwnerV1::Storage
            }
        }
    }

    /// Returns the fixed signature audience implied by this kind.
    #[must_use]
    pub const fn audience(self) -> NativeHeldOwnerV1 {
        match self {
            Self::ProviderHeld | Self::ProviderSettled | Self::ProviderRecoveryState => {
                NativeHeldOwnerV1::Root
            }
            Self::ProviderRelay | Self::ProviderStorageRecoveryQuery => NativeHeldOwnerV1::Storage,
            _ => NativeHeldOwnerV1::Provider,
        }
    }

    /// Returns the hot step or zero for a recovery control.
    #[must_use]
    pub const fn step(self) -> u64 {
        match self {
            Self::RootPrepared => 1,
            Self::StorageHeld => 2,
            Self::ProviderHeld => 3,
            Self::RootAccepted | Self::RootClosed => 4,
            Self::ProviderRelay => 5,
            Self::StorageSettled => 6,
            Self::ProviderSettled => 7,
            Self::RootTerminalRecorded => 8,
            Self::RootRecoveryQuery
            | Self::ProviderRecoveryState
            | Self::ProviderStorageRecoveryQuery
            | Self::StorageRecoveryState => 0,
        }
    }

    /// Reports whether this is a descriptor-free current-role recovery claim.
    #[must_use]
    pub const fn is_recovery(self) -> bool {
        matches!(
            self,
            Self::RootRecoveryQuery
                | Self::ProviderRecoveryState
                | Self::ProviderStorageRecoveryQuery
                | Self::StorageRecoveryState
        )
    }
}

/// Names one assigned section; each kind accepts only its exact closed set.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum NativeHeldSectionTagV1 {
    /// Fixed-family diagnostic owner witnesses.
    Witness = 1,
    /// Unchanged signed RootPrepared control.
    RootPrepared = 2,
    /// Existing exact AOSZNP03 original positive reply bytes.
    NativeReply = 3,
    /// Unchanged signed StorageHeld control.
    StorageHeld = 4,
    /// Existing canonical Source response artifact digest.
    SourceArtifact = 5,
    /// Unchanged signed hot RootAccepted or RootClosed control.
    RootDispositionControl = 6,
    /// Stable unsigned owning-journal Root disposition assertion.
    RootDispositionAssertion = 7,
    /// Stable disposition and owner settlement identity tuple.
    Settlement = 8,
    /// Exact bounded recovery query correlation.
    RecoveryQuery = 9,
    /// Unchanged signed current Root recovery query.
    RootRecoveryControl = 10,
    /// Concrete Source historical state claim.
    ProviderRecoveryState = 11,
    /// Concrete Storage historical state claim.
    StorageRecoveryState = 12,
    /// Concrete Root owning-journal historical assertion.
    RootRecoveryAssertion = 13,
}

impl NativeHeldSectionTagV1 {
    pub(super) fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Witness),
            2 => Ok(Self::RootPrepared),
            3 => Ok(Self::NativeReply),
            4 => Ok(Self::StorageHeld),
            5 => Ok(Self::SourceArtifact),
            6 => Ok(Self::RootDispositionControl),
            7 => Ok(Self::RootDispositionAssertion),
            8 => Ok(Self::Settlement),
            9 => Ok(Self::RecoveryQuery),
            10 => Ok(Self::RootRecoveryControl),
            11 => Ok(Self::ProviderRecoveryState),
            12 => Ok(Self::StorageRecoveryState),
            13 => Ok(Self::RootRecoveryAssertion),
            _ => Err(invalid("section tag")),
        }
    }
}
