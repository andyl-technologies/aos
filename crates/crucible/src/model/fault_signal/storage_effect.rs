//! Closed parameter schemas for block, flash, array, and 9p effects.
//!
//! These schemas keep volatile, durable, media, controller, and guest-visible
//! state distinct. In particular, an acknowledged write and a durable write
//! are never represented by the same implicit boolean.

use super::{
    BoundedCount, ByteRange, EffectKind, FaultContractError, FaultObjectId, HexBytes, ObjectIdSet,
    OperationSet, PositiveU64, ProbabilityMillionths,
};

/// Guest-visible block-device availability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum StorageAvailabilityState {
    /// All declared operations remain available.
    Online,
    /// No operations are admitted.
    Offline,
    /// Reads are admitted and writes are rejected.
    ReadOnly,
    /// Operations are admitted under the declared degraded policy.
    Degraded,
}

/// Treatment of state during reconnect or capacity changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum StorageTransitionPolicy {
    /// Preserve admitted operations or state.
    Preserve,
    /// Fail admitted operations with their declared typed status.
    Fail,
    /// Drain admitted operations before completing the transition.
    Drain,
    /// Discard the affected volatile state.
    Discard,
}

/// Keyed selection rule for storage operations or bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum StorageSelection {
    /// Select using a keyed uniform decision.
    KeyedUniform,
    /// Select the lowest canonical offset or operation identity.
    CanonicalFirst,
    /// Select the highest canonical offset or operation identity.
    CanonicalLast,
    /// Select every eligible item.
    All,
}

/// Read-data mutation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum StorageReadMutation {
    /// XORs a selected returned byte range.
    BitFlip {
        /// Range relative to the returned data.
        range: ByteRange,
        /// Canonical nonempty XOR mask bytes.
        mask: HexBytes,
    },
    /// Reads a retained prior version.
    Stale {
        /// Retained version identity.
        version: FaultObjectId,
    },
    /// Reads from another declared device range.
    Misdirected {
        /// Source device identity.
        source_device: FaultObjectId,
        /// Source byte range.
        source_range: ByteRange,
    },
}

/// Persistence disposition of an acknowledged write.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum StorageWriteDispositionKind {
    /// Apply the complete write normally.
    Apply,
    /// Acknowledge without applying selected bytes.
    Lost {
        /// Deterministic byte or sector selection.
        selection: StorageSelection,
    },
    /// Apply a deterministic strict subset.
    Torn {
        /// Deterministic byte or sector selection.
        selection: StorageSelection,
    },
    /// Apply to another range.
    Misdirected {
        /// Destination device identity.
        destination_device: FaultObjectId,
        /// Destination byte range.
        destination_range: ByteRange,
    },
}

/// Flush disposition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum StorageFlushKind {
    /// Report the actual durable frontier.
    Honest,
    /// Return a typed error.
    Error,
    /// Report success without advancing the required durable frontier.
    Lie,
    /// Stall until the modeled recovery or timeout.
    Stall,
}

/// Persistent media-range state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum StorageMediaState {
    /// The range always fails applicable operations.
    Bad,
    /// The range fails after declared thresholds.
    Latent,
    /// Reads return a typed poison outcome.
    Poisoned,
    /// Writes to the range fail while reads remain available.
    ReadOnly,
}

/// Storage-controller lifecycle transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum StorageControllerTransition {
    /// Reset controller and declared volatile state.
    Reset,
    /// Disconnect and later reconnect the controller path.
    Reconnect,
    /// Re-enumerate namespaces and paths.
    Enumerate,
}

/// Physical cause of a volatile-cache loss impulse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum StorageVolatileCacheLossKind {
    /// Loses entries not protected by the configured cache policy.
    PowerLoss,
    /// Loses all selected entries because the protection mechanism also failed.
    ProtectionFailure,
}

/// Exact eligible-set selector for a volatile-cache loss impulse.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum StorageVolatileCacheLossSelector {
    /// Selects every entry eligible for the loss kind and target scope.
    All,
    /// Selects entries admitted strictly after one global cache sequence.
    AfterSequence {
        /// Exclusive lower cache-sequence bound.
        sequence: u64,
    },
    /// Selects entries whose logical byte range intersects this range.
    RangeIntersection {
        /// Absolute logical device range.
        range: ByteRange,
    },
    /// Selects an exact keyed subset, capped by the live eligible cardinality.
    KeyedSubset {
        /// Requested exact cardinality when at least this many entries are eligible.
        count: BoundedCount,
    },
}

/// 9p result mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum NinePResultKind {
    /// Return a declared errno.
    Errno,
    /// Return a retained prior object version.
    Stale,
    /// Resolve to another declared object.
    Misdirected,
}

/// Typed parameters for every executable storage and 9p effect kind.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", content = "parameters", rename_all = "snake_case")]
pub enum StorageEffectSpecification {
    /// Block-device availability and reconnect behavior.
    Availability {
        /// Requested availability state.
        state: StorageAvailabilityState,
        /// Treatment of admitted and queued operations.
        reconnect_policy: StorageTransitionPolicy,
    },
    /// Guest-visible device capacity.
    ReportedCapacity {
        /// Positive reported byte length.
        length_bytes: PositiveU64,
        /// Treatment of ranges beyond a shrinking boundary.
        shrink_policy: StorageTransitionPolicy,
    },
    /// Operation-filtered completion latency.
    Latency {
        /// Affected operations.
        operations: OperationSet,
        /// Fixed added latency.
        extra_nanos: u64,
        /// Maximum keyed jitter.
        jitter_nanos: u64,
    },
    /// Bounded storage service.
    Service {
        /// Positive byte rate.
        bytes_per_second: PositiveU64,
        /// Optional positive I/O operation rate.
        iops: Option<PositiveU64>,
        /// Positive queue depth.
        queue_depth: BoundedCount,
        /// Registered token/service policy.
        service_policy: FaultObjectId,
    },
    /// Per-operation typed error.
    OperationFailure {
        /// Affected operations.
        operations: OperationSet,
        /// Keyed error probability.
        probability: ProbabilityMillionths,
        /// Registered protocol status or errno.
        status: FaultObjectId,
    },
    /// Stall, recovery, and timeout behavior.
    StallTimeout {
        /// Fixed stall, mutually exclusive with `recovery_event`.
        stall_nanos: Option<PositiveU64>,
        /// Recovery event, mutually exclusive with fixed stall.
        recovery_event: Option<FaultObjectId>,
        /// Typed timeout result.
        timeout_result: FaultObjectId,
    },
    /// Completion reordering.
    CompletionReorder {
        /// Positive reorder window.
        window_nanos: PositiveU64,
        /// Keyed selection rule.
        selection: StorageSelection,
    },
    /// Protocol-valid duplicate completion.
    DuplicateCompletion {
        /// Number of additional completions.
        copies: BoundedCount,
        /// Gap between adjacent completions; resolution cumulatively multiplies it by copy index.
        gap_nanos: u64,
        /// Registered protocol duplicate policy.
        protocol_policy: FaultObjectId,
    },
    /// Read-data transform.
    ReadTransform {
        /// Typed mutation and selector.
        mutation: StorageReadMutation,
    },
    /// Write persistence disposition.
    WriteDisposition {
        /// Typed persistence disposition.
        disposition: StorageWriteDispositionKind,
        /// Guest-visible acknowledged status.
        acknowledged_status: FaultObjectId,
    },
    /// Durable partial-order mutation.
    PersistenceOrder {
        /// Ordering-group identity.
        ordering_group: FaultObjectId,
        /// Registered delay and barrier rule.
        ordering_rule: FaultObjectId,
    },
    /// Bounded volatile write-cache admission behavior.
    VolatileCache {
        /// Positive cache capacity.
        capacity_bytes: PositiveU64,
        /// Registered admission and eviction policy.
        cache_policy: FaultObjectId,
    },
    /// Explicit volatile write-cache loss impulse.
    VolatileCacheLoss {
        /// Deterministic selection among entries eligible for this loss kind.
        selector: StorageVolatileCacheLossSelector,
        /// Whether cache protection remains effective for this impulse.
        loss: StorageVolatileCacheLossKind,
    },
    /// Flush truthfulness, error, or stall outcome.
    FlushDisposition {
        /// Flush disposition.
        kind: StorageFlushKind,
        /// Typed status returned to the guest.
        status: FaultObjectId,
    },
    /// Stateful media-range overlay.
    MediaRange {
        /// Affected device byte range.
        range: ByteRange,
        /// Range state.
        state: StorageMediaState,
        /// Affected operation filter.
        operations: OperationSet,
        /// Optional access-count threshold.
        count_threshold: Option<PositiveU64>,
        /// Optional virtual-time threshold.
        time_threshold_nanos: Option<PositiveU64>,
    },
    /// Flash wear, retention, disturb, and program state.
    FlashState {
        /// Positive erase-block size.
        erase_block_bytes: PositiveU64,
        /// Positive program-page size.
        program_page_bytes: PositiveU64,
        /// Positive endurance cycle count.
        endurance_cycles: PositiveU64,
        /// Registered retention rule.
        retention_rule: FaultObjectId,
        /// Registered read-disturb rule.
        read_disturb_rule: FaultObjectId,
        /// Registered program/erase rule.
        program_erase_rule: FaultObjectId,
    },
    /// Controller reset, reconnect, or enumeration state.
    ControllerLifecycle {
        /// Requested controller transition.
        transition: StorageControllerTransition,
        /// Complete registered transition policy for every lifecycle stage.
        transition_policy: FaultObjectId,
        /// Resulting namespace identities.
        namespaces: ObjectIdSet,
        /// Resulting path identities.
        paths: ObjectIdSet,
    },
    /// Array layout, member, path, and rebuild state.
    ArrayState {
        /// Registered array layout.
        layout: FaultObjectId,
        /// Member and path state artifact.
        member_path_state: FaultObjectId,
        /// Registered read/write member selection.
        selection_policy: FaultObjectId,
        /// Registered rebuild service.
        rebuild_service: FaultObjectId,
        /// Registered consistency policy.
        consistency_policy: FaultObjectId,
    },
    /// Typed 9p error, stale result, or misdirection.
    NinePResult {
        /// Affected typed 9p operations.
        operations: OperationSet,
        /// Result mutation kind.
        kind: NinePResultKind,
        /// Errno for an errno result.
        errno: Option<i32>,
        /// Retained object version for a stale result.
        version: Option<FaultObjectId>,
        /// Replacement object for a misdirected result.
        object: Option<FaultObjectId>,
    },
    /// Committed-versus-visible 9p frontier.
    NinePVisibility {
        /// Object or update identity.
        update: FaultObjectId,
        /// Fixed visibility delay, mutually exclusive with an event.
        delay_nanos: Option<PositiveU64>,
        /// Visibility event, mutually exclusive with a delay.
        visibility_event: Option<FaultObjectId>,
        /// Namespace/data visibility policy.
        visibility_policy: FaultObjectId,
    },
}

impl StorageEffectSpecification {
    /// Returns the exact closed registry kind for these parameters.
    #[must_use]
    pub const fn kind(&self) -> EffectKind {
        match self {
            Self::Availability { .. } => EffectKind::StorageAvailability,
            Self::ReportedCapacity { .. } => EffectKind::StorageReportedCapacity,
            Self::Latency { .. } => EffectKind::StorageLatency,
            Self::Service { .. } => EffectKind::StorageService,
            Self::OperationFailure { .. } => EffectKind::StorageOperationFailure,
            Self::StallTimeout { .. } => EffectKind::StorageStallTimeout,
            Self::CompletionReorder { .. } => EffectKind::StorageCompletionReorder,
            Self::DuplicateCompletion { .. } => EffectKind::StorageDuplicateCompletion,
            Self::ReadTransform { .. } => EffectKind::StorageReadTransform,
            Self::WriteDisposition { .. } => EffectKind::StorageWriteDisposition,
            Self::PersistenceOrder { .. } => EffectKind::StoragePersistenceOrder,
            Self::VolatileCache { .. } => EffectKind::StorageVolatileCache,
            Self::VolatileCacheLoss { .. } => EffectKind::StorageVolatileCacheLoss,
            Self::FlushDisposition { .. } => EffectKind::StorageFlushDisposition,
            Self::MediaRange { .. } => EffectKind::StorageMediaRange,
            Self::FlashState { .. } => EffectKind::StorageFlashState,
            Self::ControllerLifecycle { .. } => EffectKind::StorageControllerLifecycle,
            Self::ArrayState { .. } => EffectKind::StorageArrayState,
            Self::NinePResult { .. } => EffectKind::NinePResult,
            Self::NinePVisibility { .. } => EffectKind::NinePVisibility,
        }
    }

    /// Validates cross-field storage invariants.
    ///
    /// # Errors
    ///
    /// Returns [`FaultContractError`] when alternatives are not exclusive,
    /// flash geometry is inconsistent, a bit mask is empty, or 9p result fields
    /// do not match the selected result kind.
    pub fn validate(&self) -> Result<(), FaultContractError> {
        match self {
            Self::Service { queue_depth, .. } if queue_depth.get() > 1_048_576 => {
                Err(FaultContractError::InvalidEffectParameters {
                    effect: self.kind(),
                })
            }
            Self::DuplicateCompletion {
                copies, gap_nanos, ..
            } if *gap_nanos == 0
                || copies.get() > 256
                || gap_nanos.checked_mul(u64::from(copies.get())).is_none() =>
            {
                Err(FaultContractError::InvalidEffectParameters {
                    effect: self.kind(),
                })
            }
            Self::StallTimeout {
                stall_nanos,
                recovery_event,
                ..
            } => exactly_one(
                stall_nanos.is_some(),
                recovery_event.is_some(),
                "stall_nanos",
                "recovery_event",
            ),
            Self::ReadTransform {
                mutation: StorageReadMutation::BitFlip { mask, .. },
            } if mask.decoded_len() == 0 => Err(FaultContractError::InvalidEffectParameters {
                effect: self.kind(),
            }),
            Self::FlashState {
                erase_block_bytes,
                program_page_bytes,
                ..
            } if erase_block_bytes.get() % program_page_bytes.get() != 0 => {
                Err(FaultContractError::InvalidEffectParameters {
                    effect: self.kind(),
                })
            }
            Self::MediaRange {
                state,
                count_threshold,
                time_threshold_nanos,
                ..
            } if *state != StorageMediaState::Latent
                && (count_threshold.is_some() || time_threshold_nanos.is_some()) =>
            {
                Err(FaultContractError::InvalidEffectParameters {
                    effect: self.kind(),
                })
            }
            Self::NinePResult {
                kind,
                errno,
                version,
                object,
                ..
            } => {
                let valid = match kind {
                    NinePResultKind::Errno => {
                        errno.is_some() && version.is_none() && object.is_none()
                    }
                    NinePResultKind::Stale => {
                        errno.is_none() && version.is_some() && object.is_none()
                    }
                    NinePResultKind::Misdirected => {
                        errno.is_none() && version.is_none() && object.is_some()
                    }
                };
                if valid {
                    Ok(())
                } else {
                    Err(FaultContractError::InvalidEffectParameters {
                        effect: self.kind(),
                    })
                }
            }
            Self::NinePVisibility {
                delay_nanos,
                visibility_event,
                ..
            } => exactly_one(
                delay_nanos.is_some(),
                visibility_event.is_some(),
                "delay_nanos",
                "visibility_event",
            ),
            _ => Ok(()),
        }
    }
}

fn exactly_one(
    left_present: bool,
    right_present: bool,
    left: &'static str,
    right: &'static str,
) -> Result<(), FaultContractError> {
    if left_present == right_present {
        return Err(FaultContractError::MutuallyExclusiveFields { left, right });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FaultOperation;

    #[test]
    fn ninep_result_fields_follow_selected_kind() {
        let operations = match OperationSet::new(vec![FaultOperation::StorageRead]) {
            Ok(operations) => operations,
            Err(error) => panic!("test operation set must be valid: {error}"),
        };
        let effect = StorageEffectSpecification::NinePResult {
            operations,
            kind: NinePResultKind::Errno,
            errno: Some(5),
            version: None,
            object: None,
        };
        assert_eq!(effect.kind(), EffectKind::NinePResult);
        assert!(effect.validate().is_ok());
    }
}
