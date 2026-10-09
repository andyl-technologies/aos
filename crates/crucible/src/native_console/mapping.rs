//! Original scheduler projection and boot visibility for retained byte origins.
//!
//! Only a sealed RUN admission constructs these leases. Native emission and
//! acceptance authority remain independent; neither a map nor its generation
//! grants permission to execute or consume a transport prefix.

use crate::{
    NativeConsoleByteOrigin, NodeCounter, NodeId, NodeTimeMapping, ObservableEvent, SchedulerError,
    VirtualTime,
};

/// Immutable RUN and original ready-point maps for one logical console lifetime.
///
/// RUN bytes project their original emitted picoseconds through the retained
/// RUN map. Boot bytes become visible at the original ready point because they
/// precede the modeled scenario; their complete emission origin stays intact.
/// Physical restore generations and accepted clamp coordinates are absent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConsoleMappingLease {
    node: NodeId,
    logical_generation: u64,
    mapping: NodeTimeMapping,
    ready_point_mapping: NodeTimeMapping,
}

impl NativeConsoleMappingLease {
    /// Checks the restored logical pairing and original ready-point anchor.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when a checkpoint map names another node,
    /// canonical generation or completed boot counter. This authenticates
    /// projection consistency only, never native phase or execution authority.
    pub fn validate_binding(
        &self,
        node: &NodeId,
        generation: u64,
        ready: NodeCounter,
    ) -> Result<(), SchedulerError> {
        if node != &self.node
            || generation != self.logical_generation
            || ready != self.ready_point_mapping.anchor_counter
            || self.ready_point_mapping.anchor_time != crate::SimInstant::EPOCH
        {
            return Err(Self::codec_error());
        }
        Ok(())
    }

    /// Encodes a process-free retained scheduler map for checkpoint custody.
    ///
    /// This is projection material, not a serialized execution permission.
    /// Restoring it must be paired with the original execution checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if the node name or output allocation cannot
    /// be represented by the exact length-prefixed format.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, SchedulerError> {
        let length = u32::try_from(self.node.name.len()).map_err(|_| Self::codec_error())?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(52 + self.node.name.len())
            .map_err(|_| Self::codec_error())?;
        bytes.extend_from_slice(b"NCMAP001");
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(self.node.name.as_bytes());
        for value in [
            self.logical_generation,
            self.mapping.anchor_counter.ticks,
            self.mapping.anchor_time.ticks,
            self.ready_point_mapping.anchor_counter.ticks,
            self.ready_point_mapping.anchor_time.ticks,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(bytes)
    }

    /// Decodes an exact checkpoint projection without manufacturing a RUN owner.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] for incorrect framing, length, UTF-8, a shifted boot epoch or an
    /// unavailable node-name allocation. The enclosing checkpoint must still
    /// authenticate this material before attaching it to restored origins.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SchedulerError> {
        if bytes.len() < 52 || &bytes[..8] != b"NCMAP001" {
            return Err(Self::codec_error());
        }
        let length =
            u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| Self::codec_error())?) as usize;
        if bytes.len().checked_sub(52) != Some(length) {
            return Err(Self::codec_error());
        }
        let name = std::str::from_utf8(&bytes[12..12 + length]).map_err(|_| Self::codec_error())?;
        let mut retained_name = String::new();
        retained_name
            .try_reserve_exact(length)
            .map_err(|_| Self::codec_error())?;
        retained_name.push_str(name);
        let mut values = [0; 5];
        let (fields, _) = bytes[12 + length..].as_chunks::<8>();
        for (value, field) in values.iter_mut().zip(fields) {
            *value = u64::from_le_bytes(*field);
        }
        // The original scheduler makes boot visibility EPOCH. Checkpoint
        // material cannot choose a different evaluation epoch for saved bytes.
        if values[4] != crate::SimInstant::EPOCH.ticks {
            return Err(Self::codec_error());
        }
        Ok(Self::from_admitted_run(
            NodeId {
                name: retained_name,
            },
            values[0],
            NodeTimeMapping {
                anchor_counter: NodeCounter { ticks: values[1] },
                anchor_time: crate::SimInstant { ticks: values[2] },
            },
            NodeTimeMapping {
                anchor_counter: NodeCounter { ticks: values[3] },
                anchor_time: crate::SimInstant { ticks: values[4] },
            },
        ))
    }

    fn codec_error() -> SchedulerError {
        SchedulerError::BoundaryViolation {
            message: String::from("malformed retained native-console projection"),
        }
    }

    pub(crate) fn from_admitted_run(
        node: NodeId,
        logical_generation: u64,
        mapping: NodeTimeMapping,
        ready_point_mapping: NodeTimeMapping,
    ) -> Self {
        Self {
            node,
            logical_generation,
            mapping,
            ready_point_mapping,
        }
    }

    fn validate_origin(
        &self,
        node: &NodeId,
        origin: &NativeConsoleByteOrigin,
    ) -> Result<(), SchedulerError> {
        if node != &self.node || origin.logical_generation != self.logical_generation {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("native-console origin differs from its original mapping"),
            });
        }
        origin
            .validate()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: error.to_string(),
            })
    }

    /// Projects an original RUN byte without a poll floor or acceptance stamp.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] for a foreign node or logical generation,
    /// malformed origin, or unrepresentable original emission coordinate.
    pub fn project_origin(
        &self,
        node: &NodeId,
        origin: &NativeConsoleByteOrigin,
    ) -> Result<ObservableEvent, SchedulerError> {
        self.validate_origin(node, origin)?;
        let at = self.mapping.logical_time(NodeCounter {
            ticks: origin.emitted_ps,
        })?;
        self.event_at(node, origin, VirtualTime { ticks: at.ticks })
    }

    /// Exposes a boot byte at its genuine original ready-point visibility.
    ///
    /// `ready_counter` is the backend's synchronized completed boot counter.
    /// It must exactly match this scheduler's original ready-point anchor. The
    /// event's evaluation coordinate describes visibility; the canonical byte
    /// payload retains its earlier emitted picoseconds and raw prefix.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] for an unmatched ready counter, an origin
    /// after readiness, or any node, generation or origin validation failure.
    pub fn project_boot_origin(
        &self,
        node: &NodeId,
        ready_counter: NodeCounter,
        origin: &NativeConsoleByteOrigin,
    ) -> Result<ObservableEvent, SchedulerError> {
        self.validate_origin(node, origin)?;
        if ready_counter != self.ready_point_mapping.anchor_counter
            || origin.emitted_ps > ready_counter.ticks
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("native-console boot origin differs from ready visibility"),
            });
        }
        self.event_at(
            node,
            origin,
            VirtualTime {
                ticks: self.ready_point_mapping.anchor_time.ticks,
            },
        )
    }

    fn event_at(
        &self,
        node: &NodeId,
        origin: &NativeConsoleByteOrigin,
        at: VirtualTime,
    ) -> Result<ObservableEvent, SchedulerError> {
        ObservableEvent::native_console_byte(at, node.clone(), origin.clone()).map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: error.to_string(),
            }
        })
    }
}
