//! Allocation-free admission of production checkpoint collection shapes.
//!
//! The canonical envelope uses definite-length CBOR maps and arrays. This
//! scanner admits scenario-sized collections before serde constructs their
//! owned keys or values. The normal decoder and canonical re-encode remain the
//! authorities for field types, ordering, identity, and byte canonicality.

use crucible::model::FaultResourceLimits;

use super::ProductionFaultRuntimeCheckpointCodecError;

const MAX_CBOR_DEPTH: usize = 128;

pub(super) fn preflight_checkpoint_payload(
    payload: &[u8],
    limits: FaultResourceLimits,
) -> Result<(), ProductionFaultRuntimeCheckpointCodecError> {
    let mut cursor = CborCursor::new(payload);
    let fields = cursor.map_len()?;
    for _ in 0..fields {
        let field = cursor.text()?;
        match field {
            b"qemu_fingerprints" | b"qemu_fault_sequences" | b"qemu_fault_event_sequences" => {
                cursor.admit_map("nodes", limits.nodes, hard_limits().nodes)?;
            }
            b"qemu_issued_actions" | b"qemu_action_commits" => {
                cursor.admit_map(
                    "event_records",
                    limits.event_records,
                    hard_limits().event_records,
                )?;
            }
            b"qemu_active_rule_ids" | b"emitted_events" | b"pending_qemu_observations" => {
                cursor.admit_array(
                    "event_records",
                    limits.event_records,
                    hard_limits().event_records,
                )?;
            }
            b"pending_qemu_events" => cursor.admit_pending_qemu_events(limits)?,
            _ => cursor.skip_value(0)?,
        }
    }
    if !cursor.is_exhausted() {
        return Err(ProductionFaultRuntimeCheckpointCodecError::Malformed);
    }
    Ok(())
}

fn hard_limits() -> FaultResourceLimits {
    FaultResourceLimits::compiled_maximum()
}

struct CborCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CborCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn map_len(&mut self) -> Result<u64, ProductionFaultRuntimeCheckpointCodecError> {
        self.container_len(5)
    }

    fn array_len(&mut self) -> Result<u64, ProductionFaultRuntimeCheckpointCodecError> {
        self.container_len(4)
    }

    fn container_len(
        &mut self,
        expected_major: u8,
    ) -> Result<u64, ProductionFaultRuntimeCheckpointCodecError> {
        let initial = self.byte()?;
        if initial >> 5 != expected_major {
            return Err(ProductionFaultRuntimeCheckpointCodecError::Malformed);
        }
        self.argument(initial & 0x1f)
    }

    fn text(&mut self) -> Result<&'a [u8], ProductionFaultRuntimeCheckpointCodecError> {
        let initial = self.byte()?;
        if initial >> 5 != 3 {
            return Err(ProductionFaultRuntimeCheckpointCodecError::Malformed);
        }
        let length = self.argument(initial & 0x1f)?;
        self.take(length)
    }

    fn admit_map(
        &mut self,
        field: &'static str,
        configured: u64,
        hard: u64,
    ) -> Result<(), ProductionFaultRuntimeCheckpointCodecError> {
        let length = self.map_len()?;
        admit_collection(field, length, configured, hard)?;
        for _ in 0..length {
            self.skip_value(0)?;
            self.skip_value(0)?;
        }
        Ok(())
    }

    fn admit_array(
        &mut self,
        field: &'static str,
        configured: u64,
        hard: u64,
    ) -> Result<(), ProductionFaultRuntimeCheckpointCodecError> {
        let length = self.array_len()?;
        admit_collection(field, length, configured, hard)?;
        for _ in 0..length {
            self.skip_value(0)?;
        }
        Ok(())
    }

    fn admit_pending_qemu_events(
        &mut self,
        limits: FaultResourceLimits,
    ) -> Result<(), ProductionFaultRuntimeCheckpointCodecError> {
        let nodes = self.map_len()?;
        admit_collection("nodes", nodes, limits.nodes, hard_limits().nodes)?;

        let mut events = 0_u64;
        for _ in 0..nodes {
            self.skip_value(0)?;
            let node_events = self.array_len()?;
            let next = events.checked_add(node_events).ok_or_else(|| {
                resource_limit(
                    "event_records",
                    events,
                    node_events,
                    limits.event_records,
                    hard_limits().event_records,
                )
            })?;
            if next > limits.event_records {
                return Err(resource_limit(
                    "event_records",
                    events,
                    node_events,
                    limits.event_records,
                    hard_limits().event_records,
                ));
            }
            events = next;
            for _ in 0..node_events {
                self.skip_value(0)?;
            }
        }
        Ok(())
    }

    fn skip_value(
        &mut self,
        depth: usize,
    ) -> Result<(), ProductionFaultRuntimeCheckpointCodecError> {
        if depth >= MAX_CBOR_DEPTH {
            return Err(ProductionFaultRuntimeCheckpointCodecError::Malformed);
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let argument = self.argument(initial & 0x1f)?;
        match major {
            0 | 1 | 7 => Ok(()),
            2 | 3 => {
                let _ = self.take(argument)?;
                Ok(())
            }
            4 => {
                for _ in 0..argument {
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            5 => {
                for _ in 0..argument {
                    self.skip_value(depth + 1)?;
                    self.skip_value(depth + 1)?;
                }
                Ok(())
            }
            6 => self.skip_value(depth + 1),
            _ => Err(ProductionFaultRuntimeCheckpointCodecError::Malformed),
        }
    }

    fn argument(
        &mut self,
        additional: u8,
    ) -> Result<u64, ProductionFaultRuntimeCheckpointCodecError> {
        match additional {
            value @ 0..=23 => Ok(u64::from(value)),
            24 => Ok(u64::from(self.byte()?)),
            25 => Ok(u64::from(u16::from_be_bytes(self.array()?))),
            26 => Ok(u64::from(u32::from_be_bytes(self.array()?))),
            27 => Ok(u64::from_be_bytes(self.array()?)),
            _ => Err(ProductionFaultRuntimeCheckpointCodecError::Malformed),
        }
    }

    fn byte(&mut self) -> Result<u8, ProductionFaultRuntimeCheckpointCodecError> {
        let value = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or(ProductionFaultRuntimeCheckpointCodecError::Malformed)?;
        self.offset += 1;
        Ok(value)
    }

    fn array<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], ProductionFaultRuntimeCheckpointCodecError> {
        self.take(u64::try_from(N).unwrap_or(u64::MAX))?
            .try_into()
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Malformed)
    }

    fn take(
        &mut self,
        length: u64,
    ) -> Result<&'a [u8], ProductionFaultRuntimeCheckpointCodecError> {
        let length = usize::try_from(length)
            .map_err(|_| ProductionFaultRuntimeCheckpointCodecError::Malformed)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ProductionFaultRuntimeCheckpointCodecError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProductionFaultRuntimeCheckpointCodecError::Malformed)?;
        self.offset = end;
        Ok(value)
    }
}

fn admit_collection(
    field: &'static str,
    requested: u64,
    configured: u64,
    hard: u64,
) -> Result<(), ProductionFaultRuntimeCheckpointCodecError> {
    if requested > configured {
        return Err(resource_limit(field, 0, requested, configured, hard));
    }
    Ok(())
}

fn resource_limit(
    field: &'static str,
    current: u64,
    requested: u64,
    configured: u64,
    hard: u64,
) -> ProductionFaultRuntimeCheckpointCodecError {
    ProductionFaultRuntimeCheckpointCodecError::ResourceLimit {
        field,
        current,
        requested,
        configured,
        hard,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Serialize;

    use super::*;

    #[derive(Serialize)]
    struct NodeMapOnly {
        qemu_fingerprints: BTreeMap<u8, u8>,
    }

    #[test]
    fn preflight_rejects_authored_node_count_before_owned_decode() {
        let payload = canonical_payload(&NodeMapOnly {
            qemu_fingerprints: BTreeMap::from([(1, 1), (2, 2)]),
        });
        let limits = FaultResourceLimits {
            nodes: 1,
            ..FaultResourceLimits::default()
        };

        assert_eq!(
            preflight_checkpoint_payload(&payload, limits),
            Err(resource_limit("nodes", 0, 2, 1, hard_limits().nodes,))
        );
    }

    #[derive(Serialize)]
    struct PendingEventsOnly {
        pending_qemu_events: BTreeMap<u8, Vec<Vec<u8>>>,
    }

    #[test]
    fn preflight_rejects_total_nested_event_count_at_exact_node() {
        let payload = canonical_payload(&PendingEventsOnly {
            pending_qemu_events: BTreeMap::from([(1, vec![vec![], vec![]])]),
        });
        let limits = FaultResourceLimits {
            nodes: 1,
            event_records: 1,
            ..FaultResourceLimits::default()
        };

        assert_eq!(
            preflight_checkpoint_payload(&payload, limits),
            Err(resource_limit(
                "event_records",
                0,
                2,
                1,
                hard_limits().event_records,
            ))
        );
    }

    fn canonical_payload(value: &impl Serialize) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(value, &mut bytes)
            .unwrap_or_else(|error| panic!("preflight fixture should encode: {error}"));
        bytes
    }
}
