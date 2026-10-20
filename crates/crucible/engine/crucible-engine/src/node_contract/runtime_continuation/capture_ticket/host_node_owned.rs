//! Counts independently owned original Host node metadata using precise walkers.

use super::*;
use crate::node_contract::{ActivationRecord, NodeRoute, ReadyAttestation};

impl crate::node_contract::NodeRuntime {
    pub(crate) fn capture_host_node_metadata_storage(
        activation: &ActivationRecord,
        route: &NodeRoute,
        ready: Option<&(ReadyAttestation, Vec<u8>)>,
    ) -> Result<usize, RuntimeError> {
        let mut total = storage::add(activation.owned_storage()?, route.owned_storage()?)?;
        if let Some((attestation, bytes)) = ready {
            let ReadyAttestation {
                owners,
                boundary: _,
                state_inventory,
                ready_receipt,
            } = attestation;
            total = storage::add(total, owners.owned_storage()?)?;
            total = storage::add(total, state_inventory.owned_storage()?)?;
            total = storage::add(total, ready_receipt.owned_storage()?)?;
            total = storage::add(total, bytes.capacity())?;
        }
        Ok(total)
    }
}
