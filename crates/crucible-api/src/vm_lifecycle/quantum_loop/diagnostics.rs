//! Advisory diagnostics through the original owned lifecycle node leases.

use super::*;

pub(super) fn observe_owned_node_diagnostics(
    leases: &mut BTreeMap<NodeId, Box<dyn ProductionVmNodeLease>>,
) {
    for lease in leases.values_mut() {
        lease.observe_operational_diagnostics();
    }
}

#[cfg(test)]
mod tests;
