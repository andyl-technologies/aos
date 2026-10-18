//! Counts the concrete code-owner graph policy without a currency callback.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible::node_contract::RuntimeError;

impl PacketCompleteGraphOwner {
    pub(in crate::node_qualification::packet_collection::complete) fn charge_host_setup17_data(
        &self,
        counter: &mut Counter,
    ) -> Result<(), RuntimeError> {
        let Self { policy } = self;
        policy
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if counter
            .rc(policy)
            .map_err(|_| RuntimeError::ResourceLimit)?
        {
            policy
                .charge_retained_storage(counter)
                .map_err(|_| RuntimeError::ResourceLimit)?;
        }
        Ok(())
    }
}
