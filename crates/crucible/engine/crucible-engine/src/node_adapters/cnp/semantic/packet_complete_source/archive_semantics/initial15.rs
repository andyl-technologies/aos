//! Retains every completed semantic5 decode product through a later refusal.
//!
//! A successful borrowed DATA decode does not issue Source, native or runtime
//! authority. The enclosing initial15 group performs all independent joins.

use super::decoded_storage::{Census, Owned};
use super::*;
use serde_json::Value;
use std::mem::size_of;

pub(in crate::node_adapters::cnp::semantic::packet_complete_source) struct Initial15SemanticAttempt
{
    semantic_value: Option<Value>,
    ancestry_value: Option<Value>,
    semantic: Option<data::ArchivedSemanticCustody>,
    ancestry: Option<data::ArchivedAncestry>,
    completed: Option<PacketCompleteArchivedSemantics>,
    attempted: bool,
    verified: bool,
}

impl Initial15SemanticAttempt {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn new_data() -> Self {
        Self {
            semantic_value: None,
            ancestry_value: None,
            semantic: None,
            ancestry: None,
            completed: None,
            attempted: false,
            verified: false,
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn read_data(
        &mut self,
        semantic: &[u8],
        ancestry: &[u8],
        maximum_record: usize,
        additional: usize,
        maximum: usize,
    ) -> Result<(), OperationFailure> {
        if self.attempted {
            return Err(refused("initial15 semantic decode attempt spent"));
        }
        self.attempted = true;
        let demand = PacketCompleteArchivedSemantics::decode_demand_data(
            semantic,
            ancestry,
            maximum_record,
            maximum,
        )?;
        // Both original DOMs and independently typed trees remain retained.
        // Two further DOMs can coexist during the defining lossless comparisons.
        additional
            .checked_add(
                demand
                    .checked_mul(2)
                    .ok_or_else(|| refused("initial15 semantic decoder extent overflow"))?,
            )
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .filter(|n| *n <= maximum)
            .ok_or_else(|| refused("initial15 complete semantic decoder credit exhausted"))?;
        self.semantic_value =
            Some(canonical::parse_json(semantic, maximum_record).map_err(unknown)?);
        self.ancestry_value =
            Some(canonical::parse_json(ancestry, maximum_record).map_err(unknown)?);
        self.semantic = Some(
            data::ArchivedSemanticCustody::deserialize(
                self.semantic_value
                    .as_ref()
                    .ok_or_else(|| refused("initial15 semantic DOM absent"))?,
            )
            .map_err(unknown)?,
        );
        self.ancestry = Some(data::ArchivedAncestry::decode(
            self.ancestry_value
                .as_ref()
                .ok_or_else(|| refused("initial15 ancestry DOM absent"))?,
        )?);
        self.completed = Some(PacketCompleteArchivedSemantics {
            semantic: self
                .semantic
                .take()
                .ok_or_else(|| refused("initial15 typed semantic absent"))?,
            ancestry: self
                .ancestry
                .take()
                .ok_or_else(|| refused("initial15 typed ancestry absent"))?,
            reserved_decoder_bytes: demand,
        });
        let decoded = self
            .completed
            .as_ref()
            .ok_or_else(|| refused("initial15 semantic result absent"))?;
        if decoded.semantic.schema != "source-owned.packet-semantic-custody/5"
            || !matches!(decoded.ancestry, data::ArchivedAncestry::References(_))
            || serde_json::to_value(&decoded.semantic).map_err(unknown)?
                != *self
                    .semantic_value
                    .as_ref()
                    .ok_or_else(|| refused("initial15 semantic DOM absent"))?
            || serde_json::to_value(&decoded.ancestry).map_err(unknown)?
                != *self
                    .ancestry_value
                    .as_ref()
                    .ok_or_else(|| refused("initial15 ancestry DOM absent"))?
        {
            return Err(refused("initial15 closed semantic/ancestry fields differ"));
        }
        self.verified = true;
        Ok(())
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn read_data_ref(
        &self,
    ) -> Result<&PacketCompleteArchivedSemantics, OperationFailure> {
        if !self.verified {
            return Err(refused("initial15 semantic decode incomplete"));
        }
        self.completed
            .as_ref()
            .ok_or_else(|| refused("initial15 semantic result absent"))
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            semantic_value: _,
            ancestry_value: _,
            semantic: _,
            ancestry: _,
            completed: _,
            attempted: _,
            verified: _,
        } = self;
        let mut census = Census::new(maximum);
        census.add(size_of::<Self>())?;
        census.charge(&self.semantic_value)?;
        census.charge(&self.ancestry_value)?;
        census.charge(&self.semantic)?;
        census.charge(&self.ancestry)?;
        if let Some(decoded) = &self.completed {
            let nested = decoded
                .retained_requested_storage_data(maximum)?
                .checked_sub(size_of::<PacketCompleteArchivedSemantics>())
                .ok_or(RuntimeError::ResourceLimit)?;
            census.add(nested)?;
        }
        Ok(census.bytes())
    }
}
