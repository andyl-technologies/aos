//! Retains original ARM Ready bodies beneath complete public preparation.
//!
//! The native session is borrowed only through its current opaque authority.
//! This initial mapping refuses reconstructed construction, including tick zero.
//! Historical mappings will come from the separately authenticated Root codec;
//! portable tokens and profile hashes never substitute for that source seal.

use crucible_node_contract::{ContentRef, Extensions, PreparedOwner, canonical};
use crucible_node_provider::gem5::ArmRootExactAuthority;

use super::{ArmRootNodePreparation, encoding, ledger::RootLedger, refusal};
use crate::node_contract::{ActivationRecord, OperationFailure, ReadyAttestation};
use serde::Serialize;

#[derive(Serialize)]
struct ReadinessWire<'a> {
    schema: &'static str,
    world: crate::node_contract::SavedRuntimeActivation,
    node: &'a crucible_node_contract::Id,
    owners: &'a [crate::node_contract::OwnerIdentity],
    binding: &'a crucible_node_contract::HashRef,
    native_boundary: &'a crucible_node_provider::gem5::Gem5Boundary,
    native_packet: &'a ContentRef,
    native_session: &'a ContentRef,
    independent_closure: &'a ContentRef,
}

pub(super) struct ArmRootPreparedMapping {
    pub(super) world: ActivationRecord,
    pub(super) ready: ReadyAttestation,
    pub(super) owner: PreparedOwner,
    pub(super) original_packet: ContentRef,
    pub(super) original_session: ContentRef,
}

impl ArmRootPreparedMapping {
    pub(super) fn prepare(
        preparation: &ArmRootNodePreparation,
        authority: &ArmRootExactAuthority,
        world: &ActivationRecord,
        maximum_bytes: usize,
        ledger: &mut RootLedger,
        restored: Option<&super::AuthenticatedArmRootContinuation>,
    ) -> Result<Self, OperationFailure> {
        if maximum_bytes == 0
            || maximum_bytes > 256 * 1024 * 1024
            || world.world_binding_hash != preparation.world_binding_hash
            || preparation.route.owners.len() != 1
            || !world.owners.contains(&preparation.route.owners[0])
            || world.boundary
                != restored.map_or_else(
                    || preparation.native.logical_position(),
                    |source| source.common_cut(),
                )
        {
            return Err(refusal(
                "ARM original preparation differs from its actual complete world scope",
            ));
        }
        let session = match restored {
            Some(source) => {
                super::restore::validate_target(preparation, authority, source, world)?;
                preparation
                    .native
                    .restored_prepared_session(authority, source.capture())
            }
            None => preparation.native.initial_prepared_session(authority),
        }
        .map_err(|error| refusal(&error.to_string()))?;
        let (packet, packet_bytes) = session.packet();
        let (transcript, transcript_bytes) = session.transcript();
        let (closure, closure_bytes) = authority.evidence();
        let binding = preparation
            .binding
            .identity()
            .map_err(|error| refusal(&error.to_string()))?;

        let remaining = [packet_bytes, transcript_bytes, closure_bytes]
            .iter()
            .try_fold(maximum_bytes, |remaining, bytes| {
                remaining.checked_sub(bytes.len())
            })
            .ok_or_else(|| refusal("ARM preparation original body credits are exhausted"))?;
        let bytes = encoding::record(
            &ReadinessWire {
                schema: "crucible.gem5.arm-root-common-readiness.v1",
                world: crate::node_contract::SavedRuntimeActivation::from(world),
                node: &preparation.route.node,
                owners: &preparation.route.owners,
                binding: &binding,
                native_boundary: preparation.native.boundary(),
                native_packet: packet,
                native_session: transcript,
                independent_closure: closure,
            },
            remaining,
        )?;
        let reference = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| refusal(&error.to_string()))?;
        let ready = ReadyAttestation {
            owners: preparation.route.owners.clone(),
            boundary: world.boundary,
            state_inventory: closure.clone(),
            ready_receipt: reference.clone(),
        };
        let owner = &preparation.route.owners[0];
        let prepared = PreparedOwner {
            owner_id: owner.owner.clone(),
            incarnation_id: owner.incarnation.clone(),
            owner_generation: owner.generation,
            prepared_token: session.token().clone(),
            binding_hashes: vec![binding],
            ready_receipt: reference.clone(),
            extensions: Extensions::new(),
        };

        // Retain every original body before returning a public mapping. Native
        // session validation has no modeled effect; storage refusal cannot leave
        // a published token referring to missing readiness bytes.
        let originals = [
            (&reference, bytes.as_slice()),
            (packet, packet_bytes),
            (transcript, transcript_bytes),
            (closure, closure_bytes),
        ];
        let mut total = 0usize;
        for (reference, body) in originals {
            reference
                .verify(body)
                .map_err(|error| refusal(&error.to_string()))?;
            total = total
                .checked_add(body.len())
                .filter(|total| *total <= maximum_bytes)
                .ok_or_else(|| refusal("ARM preparation body credit is exhausted"))?;
        }
        ledger.retain_standalone(&originals)?;
        Ok(Self {
            world: world.clone(),
            ready,
            owner: prepared,
            original_packet: packet.clone(),
            original_session: transcript.clone(),
        })
    }

    pub(super) fn validate_current(
        &self,
        preparation: &ArmRootNodePreparation,
        authority: &ArmRootExactAuthority,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        restored: Option<&super::AuthenticatedArmRootContinuation>,
    ) -> Result<(), OperationFailure> {
        if &self.world != world
            || &self.ready != ready
            || restored.is_none() && preparation.native.logical_position() != ready.boundary
            || world.world_binding_hash != preparation.world_binding_hash
            || ready.owners != preparation.route.owners
        {
            return Err(refusal("ARM original public readiness scope changed"));
        }
        let session = match restored {
            Some(source) => {
                super::restore::validate_target(preparation, authority, source, world)?;
                preparation
                    .native
                    .restored_prepared_session(authority, source.capture())
            }
            None => preparation.native.initial_prepared_session(authority),
        }
        .map_err(|error| refusal(&error.to_string()))?;
        if session.token() != &self.owner.prepared_token
            || session.packet().0 != &self.original_packet
            || session.transcript().0 != &self.original_session
            || authority.evidence().0 != &ready.state_inventory
        {
            return Err(refusal(
                "ARM public mapping no longer owns its original native session",
            ));
        }
        Ok(())
    }
}
