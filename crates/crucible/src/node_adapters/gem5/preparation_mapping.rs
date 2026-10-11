//! Retains genuine original native preparation beneath public owner mappings.
//!
//! This selected preparation-bearing profile keeps both the actual native Ready
//! packet and the common readiness body. A portable token or a binding hash is
//! never sufficient: every public mapping read revalidates the original owning
//! session and its current independently qualified stopped native authority.
//! Legacy native-continuation-v2 does not select or serialize this profile.

use crucible_node_contract::{ContentRef, Extensions, Id, PreparedOwner, SchemaRef, canonical};

use crate::node_contract::{ActivationRecord, OperationFailure, ReadyAttestation};

use crate::node_admission::AdmittedGraph;

use super::{
    Gem5PreparationQualification,
    node::{QualifiedGem5Node, native_refusal},
    refusal,
};

/// Preserves exact first preparation bodies before a public receipt is exposed.
pub(super) struct Gem5PreparedMapping {
    pub(super) world: ActivationRecord,
    pub(super) ready: ReadyAttestation,
    pub(super) owners: Vec<PreparedOwner>,
    pub(super) original_session: ContentRef,
    pub(super) original_packet: ContentRef,
}

impl QualifiedGem5Node {
    pub(super) fn retain_original_preparation_mapping(
        &mut self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
        ready_bytes: &[u8],
    ) -> Result<Gem5PreparedMapping, OperationFailure> {
        if self.quarantined
            || self.active.is_some()
            || self.ledger.operations().len() != 0
            || (self.restored.is_some() && !self.public_continuation)
            || world.world_binding_hash != self.preparation.world_binding_hash
            || world.boundary != self.readiness_boundary()?
            || ready.boundary != world.boundary
            || ready.owners != self.preparation.route.owners
            || self.preparation.route.owners.len() != 1
        {
            return Err(refusal(
                "public gem5 preparation lacks its untouched complete native owner",
            ));
        }
        ready
            .ready_receipt
            .verify(ready_bytes)
            .map_err(|error| refusal(&error.to_string()))?;
        let session = if self.restored.is_some() {
            self.preparation
                .native
                .restored_prepared_session(&self.authority)
        } else {
            self.preparation
                .native
                .initial_prepared_session(&self.authority)
        }
        .map_err(native_refusal)?;
        let (packet, packet_bytes) = session.packet();
        let (transcript, transcript_bytes) = session.transcript();
        let (closure, closure_bytes) = self.authority.evidence();
        if ready.state_inventory != *closure {
            return Err(refusal(
                "public gem5 readiness inventory differs from its actual live closure",
            ));
        }
        let owner = &self.preparation.route.owners[0];
        if !world.owners.contains(owner)
            || self.preparation.binding.authority.incarnation_id != owner.incarnation
            || self.preparation.binding.authority.owner_generation != owner.generation
        {
            return Err(refusal(
                "public gem5 owner mapping differs from actual admitted native custody",
            ));
        }
        let prepared = PreparedOwner {
            owner_id: owner.owner.clone(),
            incarnation_id: owner.incarnation.clone(),
            owner_generation: owner.generation,
            prepared_token: session.token().clone(),
            binding_hashes: vec![
                self.preparation
                    .binding
                    .identity()
                    .map_err(|error| refusal(&error.to_string()))?,
            ],
            ready_receipt: ready.ready_receipt.clone(),
            extensions: Extensions::new(),
        };
        let original_session = transcript.clone();
        let original_packet = packet.clone();

        // All original bodies consume the existing finite native evidence ledger
        // before the public mapping exists. No later observation regenerates them.
        self.ledger.retain_standalone(&[
            (&ready.ready_receipt, ready_bytes),
            (packet, packet_bytes),
            (transcript, transcript_bytes),
            (closure, closure_bytes),
        ])?;
        Ok(Gem5PreparedMapping {
            world: world.clone(),
            ready: ready.clone(),
            owners: vec![prepared],
            original_session,
            original_packet,
        })
    }

    pub(super) fn validate_original_preparation_mapping(
        &self,
        mapping: &Gem5PreparedMapping,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if mapping.world != *world
            || mapping.ready != *ready
            || self.world.as_ref() != Some(&(world.clone(), ready.clone()))
            || self.quarantined
            || self.active.is_some()
            || (self.restored.is_some() && !self.public_continuation)
            || self.readiness_boundary()? != ready.boundary
        {
            return Err(refusal(
                "public gem5 preparation mapping is foreign, restored or no longer inactive",
            ));
        }
        let session = if self.restored.is_some() {
            self.preparation
                .native
                .restored_prepared_session(&self.authority)
        } else {
            self.preparation
                .native
                .initial_prepared_session(&self.authority)
        }
        .map_err(native_refusal)?;
        if session.transcript().0 != &mapping.original_session
            || session.packet().0 != &mapping.original_packet
            || mapping.owners.len() != 1
            || mapping.owners[0].prepared_token != *session.token()
        {
            return Err(refusal(
                "public gem5 preparation no longer owns its original Ready/control session",
            ));
        }
        Ok(())
    }

    pub(super) fn original_prepared_owners(
        &self,
        mapping: &Gem5PreparedMapping,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Vec<PreparedOwner>, OperationFailure> {
        self.validate_original_preparation_mapping(mapping, world, ready)?;
        Ok(mapping.owners.clone())
    }
}

/// Retains the actual qualified native node after public preparation is refused.
pub struct Gem5PublicPreparationFailure {
    /// Describes the inactive preparation refusal without claiming native cleanup.
    pub error: OperationFailure,
    /// Retains the original native process, authority and supervisory reservation.
    pub node: QualifiedGem5Node,
}

/// Defines the exact source-owned live preparation record semantics.
pub const GEM5_PUBLIC_PREPARATION_SPECIFICATION: &str = "gem5 public initial preparation v1: actual untouched original native Ready wire packet; original PID/startticks and closed control session; installed controller/model and launch scope; current independently audited opaque native closure/exact authority; complete admitted owner binding roster; original common readiness body retained before public receipt; restored-at-zero and later native progress refused; capture requires a separately qualified preparation-bearing native codec";

/// Names the installed original-session public preparation record format.
///
/// The schema names evidence data only. Original native session custody and an
/// independently installed qualifier remain mandatory; hashes mint no readiness.
///
/// # Errors
/// Refuses invalid format identities or content-hash construction failure.
pub fn gem5_public_preparation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("crucible/gem5-public-preparation-v1")
            .map_err(|error| refusal(&error.to_string()))?,
        version: 1,
        definition: canonical::content_ref(
            GEM5_PUBLIC_PREPARATION_SPECIFICATION.as_bytes(),
            "text/plain",
        )
        .map_err(|error| refusal(&error.to_string()))?,
        extensions: Extensions::new(),
    })
}

impl QualifiedGem5Node {
    /// Selects genuine initial public preparation under independently installed policy.
    ///
    /// This first edition permits live preparation only. Legacy native-v2 capture
    /// remains refused because it does not preserve the original preparation
    /// bodies. The actual node and its native resources are returned on refusal.
    ///
    /// # Errors
    /// Refuses missing installed schema/policy, reconstructed or already armed
    /// peers, changed native identity or any advertised preservation guarantee.
    pub fn into_public_initial_preparation(
        mut self,
        graph: &AdmittedGraph,
        qualification: &dyn Gem5PreparationQualification,
    ) -> Result<Self, Box<Gem5PublicPreparationFailure>> {
        let validate = || {
            let node = &self.preparation.route.node;
            if self.archive.is_some()
                || !graph.selected_extensions().is_empty()
                || (self.restored.is_some() && !self.public_continuation)
                || self.world.is_some()
                || self.active.is_some()
                || self.quarantined
                || graph.world_binding_hash() != &self.preparation.world_binding_hash
                || graph.binding(node) != Some(&self.preparation.binding)
                || !self
                    .preparation
                    .binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(&gem5_public_preparation_schema()?)
            {
                return Err(refusal(
                    "gem5 public initial preparation is not its selected live installed profile",
                ));
            }
            qualification.authenticate_preparation(&self.preparation.native, graph, node)?;
            self.preparation
                .native
                .initial_prepared_session(&self.authority)
                .map_err(native_refusal)?;
            Ok(())
        };
        if let Err(error) = validate() {
            return Err(Box::new(Gem5PublicPreparationFailure { error, node: self }));
        }
        self.public_preparation = true;
        Ok(self)
    }
}
