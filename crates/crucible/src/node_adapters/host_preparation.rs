//! Authenticates public initial preparation of an actual owned integer clock.
//!
//! This selected live profile owns no timers, ports, inputs or autonomous work.
//! Its private model session and exact readiness body remain under the owning
//! node. Portable token/body hashes correlate that custody and grant no authority.
//! Legacy host continuation cannot omit these original preparation records.

use super::*;
use crucible_node_contract::{Extensions, PreparedOwner, SchemaRef};

/// Distinguishes actual construction from every authenticated restore path.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum HostPreparationOrigin {
    Original,
    Restored,
}

pub(super) struct HostPublicPreparation {
    anchor: Rc<()>,
    token: Id,
    session: ContentRef,
    session_bytes: Vec<u8>,
    native_ready: ContentRef,
    native_ready_bytes: Vec<u8>,
    ready: Option<(ActivationRecord, ReadyAttestation, Vec<u8>)>,
}

/// Defines the exact source-owned live preparation record semantics.
pub const HOST_PUBLIC_CLOCK_PREPARATION_SPECIFICATION: &str = "host public initial clock preparation v1: actual owned timer-free integer clock at epoch; original model construction and private memory session; source-installed model/artifact qualification; exact binding/owner roster and common ready body retained before public receipt; restored-at-zero and any input/operation history refused; original preparation records require a distinct preservation codec";

/// Returns the selected original-clock-session public preparation schema.
///
/// # Errors
/// Refuses invalid schema identities or hashing failure.
pub fn host_public_clock_preparation_schema() -> Result<SchemaRef, OperationFailure> {
    Ok(SchemaRef {
        id: Id::new("crucible/host-public-clock-preparation-v1")
            .map_err(|error| failure(&error.to_string()))?,
        version: 1,
        definition: canonical::content_ref(
            HOST_PUBLIC_CLOCK_PREPARATION_SPECIFICATION.as_bytes(),
            "text/plain",
        )
        .map_err(|error| failure(&error.to_string()))?,
        extensions: Extensions::new(),
    })
}

impl HostModelNode {
    /// Selects original public clock preparation under installed model policy.
    ///
    /// Failure leaves the actual owned clock inside this node. This first edition
    /// permits live public activation only and refuses legacy capture afterward.
    ///
    /// # Errors
    /// Refuses foreign graph/schema, restored or already used clock custody,
    /// missing installed qualification or non-clock/port-bearing models.
    pub fn qualify_public_initial_clock(
        &mut self,
        graph: &AdmittedGraph,
        qualification: &dyn HostModelQualification,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original_clock()?;
        let guarantee = graph
            .guarantees(&self.route.node)
            .ok_or_else(|| failure("public clock admitted guarantee is absent"))?;
        if guarantee.capture_scope != crucible_node_contract::CaptureScope::None
            || guarantee.continuation != crucible_node_contract::Continuation::Unsupported
            || guarantee.durable_restart
            || guarantee.isolated_fork
            || guarantee.conditional_replay
            || !graph.selected_extensions().is_empty()
            || graph.world_binding_hash() != &self.world_hash
            || graph.binding(&self.route.node) != Some(&self.binding)
            || graph.descriptor(&self.route.node) != Some(&self.descriptor)
            || !self
                .binding
                .compatibility
                .implementation
                .formats
                .contains(&host_public_clock_preparation_schema()?)
            || self.readiness.is_some()
            || self.public_preparation.is_some()
        {
            return Err(failure(
                "public initial clock is not its selected installed graph",
            ));
        }
        let model = self
            .model
            .as_ref()
            .ok_or_else(|| failure("actual clock is absent"))?;
        qualification.authenticate_model(model, &self.descriptor, &self.binding)?;
        let native_ready_bytes = self.receipt_bytes("host-model-owned-inactive-v1");
        let native_ready = canonical::content_ref(&native_ready_bytes, "application/octet-stream")
            .map_err(|error| failure(&error.to_string()))?;
        let session_bytes = canonical::canonical_json(&serde_json::json!({
            "format":"crucible.host.original-clock-session", "version":1,
            "world_hash":self.world_hash, "node":self.route.node,
            "owners":self.route.owners, "binding":self.binding.identity()
                .map_err(|error| failure(&error.to_string()))?,
            "initial_model":self.descriptor.initialization_ref,
            "original_native_ready":native_ready,
        }))
        .map_err(|error| failure(&error.to_string()))?;
        if session_bytes
            .len()
            .checked_add(native_ready_bytes.len())
            .is_none_or(|total| total > self.limits.maximum_capture_bytes)
        {
            return Err(failure(
                "original clock session exceeds admitted preparation credit",
            ));
        }
        let session = canonical::content_ref(&session_bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        let token = Id::new(format!("host/prepared/{}", session.hash.digest))
            .map_err(|error| failure(&error.to_string()))?;
        self.public_preparation = Some(HostPublicPreparation {
            anchor: Rc::clone(&self.original_model_session),
            token,
            session,
            session_bytes,
            native_ready,
            native_ready_bytes,
            ready: None,
        });
        Ok(())
    }

    fn authenticate_original_clock(&self) -> Result<(), OperationFailure> {
        if self.preparation_origin != HostPreparationOrigin::Original
            || !matches!(self.model.as_ref(), Some(HostModel::Clock(clock)) if clock.current_icount() == 0)
            || self.boundary != Position::new(0.into(), 0.into(), Phase::BoundaryControl)
            || self.quarantined
            || !self.completed.is_empty()
            || !self.failed.is_empty()
            || !self.input_history.is_empty()
            || self.staged.is_some()
            || !self.pending_causes.is_empty()
            || self.prepared_continuation.is_some()
            || self.input_endpoint.is_some()
            || self.output_endpoint.is_some()
            || self.native_sequence != 0
            || self.capture()?.as_slice() != self.initial.as_slice()
        {
            return Err(failure(
                "initial public clock lacks original untouched model custody",
            ));
        }
        Ok(())
    }

    pub(super) fn retain_public_clock_ready(
        &mut self,
        world: &ActivationRecord,
        ready: &mut ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.public_preparation.is_none() {
            return Ok(());
        }
        self.authenticate_original_clock()?;
        let preparation = self
            .public_preparation
            .as_mut()
            .ok_or_else(|| failure("original public clock session disappeared"))?;
        let bytes = canonical::canonical_json(&serde_json::json!({
            "format":"crucible.host.public-clock-ready", "version":1,
            "world":{
                "generation":world.generation,"activation_id":world.activation_id,
                "world_binding_hash":world.world_binding_hash,
                "owners":world.owners,"boundary":world.boundary,
            }, "session":preparation.session,
            "inventory":ready.state_inventory, "boundary":ready.boundary,
            "owners":ready.owners, "original_native_ready":preparation.native_ready,
        }))
        .map_err(|error| failure(&error.to_string()))?;
        if bytes
            .len()
            .checked_add(preparation.session_bytes.len())
            .and_then(|total| total.checked_add(preparation.native_ready_bytes.len()))
            .is_none_or(|total| total > self.limits.maximum_capture_bytes)
        {
            return Err(failure(
                "public clock ready bodies exceed original preparation credit",
            ));
        }
        ready.ready_receipt = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        if preparation
            .ready
            .as_ref()
            .is_some_and(|original| original != &(world.clone(), ready.clone(), bytes.clone()))
        {
            return Err(failure(
                "public clock is already prepared for another world",
            ));
        }
        preparation.ready = Some((world.clone(), ready.clone(), bytes));
        Ok(())
    }

    pub(super) fn public_clock_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        let Some(preparation) = &self.public_preparation else {
            return Ok(None);
        };
        self.authenticate_original_clock()?;
        let Some((original, retained, bytes)) = &preparation.ready else {
            return Err(failure("public clock has no original ready body"));
        };
        if original != world
            || retained != ready
            || !Rc::ptr_eq(&preparation.anchor, &self.original_model_session)
            || self.readiness.as_ref() != Some(&(world.clone(), ready.clone()))
        {
            return Err(failure(
                "public clock preparation has changed actual owner custody",
            ));
        }
        ready
            .ready_receipt
            .verify(bytes)
            .map_err(|error| failure(&error.to_string()))?;
        preparation
            .session
            .verify(&preparation.session_bytes)
            .map_err(|error| failure(&error.to_string()))?;
        preparation
            .native_ready
            .verify(&preparation.native_ready_bytes)
            .map_err(|error| failure(&error.to_string()))?;
        if preparation.native_ready_bytes != self.receipt_bytes("host-model-owned-inactive-v1") {
            return Err(failure("public clock original native ready body differs"));
        }
        let owner = self
            .route
            .owners
            .first()
            .filter(|_| self.route.owners.len() == 1)
            .ok_or_else(|| failure("public clock original owner roster is incomplete"))?;
        Ok(Some(vec![PreparedOwner {
            owner_id: owner.owner.clone(),
            incarnation_id: owner.incarnation.clone(),
            owner_generation: owner.generation,
            prepared_token: preparation.token.clone(),
            binding_hashes: vec![
                self.binding
                    .identity()
                    .map_err(|error| failure(&error.to_string()))?,
            ],
            ready_receipt: ready.ready_receipt.clone(),
            extensions: Extensions::new(),
        }]))
    }
}
