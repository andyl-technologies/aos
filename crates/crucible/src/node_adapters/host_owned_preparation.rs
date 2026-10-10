//! Retains actual original public preparation of finite Script and Block models.
//!
//! The selected installed policy authenticates the complete world and original
//! initialized model. Private session identity and exact original readiness stay
//! with that same owning node; portable owner records only describe this custody.
//! Legacy model capture cannot omit these preparation records.

use super::*;
use crucible_node_contract::{Extensions, PreparedOwner};

#[path = "host_owned_preparation/credit.rs"]
mod credit;

#[path = "host_owned_preparation/continuation.rs"]
pub(super) mod continuation;

#[path = "host_owned_preparation/restored.rs"]
mod restored;

pub use continuation::{
    HOST_PUBLIC_OWNED_MODEL_CONTINUATION_PROFILE,
    HOST_PUBLIC_OWNED_MODEL_CONTINUATION_SPECIFICATION,
    host_public_owned_model_continuation_schema, validate_public_owned_model_continuation,
};

/// Defines the separately selected original finite-model preparation semantics.
pub const HOST_PUBLIC_OWNED_MODEL_PREPARATION_SPECIFICATION: &str = "host public original owned model preparation v1: original independently owned finite Block request script or Block/COW model; separately installed complete-world policy and immutable input/model qualification; actual initialized state and private memory session; exact complete graph owner/binding roster and original readiness retained; restored, used, recorded, condition and other models refused; no continuation, capture, fork or replay qualification";

pub(super) struct OriginalOwnedModelPreparation {
    anchor: Rc<()>,
    token: Id,
    session: ContentRef,
    session_bytes: Vec<u8>,
    initial_native: ContentRef,
    native_ready: ContentRef,
    native_ready_bytes: Vec<u8>,
    world_owners: Vec<OwnerIdentity>,
    ready: Option<(ActivationRecord, ReadyAttestation, Vec<u8>)>,
    previous: Option<ContentRef>,
}

impl HostModelNode {
    /// Selects public initial preparation of an actual original Script or Block.
    ///
    /// This attachment retains the same model and private memory session. It
    /// requires separate installed whole-world qualification and refuses legacy
    /// capture rather than discarding original public preparation history.
    ///
    /// # Errors
    /// Refuses unsupported, restored, already armed or changed native custody,
    /// a foreign graph, or missing installed complete-world qualification.
    pub fn qualify_public_initial_owned_model(
        &mut self,
        graph: &AdmittedGraph,
        qualification: &dyn HostModelQualification,
    ) -> Result<(), OperationFailure> {
        self.authenticate_original_owned_model()?;
        if graph.world_binding_hash() != &self.world_hash
            || graph.binding(&self.route.node) != Some(&self.binding)
            || graph.descriptor(&self.route.node) != Some(&self.descriptor)
            || !graph.selected_extensions().is_empty()
            || self.readiness.is_some()
            || self.public_preparation.is_some()
            || self.public_model_preparation.is_some()
        {
            return Err(failure(
                "original model preparation names a foreign or used graph",
            ));
        }
        let model = self
            .model
            .as_ref()
            .ok_or_else(|| failure("original model is absent"))?;
        qualification.authenticate_model(model, &self.descriptor, &self.binding)?;
        qualification.authenticate_initial_owned_model(
            model,
            graph,
            &self.descriptor,
            &self.binding,
        )?;

        let count = graph.node_ids().count();
        if count == 0 || count > 64 {
            return Err(failure(
                "original model preparation exceeds selected owner credit",
            ));
        }
        let native_length = credit::native_ready_length(self)?;
        let remaining = self
            .limits
            .maximum_capture_bytes
            .checked_sub(native_length)
            .ok_or_else(|| failure("original native readiness exceeds preparation credit"))?;
        let initial_native =
            canonical::content_ref(self.initial.as_slice(), "application/octet-stream")
                .map_err(|error| failure(&error.to_string()))?;
        let native_ready_bytes = self.receipt_bytes("host-model-owned-inactive-v1");
        if native_ready_bytes.len() != native_length {
            return Err(failure(
                "original native readiness differs from precredited geometry",
            ));
        }
        let native_ready = canonical::content_ref(&native_ready_bytes, "application/octet-stream")
            .map_err(|error| failure(&error.to_string()))?;
        let binding_hash = self
            .binding
            .identity()
            .map_err(|error| failure(&error.to_string()))?;
        let session_length = credit::session_length(
            self,
            graph,
            &initial_native,
            &native_ready,
            &binding_hash,
            remaining,
        )?;

        // Only the borrowed complete geometry has consumed serialized credit;
        // owner copies and a canonical value tree follow that successful check.
        let mut world_owners = Vec::new();
        world_owners
            .try_reserve_exact(count)
            .map_err(|_| failure("original model owner reservation failed"))?;
        for node in graph.node_ids() {
            let original = graph
                .binding(node)
                .ok_or_else(|| failure("original graph binding is absent"))?;
            world_owners.push(OwnerIdentity {
                owner: original.compatibility.execution_owner.id.clone(),
                incarnation: original.authority.incarnation_id.clone(),
                generation: original.authority.owner_generation,
            });
        }
        world_owners.sort();
        if world_owners
            .windows(2)
            .any(|pair| pair[0].owner == pair[1].owner)
        {
            return Err(failure(
                "public finite-model preparation requires independent original owners",
            ));
        }

        let session_bytes = credit::encode_session(
            self,
            (&initial_native, &native_ready, &binding_hash),
            &world_owners,
        )?;
        if session_bytes.len() != session_length {
            return Err(failure(
                "original session serialization differs from precredited geometry",
            ));
        }
        let session = canonical::content_ref(&session_bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        let token = Id::new(format!("host/model-prepared/{}", session.hash.digest))
            .map_err(|error| failure(&error.to_string()))?;
        self.public_model_preparation = Some(OriginalOwnedModelPreparation {
            anchor: Rc::clone(&self.original_model_session),
            token,
            session,
            session_bytes,
            initial_native,
            native_ready,
            native_ready_bytes,
            world_owners,
            ready: None,
            previous: None,
        });
        Ok(())
    }

    fn authenticate_original_owned_model(&self) -> Result<(), OperationFailure> {
        let supported = match self.model.as_ref() {
            Some(HostModel::ScriptedSource(source)) => {
                source.kind() == super::super::ScriptedRequestKind::Block
            }
            Some(HostModel::Io(node)) => node.block_device().is_some(),
            _ => false,
        };
        if !supported
            || self.preparation_origin != HostPreparationOrigin::Original
            || self.boundary != Position::new(0.into(), 0.into(), Phase::BoundaryControl)
            || self.quarantined
            || !self.completed.is_empty()
            || !self.failed.is_empty()
            || !self.input_history.is_empty()
            || self.staged.is_some()
            || !self.pending_causes.is_empty()
            || self.prepared_continuation.is_some()
            || self.recorded_ingress.is_some()
            || self.condition_preservation
            || self.native_sequence != 0
            || self.route.owners.len() != 1
            || self.capture()?.as_slice() != self.initial.as_slice()
        {
            return Err(failure(
                "public model lacks original unchanged inactive custody",
            ));
        }
        Ok(())
    }

    pub(super) fn retain_owned_model_ready(
        &mut self,
        world: &ActivationRecord,
        ready: &mut ReadyAttestation,
    ) -> Result<(), OperationFailure> {
        if self.public_model_preparation.is_none() {
            if self.public_model_history.is_some() {
                return Err(failure(
                    "retained restored capsule has no successful fresh preparation",
                ));
            }
            return Ok(());
        }
        self.authenticate_owned_model_preparation()?;
        if self
            .public_model_history
            .as_ref()
            .is_some_and(|history| &history.target != world)
        {
            return Err(failure(
                "restored public readiness has another authenticated target",
            ));
        }
        let total_credit = self.restored_preparation_credit()?;
        let preparation = self
            .public_model_preparation
            .as_mut()
            .ok_or_else(|| failure("original owned-model session disappeared"))?;
        if world.owners != preparation.world_owners
            || ready.ready_receipt != preparation.native_ready
        {
            return Err(failure(
                "original model readiness has another complete owner roster",
            ));
        }
        preparation
            .initial_native
            .verify(self.initial.as_slice())
            .map_err(|error| failure(&error.to_string()))?;
        preparation
            .native_ready
            .verify(&preparation.native_ready_bytes)
            .map_err(|error| failure(&error.to_string()))?;
        let remaining = total_credit
            .checked_sub(preparation.session_bytes.len())
            .and_then(|remaining| remaining.checked_sub(preparation.native_ready_bytes.len()))
            .ok_or_else(|| failure("retained original session exceeds preparation credit"))?;
        let ready_length = credit::ready_length(world, ready, preparation, remaining)?;
        let bytes = credit::encode_ready(world, ready, preparation)?;
        if bytes.len() != ready_length {
            return Err(failure(
                "original readiness differs from precredited geometry",
            ));
        }
        ready.ready_receipt = canonical::content_ref(&bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        if preparation
            .ready
            .as_ref()
            .is_some_and(|(original, retained, body)| {
                original != world || retained != ready || body != &bytes
            })
        {
            return Err(failure(
                "original model was armed for another complete world",
            ));
        }
        preparation.ready = Some((world.clone(), ready.clone(), bytes));
        Ok(())
    }

    pub(super) fn original_model_owners(
        &self,
        world: &ActivationRecord,
        ready: &ReadyAttestation,
    ) -> Result<Option<Vec<PreparedOwner>>, OperationFailure> {
        let Some(preparation) = &self.public_model_preparation else {
            if self.public_model_history.is_some() {
                return Err(failure(
                    "restored source capsule has no fresh public preparation",
                ));
            }
            return Ok(None);
        };
        self.authenticate_owned_model_preparation()?;
        let Some((original, retained, bytes)) = &preparation.ready else {
            return Err(failure("original model has no retained readiness body"));
        };
        if original != world
            || retained != ready
            || !Rc::ptr_eq(&preparation.anchor, &self.original_model_session)
            || self
                .readiness
                .as_ref()
                .is_none_or(|(original, retained)| original != world || retained != ready)
        {
            return Err(failure(
                "original model preparation has foreign actual custody",
            ));
        }
        preparation
            .initial_native
            .verify(self.initial.as_slice())
            .map_err(|error| failure(&error.to_string()))?;
        preparation
            .session
            .verify(&preparation.session_bytes)
            .map_err(|error| failure(&error.to_string()))?;
        ready
            .ready_receipt
            .verify(bytes)
            .map_err(|error| failure(&error.to_string()))?;
        preparation
            .native_ready
            .verify(&preparation.native_ready_bytes)
            .map_err(|error| failure(&error.to_string()))?;
        if preparation.native_ready_bytes != self.receipt_bytes("host-model-owned-inactive-v1") {
            return Err(failure("original model native readiness body changed"));
        }
        let owner = self
            .route
            .owners
            .first()
            .ok_or_else(|| failure("original model owner is absent"))?;
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

#[cfg(test)]
#[path = "host_owned_preparation/tests.rs"]
mod tests;
