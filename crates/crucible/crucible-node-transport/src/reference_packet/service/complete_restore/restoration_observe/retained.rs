//! Walks actual independent observation owners without encoding their backing.

use super::*;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata, RetainedProtocolMetadataFacts};

/// Borrows actual observation originals; containing roots are counted by callers.
pub enum RetainedRestorationObservationData<'a> {
    /// Borrows the separately owned baseline method body.
    Body(&'a crate::bodies::ObserveRequest),
    /// Borrows the complete unsigned observation request.
    Request(&'a PacketRestorationObservationRequest),
    /// Borrows the separately owned full MAC context.
    Context(&'a PacketRestorationObservationContext),
    /// Borrows the actual proof data owner.
    Proof(&'a PacketRestorationObservationProof),
    /// Borrows the complete independently retained inline artifact.
    Artifact(&'a PacketRestorationObservationArtifact),
    /// Borrows the actual typed terminal, including error/raw owners.
    Response(&'a crate::bodies::ResponseBody),
}

impl RetainedRestorationObservationData<'_> {
    /// Names the defining borrowed observation DTO controls.
    pub(crate) fn capacity_counter_scratch_data() -> usize {
        counter_scratch_data()
    }

    /// Counts real nested capacities without serializing or accepting authority.
    ///
    /// # Errors
    /// Refuses checked traversal overflow, finite observer limits or another
    /// typed terminal variant. Already retained owning parents remain intact.
    pub fn original_retained_metadata_facts(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_owned_metadata_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Visits this actual independent owner under the caller's raw traversal.
    ///
    /// # Errors
    /// Refuses metadata overflow/limits or an unsupported typed response variant.
    pub(crate) fn observe_owned_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Body(value) => {
                let crate::bodies::ObserveRequest {
                    binding_hash,
                    owner_generation,
                    after_observation_sequence,
                    maximum_items,
                    extensions,
                } = value;
                observer.observe(binding_hash)?;
                observer.observe(owner_generation)?;
                observer.observe(after_observation_sequence)?;
                observer.observe(maximum_items)?;
                observer.observe(extensions)?;
            }
            Self::Request(value) => observer.observe(*value)?,
            Self::Context(value) => observer.observe(*value)?,
            Self::Proof(value) => observer.observe(*value)?,
            Self::Artifact(value) => observer.observe(*value)?,
            Self::Response(value) => response(value, observer)?,
        }
        Ok(())
    }
}

macro_rules! fields {
    ($ty:ty,$($field:ident),+ $(,)?) => {
        impl ObserveMetadata for $ty {
            fn observe_metadata(&self, observer:&mut MetadataObserver<'_>)->Result<(),ProviderError> {
                let Self {$($field),+}=self;
                $(observer.observe($field)?;)+
                Ok(())
            }
        }
        impl $ty {
            /// Visits actual owned fields after the caller retains its root.
            pub(crate) fn observe_owned_metadata_data(&self, observer:&mut MetadataObserver<'_>)->Result<(),ProviderError> {
                observer.observe(self)
            }
        }
    };
}
fields!(
    PacketRestorationObservationRequest,
    schema,
    scope,
    world_original,
    world_terminal,
    maximum_items,
    native_allocation
);
fields!(
    PacketRestorationObservationContext,
    request,
    assigned_request
);
fields!(
    PacketRestorationObservationProof,
    schema,
    algorithm,
    context_digest,
    mac
);
fields!(PacketRestorationObservationArtifact, request, proof);

fn response(
    body: &crate::bodies::ResponseBody,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    use crate::bodies::{MethodResult, ObserveResult, ResponseBody, ResponseShape};
    let ResponseBody { shape, result } = body;
    match shape {
        ResponseShape::Accepted {
            operation_state,
            result,
            extensions,
        }
        | ResponseShape::Completed {
            operation_state,
            result,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(result)?;
            observer.observe(extensions)?;
        }
        ResponseShape::Error {
            operation_state,
            error,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(error)?;
            observer.observe(extensions)?;
        }
    }
    match result {
        None => Ok(()),
        Some(MethodResult::Observe(value)) => {
            let ObserveResult {
                observations,
                next_sequence,
                complete,
                inventory_hash,
            } = value;
            observer.observe(observations)?;
            observer.observe(next_sequence)?;
            observer.observe(complete)?;
            observer.observe(inventory_hash)
        }
        _ => Err(super::invalid()),
    }
}

pub(super) fn counter_scratch_data() -> usize {
    use crate::bodies::{
        ErrorRecord, MethodResult, ObserveResult, OperationState, ResponseBody, ResponseShape,
    };
    use std::mem::size_of;
    size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<&ResponseBody>()
        + size_of::<&ResponseShape>()
        + size_of::<&Option<MethodResult>>()
        + size_of::<&ObserveResult>()
        + size_of::<(
            &String,
            &PacketRestorationActivationScope,
            &ContentRef,
            &ContentRef,
            &U64,
            &PacketRestorationActivationAllocationRow,
        )>()
        + size_of::<(&PacketRestorationObservationRequest, &Bytes)>()
        + size_of::<(&String, &String, &Bytes, &Bytes)>()
        + size_of::<(
            &PacketRestorationObservationRequest,
            &PacketRestorationObservationProof,
        )>()
        + size_of::<(
            &crucible_node_format::HashRef,
            &U64,
            &U64,
            &U64,
            &crucible_node_format::Extensions,
        )>()
        + size_of::<(
            &Vec<crucible_node_format::ObservationBatch>,
            &U64,
            &bool,
            &crucible_node_format::HashRef,
        )>()
        + 2 * size_of::<(
            &OperationState,
            &serde_json::Map<String, serde_json::Value>,
            &crucible_node_format::Extensions,
        )>()
        + size_of::<(
            &OperationState,
            &ErrorRecord,
            &crucible_node_format::Extensions,
        )>()
}
