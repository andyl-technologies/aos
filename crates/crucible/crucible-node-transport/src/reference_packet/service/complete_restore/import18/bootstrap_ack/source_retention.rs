//! Observes actual bootstrap18 DTO backing, including invalid failed partials.
//!
//! The shared defining walk preserves every field independently. It parses,
//! authenticates and clones nothing, and exports no live MetadataObserver.

use super::*;
use crate::retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts};
use std::mem::size_of;

/// Selects one borrowed actual DTO without issuing its success or origin claim.
#[derive(Clone, Copy)]
pub enum PacketNativeImport18BootstrapRetainedData<'a> {
    /// Borrows the closed profile-specific request.
    Request(&'a PacketNativeImport18BootstrapRequest),
    /// Borrows the bootstrap-only method result.
    Result(&'a PacketNativeImport18BootstrapResult),
    /// Borrows the complete original context.
    Context(&'a PacketNativeImport18BootstrapAckContext),
    /// Borrows the Source proof, including failed partial fields.
    Proof(&'a PacketNativeImport18BootstrapAckProof),
    /// Borrows the native terminal receipt, including failed partial fields.
    Receipt(&'a PacketNativeImport18BootstrapAckReceipt),
}

impl PacketNativeImport18BootstrapRetainedData<'_> {
    /// Reports actual retained nested backing without checking DTO eligibility.
    ///
    /// # Errors
    /// Refuses metadata traversal or checked backing arithmetic exhaustion.
    pub fn retained_metadata_data(self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Reports the actual maximum sequential Bytes formatter temporary.
    ///
    /// This is separate from the output Value/canonical/parser and parent owners.
    /// Invalid partial digest banks are measured at their actual retained lengths.
    ///
    /// # Errors
    /// Refuses metadata traversal or checked base64 output extent overflow.
    pub fn serialization_transient_bytes_data(self) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_data(&mut observer)?;
        observer
            .ordinary_bytes_formatter_data()
            .maximum_temporary_requested_bytes_data()
    }

    pub(in crate::reference_packet) fn observe_data(
        self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Request(value) => {
                let PacketNativeImport18BootstrapRequest {
                    schema,
                    recipe_identity,
                    initial_funding,
                } = value;
                observer.observe(schema)?;
                observer.observe(recipe_identity)?;
                row(initial_funding, observer)
            }
            Self::Result(value) => {
                let PacketNativeImport18BootstrapResult {
                    schema,
                    state,
                    recipe_identity,
                    initial_funding,
                } = value;
                observer.observe(schema)?;
                match state {
                    PacketNativeImport18BootstrapAckState::BootstrapOnly => {}
                }
                observer.observe(recipe_identity)?;
                row(initial_funding, observer)
            }
            Self::Context(value) => {
                let PacketNativeImport18BootstrapAckContext {
                    schema,
                    algorithm,
                    source_birth,
                    kernel_binding,
                    policy_binding,
                    host_registration,
                    native_registration,
                    hello_request,
                    hello_response,
                    assigned_request,
                    recipe_identity,
                    initial_funding,
                } = value;
                observer.observe(schema)?;
                observer.observe(algorithm)?;
                for digest in [
                    source_birth,
                    kernel_binding,
                    policy_binding,
                    host_registration,
                    native_registration,
                    hello_request,
                    hello_response,
                    assigned_request,
                    recipe_identity,
                ] {
                    observer.observe(digest)?;
                }
                row(initial_funding, observer)
            }
            Self::Proof(value) => {
                let PacketNativeImport18BootstrapAckProof {
                    schema,
                    algorithm,
                    context_digest,
                    mac,
                } = value;
                observer.observe(schema)?;
                observer.observe(algorithm)?;
                observer.observe(context_digest)?;
                observer.observe(mac)
            }
            Self::Receipt(value) => {
                let PacketNativeImport18BootstrapAckReceipt {
                    schema,
                    algorithm,
                    state,
                    context_digest,
                    assigned_response,
                    mac,
                } = value;
                observer.observe(schema)?;
                observer.observe(algorithm)?;
                match state {
                    PacketNativeImport18BootstrapAckState::BootstrapOnly => {}
                }
                observer.observe(context_digest)?;
                observer.observe(assigned_response)?;
                observer.observe(mac)
            }
        }
    }
}

fn row(
    value: &PacketNativeStartupAllocationRow,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let PacketNativeStartupAllocationRow {
        retained_requested_bytes,
        maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes,
    } = value;
    observer.observe(retained_requested_bytes)?;
    observer.observe(maximum_simultaneous_transient_bytes)?;
    observer.observe(declared_counter_scratch_bytes)
}

/// Names exact DTO field/reference, observer, result and formatter controls.
pub fn native_import18_bootstrap_retention_counter_scratch_data() -> usize {
    size_of::<PacketNativeImport18BootstrapRetainedData<'static>>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<(&String, &Bytes, &PacketNativeStartupAllocationRow)>()
        + size_of::<(
            &String,
            &PacketNativeImport18BootstrapAckState,
            &Bytes,
            &PacketNativeStartupAllocationRow,
        )>()
        + size_of::<(
            &String,
            &String,
            &Bytes,
            &Bytes,
            &Bytes,
            &Bytes,
            &Bytes,
            &Bytes,
            &Bytes,
            &Bytes,
            &Bytes,
            &PacketNativeStartupAllocationRow,
        )>()
        + size_of::<(&String, &String, &Bytes, &Bytes)>()
        + size_of::<(
            &String,
            &String,
            &PacketNativeImport18BootstrapAckState,
            &Bytes,
            &Bytes,
            &Bytes,
        )>()
        + size_of::<(&U64, &U64, &U64)>()
        + size_of::<[&Bytes; 9]>()
        + size_of::<std::array::IntoIter<&Bytes, 9>>()
        + size_of::<&mut MetadataObserver<'static>>()
        + size_of::<&PacketNativeStartupAllocationRow>()
        + size_of::<[u8; 20]>()
        + crate::retained_metadata::ordinary_bytes_formatter_counter_scratch_data()
        // Extracted match roots coexist with the selected field walk.
        + size_of::<&PacketNativeImport18BootstrapRequest>()
        + size_of::<&PacketNativeImport18BootstrapResult>()
        + size_of::<&PacketNativeImport18BootstrapAckContext>()
        + size_of::<&PacketNativeImport18BootstrapAckProof>()
        + size_of::<&PacketNativeImport18BootstrapAckReceipt>()
        + size_of::<&Bytes>()
        // This shallow observer calls observe/string/vector/record/add. Its
        // public facts walk has no recording bank or shared-root insertion.
        + size_of::<crate::retained_metadata::records::MetadataRecordKind>()
        + size_of::<crate::retained_metadata::records::MetadataCapacityRecord>()
        + size_of::<&mut usize>()
        + size_of::<Option<usize>>() * 2
        + size_of::<usize>() * 9
        + size_of::<&String>()
        + size_of::<&U64>()
        + size_of::<crate::retained_metadata::OrdinaryBytesFormatterDemandData>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_partial_request_keeps_real_digest_capacity_and_schema_backing() {
        let mut bytes = Vec::with_capacity(79);
        bytes.push(1);
        let mut schema = String::with_capacity(91);
        schema.push_str("partial");
        let request = PacketNativeImport18BootstrapRequest {
            schema,
            recipe_identity: Bytes::new(bytes),
            initial_funding: PacketNativeStartupAllocationRow {
                retained_requested_bytes: U64::new(0),
                maximum_simultaneous_transient_bytes: U64::new(0),
                declared_counter_scratch_bytes: U64::new(0),
            },
        };
        assert!(request.validate_data().is_err());
        let facts = PacketNativeImport18BootstrapRetainedData::Request(&request)
            .retained_metadata_data()
            .unwrap();
        assert_eq!(facts.string_capacity_bytes, request.schema.capacity());
        assert_eq!(
            facts.vector_capacity_bytes,
            request.recipe_identity.allocation_capacity()
        );
    }
}
