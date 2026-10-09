//! Verifies immutable bytes and delegates trust decisions to host policy.

use std::io::{self, Write};

use crucible_node_contract::{
    BindingCompatibility, ContentRef, HashRef, Id, ImplementationIdentity, NodeBinding, SchemaRef,
    Validate, canonical,
};
use serde::{Serialize, de::DeserializeOwned};

use super::error::{AdmissionCode, AdmissionError, AdmissionStage, AdmissionSubject, refuse};

/// Bounds graph admission allocations independently of transport frame limits.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionLimits {
    /// Bounds public logical nodes.
    pub maximum_nodes: usize,
    /// Bounds distinct execution/capture owners.
    pub maximum_owners: usize,
    /// Bounds declared mutable domains and realized objects independently.
    pub maximum_state_objects: usize,
    /// Bounds public connections and internal causal paths independently.
    pub maximum_connections: usize,
    /// Bounds ports per node and lanes per port independently.
    pub maximum_ports_or_lanes: usize,
    /// Bounds each referenced immutable blob before fetching it.
    pub maximum_content_bytes: usize,
    /// Bounds all verified content fetched during one admission.
    pub maximum_total_content_bytes: usize,
    /// Bounds each complete supplied core object before hashing or cloning it.
    pub maximum_core_object_bytes: usize,
    /// Bounds all supplied core objects together before constructing a seal.
    pub maximum_total_core_bytes: usize,
    /// Bounds negotiated messages independently of the underlying transport.
    pub maximum_payload_bytes: u64,
    /// Bounds outstanding events on one admitted connection.
    pub maximum_pending_events: u64,
    /// Bounds cumulative connection payload reservation for the whole graph.
    pub maximum_total_pending_bytes: u64,
    /// Bounds retained directed conflict relations between actual mutable owners.
    pub maximum_owner_conflict_pairs: usize,
    /// Bounds pair examinations while deriving shared-domain conflicts.
    pub maximum_owner_conflict_checks: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            maximum_nodes: 1024,
            maximum_owners: 2048,
            maximum_state_objects: 16_384,
            maximum_connections: 16_384,
            maximum_ports_or_lanes: 256,
            maximum_content_bytes: 4 * 1024 * 1024,
            maximum_total_content_bytes: 64 * 1024 * 1024,
            maximum_core_object_bytes: 8 * 1024 * 1024,
            maximum_total_core_bytes: 64 * 1024 * 1024,
            maximum_payload_bytes: 16 * 1024 * 1024,
            maximum_pending_events: 65_536,
            maximum_total_pending_bytes: 1024 * 1024 * 1024,
            maximum_owner_conflict_pairs: 65_536,
            maximum_owner_conflict_checks: 1_048_576,
        }
    }
}

/// Names a host-accepted claim and the exact immutable scope it must cover.
#[derive(Clone, Debug)]
pub enum QualificationClaim<'a> {
    /// Covers required guarantees and explicit weaker-contract acceptance.
    Scenario {
        /// Commits to the exact frozen world.
        world_binding_hash: &'a HashRef,
        /// Binds the complete authored/resolved scenario content.
        scenario_ref: &'a ContentRef,
        /// Commits to the scenario requirements actually used by admission.
        requirements_hash: &'a HashRef,
    },
    /// Covers the selected implementation, parameters, mode, devices, and facets.
    Node {
        /// Contains the complete actual selected implementation/model contract.
        binding: &'a BindingCompatibility,
        /// Commits to the complete selected compatibility contract.
        binding_hash: &'a HashRef,
        /// Enumerates the binding's accepted evidence candidates.
        qualification_refs: &'a [ContentRef],
    },
    /// Covers the exact schema, port semantics, and guest-facing device mapping.
    Port {
        /// Names the selected node.
        node_id: &'a Id,
        /// Commits to that node's selected compatibility contract.
        binding_hash: &'a HashRef,
        /// Names the exact selected port.
        port_id: &'a Id,
        /// Binds the full ordering, flow-control, and interpretation policy.
        policy_ref: &'a ContentRef,
    },
    /// Covers all declared and effective causal/state paths in this world.
    CompleteInventory {
        /// Commits to the exact frozen world.
        world_binding_hash: &'a HashRef,
        /// Binds the complete ownership and object inventory.
        ownership_ref: &'a ContentRef,
        /// Binds the evidence for inventory completeness.
        proof_ref: &'a ContentRef,
    },
    /// Covers selected latency, failure paths, conversion, and transfer custody.
    Connection {
        /// Commits to the exact frozen world.
        world_binding_hash: &'a HashRef,
        /// Names the selected public connection or internal causal path.
        connection_id: &'a Id,
        /// Binds all-path proof for its actual selected policy.
        proof_ref: &'a ContentRef,
    },
    /// Covers all owned domains and cross-owner consistent-cut dependencies.
    Capture {
        /// Commits to the exact frozen world.
        world_binding_hash: &'a HashRef,
        /// Names the authoritative capture owner.
        capture_owner_id: &'a Id,
        /// Binds complete unchanged-cut preservation and claimed reconstruction.
        procedure_ref: &'a ContentRef,
    },
    /// Covers complete microstep closure for one actual execution owner.
    SameTimeClosure {
        /// Commits to the exact frozen world.
        world_binding_hash: &'a HashRef,
        /// Names the participating indivisible execution owner.
        execution_owner_id: &'a Id,
        /// Binds the complete closure and ordering evidence.
        proof_ref: &'a ContentRef,
    },
    /// Covers coordinator state closure, limits, and selected containment policy.
    Coordinator {
        /// Commits to the exact frozen world.
        world_binding_hash: &'a HashRef,
        /// Binds the complete selected coordinator policy.
        policy_ref: &'a ContentRef,
    },
}

/// Reports unavailable, corrupt, untrusted, or out-of-scope admission evidence.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{message}")]
pub struct EvidenceError {
    /// Describes the host verification refusal without conferring authority.
    pub message: String,
}

/// Resolves immutable bytes and applies host-installed trust and qualification policy.
///
/// Implementations are part of the trusted host admission boundary. Providers
/// cannot satisfy this interface by echoing content references or self-issued
/// receipts. A successful qualification decision must authenticate accepted
/// executable evidence for the exact supplied claim, including all selected
/// configuration restrictions. It does not confer native custody or execution.
pub trait AdmissionEvidence {
    /// Borrows a source-installed exact semantic registry, when explicitly configured.
    ///
    /// The default preserves refusal of nonempty identity-bearing extension maps.
    /// Negotiated feature strings and portable declarations cannot construct a
    /// registry or replace namespace, handler, and application qualification.
    fn extension_registry(&self) -> Option<&super::InstalledExtensionRegistry> {
        None
    }

    /// Reads the complete immutable object under an enforced byte ceiling.
    ///
    /// # Errors
    /// Rejects unavailable content and any fetch that would exceed the ceiling.
    /// The implementation must enforce the ceiling before allocating content.
    fn content(
        &self,
        reference: &ContentRef,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, EvidenceError>;

    /// Authenticates actual installed executables, adapters, patches, and models.
    ///
    /// # Errors
    /// Rejects missing or mismatched installed artifacts, untrusted identities,
    /// and implementation measurements that have not been positively established.
    fn authenticate_implementation(
        &self,
        implementation: &ImplementationIdentity,
    ) -> Result<(), EvidenceError>;

    /// Authenticates the actual live owner, generation, session, and host receipt.
    ///
    /// # Errors
    /// Rejects copied vendor claims, stale owners, foreign receipts, and any
    /// binding for which actual host custody has not been positively established.
    fn authenticate_authority(&self, binding: &NodeBinding) -> Result<(), EvidenceError>;

    /// Authenticates installed support for the exact bounded payload/state schema.
    ///
    /// # Errors
    /// Rejects unknown schema editions, unresolved semantic references, incomplete
    /// bounds, and schemas without an installed validator for actual use. A valid
    /// content digest or generic JSON decoding is not schema support.
    fn authenticate_schema(&self, schema: &SchemaRef) -> Result<(), EvidenceError>;

    /// Accepts an exact claim under the host's qualification policy.
    ///
    /// # Errors
    /// Rejects absent, unknown, stale, fixture-only, or out-of-scope evidence.
    /// Successful decoding, startup, or a copied receipt is insufficient.
    fn qualify(&self, claim: QualificationClaim<'_>) -> Result<(), EvidenceError>;
}

pub(super) struct VerifiedContent<'a> {
    pub source: &'a dyn AdmissionEvidence,
    pub limits: AdmissionLimits,
    consumed: usize,
    extensions: Option<super::extensions::ExtensionAdmission<'a>>,
}

impl<'a> VerifiedContent<'a> {
    pub fn new(source: &'a dyn AdmissionEvidence, limits: AdmissionLimits) -> Self {
        Self {
            source,
            limits,
            consumed: 0,
            extensions: None,
        }
    }

    pub fn configure_extensions(
        &mut self,
        request: super::AdmissionRequest<'a>,
        world_hash: HashRef,
    ) {
        self.extensions = self.source.extension_registry().map(|registry| {
            super::extensions::ExtensionAdmission::new(registry, request, world_hash)
        });
    }

    /// Authenticates nonempty extensions against the installed semantic registry.
    ///
    /// # Errors
    /// Refuses absent installed interpretation or a record that fails semantic application admission.
    pub fn extension_record<'p>(
        &mut self,
        record: &impl Serialize,
        extensions: &crucible_node_contract::Extensions,
        placement: impl FnOnce() -> super::extensions::RecordPlacement<'p>,
    ) -> Result<(), AdmissionError> {
        if extensions.is_empty() {
            return Ok(());
        }
        let placement = placement();
        if let Some(admission) = &mut self.extensions {
            return admission.check(record, extensions, placement, self.limits);
        }
        Err(refuse(
            AdmissionStage::Nodes,
            placement.node.map_or(AdmissionSubject::World, |node| {
                AdmissionSubject::Node(node.clone())
            }),
            AdmissionCode::UnknownInterface,
            "explicit source-installed exact semantic registry",
            "nonempty extension map has no authenticated installed interpretation",
        ))
    }

    pub fn take_extensions(&mut self) -> super::AdmittedExtensionSet {
        self.extensions
            .take()
            .map(super::extensions::ExtensionAdmission::into_selected)
            .unwrap_or_default()
    }

    /// Reads and verifies one immutable object within the remaining fetch credits.
    ///
    /// # Errors
    /// Refuses invalid references, unavailable or mismatched content, unrepresentable lengths, or exhausted object and cumulative byte ceilings.
    pub fn read(&mut self, reference: &ContentRef) -> Result<Vec<u8>, AdmissionError> {
        reference
            .validate()
            .map_err(|error| invalid_content(error.to_string()))?;
        let length = usize::try_from(reference.length.get())
            .map_err(|_| invalid_content("unrepresentable content length"))?;
        let remaining = self
            .limits
            .maximum_total_content_bytes
            .checked_sub(self.consumed)
            .ok_or_else(|| invalid_content("total content ceiling exhausted"))?;
        let maximum = remaining.min(self.limits.maximum_content_bytes);
        if length > maximum {
            return Err(refuse(
                AdmissionStage::Authenticate,
                AdmissionSubject::World,
                AdmissionCode::BoundMismatch,
                "content within per-object and cumulative fetch ceilings",
                "declared content exceeds remaining capacity",
            ));
        }

        let bytes = self
            .source
            .content(reference, maximum)
            .map_err(|error| invalid_content(error.to_string()))?;
        if bytes.len() != length || bytes.len() > maximum {
            return Err(invalid_content(
                "fetched content length differs from bound reference",
            ));
        }
        let actual = canonical::hash("cnp.blob.v1", &bytes)
            .map_err(|error| invalid_content(error.to_string()))?;
        if actual != reference.hash {
            return Err(invalid_content(
                "fetched bytes do not match the content digest",
            ));
        }
        self.consumed = self
            .consumed
            .checked_add(bytes.len())
            .ok_or_else(|| invalid_content("content accounting overflow"))?;
        Ok(bytes)
    }

    /// Decodes a verified immutable object as the requested policy type.
    ///
    /// # Errors
    /// Refuses content-fetch failures, invalid bounded canonical JSON, or a policy that does not match the requested schema.
    pub fn policy<T: DeserializeOwned>(
        &mut self,
        reference: &ContentRef,
    ) -> Result<T, AdmissionError> {
        let bytes = self.read(reference)?;
        let value = canonical::parse_json(&bytes, self.limits.maximum_content_bytes)
            .map_err(|error| invalid_content(error.to_string()))?;
        serde_json::from_value(value).map_err(|error| {
            refuse(
                AdmissionStage::Parse,
                AdmissionSubject::World,
                AdmissionCode::InvalidSchema,
                "closed supported referenced policy schema",
                error.to_string(),
            )
        })
    }

    /// Verifies an immutable content reference through the bounded evidence source.
    ///
    /// # Errors
    /// Refuses invalid references, unavailable or mismatched content, or exhausted fetch credits.
    pub fn verify(&mut self, reference: &ContentRef) -> Result<(), AdmissionError> {
        self.read(reference).map(|_| ())
    }

    /// Authenticates the selected qualification scope through the installed evidence source.
    ///
    /// # Errors
    /// Refuses claims that the installed source cannot authenticate for the requested subject.
    pub fn qualify(
        &self,
        subject: AdmissionSubject,
        claim: QualificationClaim<'_>,
    ) -> Result<(), AdmissionError> {
        self.source.qualify(claim).map_err(|error| {
            refuse(
                AdmissionStage::Authenticate,
                subject,
                AdmissionCode::QualificationUnavailable,
                "host-accepted evidence covering actual selected scope",
                error.to_string(),
            )
        })
    }
}

fn invalid_content(observed: impl Into<String>) -> AdmissionError {
    refuse(
        AdmissionStage::Authenticate,
        AdmissionSubject::World,
        AdmissionCode::IdentityMismatch,
        "available immutable bytes matching their complete content reference",
        observed,
    )
}

struct CountingWriter {
    remaining: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("core object exceeds admission byte ceiling"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn bounded_core(
    value: &impl Serialize,
    maximum: usize,
) -> Result<usize, AdmissionError> {
    // Count without buffering before canonicalization or cloning. This includes
    // extension payloads whose size is not bounded by array cardinality alone.
    let mut writer = CountingWriter { remaining: maximum };
    serde_json::to_writer(&mut writer, value).map_err(|error| {
        refuse(
            AdmissionStage::Parse,
            AdmissionSubject::World,
            AdmissionCode::BoundMismatch,
            "core object within admitted serialization ceiling",
            error.to_string(),
        )
    })?;
    Ok(maximum - writer.remaining)
}
