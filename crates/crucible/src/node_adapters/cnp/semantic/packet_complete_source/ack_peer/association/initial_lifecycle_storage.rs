//! Counts the Source-owned association, signing and preparation construction.
//!
//! Existing context byte banks are current owners, not new growth. This row
//! adds independently retained normalized Values, typed preparation copies and
//! the real signing/validation work. Provider initial-lifecycle storage and the
//! concrete authority's callback-construction phase remain separate rows.

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_contract::{ContentRef, HashRef, Id};
use crucible_node_provider::{
    client::{
        PacketNativeHostInitialLifecycleStorageData,
        original_host_source_json_counter_scratch_data,
        original_host_source_json_extent_storage_data,
        original_host_source_json_occurrence_storage_data,
    },
    reference_packet::service::ack_emitter::{
        MAXIMUM_CANONICAL_ACK_ADMISSION_CONTEXT_BYTES, MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES,
        PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM, PacketCanonicalAckAdmissionContext,
        PacketCanonicalAckAdmissionProof,
    },
};
use serde::Serialize;
use std::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node_adapters::cnp::semantic) struct OriginalInitialSourceStorage {
    pub(in crate::node_adapters::cnp::semantic) retained: usize,
    pub(in crate::node_adapters::cnp::semantic) transient: usize,
    pub(in crate::node_adapters::cnp::semantic) scratch: usize,
}

impl OriginalInitialSourceStorage {
    pub(in crate::node_adapters::cnp::semantic) fn requested_peak_data(
        self,
    ) -> Result<usize, RuntimeError> {
        add(&[self.retained, self.transient, self.scratch])
    }
}

// These projections borrow the actual closed installed DTO family. Their
// serializers contain String/Id/HashRef/U64/Value and derive containers, with
// no Bytes/base64 or user-supplied Serialize implementation. U64's one live
// decimal formatter bank is precredited separately before invoking the visitor.
#[derive(Serialize)]
struct InstalledProjection<'a> {
    provider: &'a crucible_node_contract::ProviderManifest,
    profile: &'a crucible_node_contract::NodeManifest,
    descriptor: &'a crucible_node_contract::NodeDescriptor,
    binding: &'a crucible_node_contract::NodeBinding,
    capabilities: &'a crucible_node_contract::CapabilityProfile,
    exact_facet: &'a crucible_node_contract::FacetSelection,
    guarantees: &'a crucible_node_contract::GuaranteeProfile,
    owner: &'a crucible_node_contract::OwnerBinding,
    realize: &'a crucible_node_provider::bodies::RealizeRequest,
    admission: &'a Id,
    transaction: &'a Id,
    gate: &'a Id,
    admission_receipt: &'a ContentRef,
    world_binding_hash: &'a HashRef,
    receipt_schema: &'a crucible_node_contract::SchemaRef,
    maximum_operations: usize,
    maximum_semantic_bytes: usize,
    maximum_result_bytes: usize,
    maximum_authorization_bytes: usize,
}

#[derive(Serialize)]
struct BirthFields<'a> {
    schema: &'static str,
    birth_id: &'static str,
    private_launch: &'a Id,
    host_executable: &'a ContentRef,
}

#[derive(Serialize)]
struct KernelFields<'a> {
    schema: &'static str,
    controller: KernelPeer<'a>,
    native: KernelPeer<'a>,
}

#[derive(Serialize)]
struct KernelPeer<'a> {
    pid: crucible_node_contract::U64,
    uid: crucible_node_contract::U64,
    executable: &'a ContentRef,
}

#[derive(Serialize)]
struct ContextFields {
    schema: &'static str,
    algorithm: &'static str,
    source_birth: &'static str,
    kernel_binding: &'static str,
    policy_binding: &'static str,
    host_registration: &'static str,
    native_registration: &'static str,
    hello_request: &'static str,
    hello_response: &'static str,
    assigned_admit: &'static str,
}

#[derive(Serialize)]
struct ProofFields {
    schema: &'static str,
    algorithm: &'static str,
    context_digest: &'static str,
    mac: &'static str,
}

const DIGEST_BASE64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

impl PacketCompleteSemanticSource {
    pub(in crate::node_adapters::cnp::semantic) fn original_initial_source_storage_data(
        &self,
        frame_bytes: usize,
        initial_sdk_quote: Option<&PacketNativeHostInitialLifecycleStorageData>,
        maximum: usize,
    ) -> Result<OriginalInitialSourceStorage, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let birth = self
            .ack_peer_birth
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let birth = birth.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        let inputs = birth.original_initial_lifecycle_inputs_data()?;
        let selected = self.installation();
        let installed = InstalledProjection {
            provider: &selected.provider,
            profile: &selected.profile,
            descriptor: &selected.descriptor,
            binding: &selected.binding,
            capabilities: &selected.capabilities,
            exact_facet: &selected.exact_facet,
            guarantees: &selected.guarantees,
            owner: &selected.owner,
            realize: &selected.realize,
            admission: &selected.admission,
            transaction: &selected.transaction,
            gate: &selected.gate,
            admission_receipt: &selected.admission_receipt,
            world_binding_hash: &selected.world_binding_hash,
            receipt_schema: &selected.receipt_schema,
            maximum_operations: selected.maximum_operations,
            maximum_semantic_bytes: selected.maximum_semantic_bytes,
            maximum_result_bytes: selected.maximum_result_bytes,
            maximum_authorization_bytes: selected.maximum_authorization_bytes,
        };
        let installation_phase = NodeRuntime::capture_serialization_storage(&installed, maximum)?;
        let source_json = original_host_source_json_occurrence_storage_data(
            inputs.source_birth,
            super::super::frame::MAXIMUM_ACK_SOURCE_BIRTH_BYTES,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let registration_json = original_host_source_json_occurrence_storage_data(
            inputs.host_registration,
            super::super::frame::MAXIMUM_ACK_HOST_REGISTRATION_BYTES,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        let birth_fields = NodeRuntime::capture_serialization_storage(
            &BirthFields {
                schema: "source-owned.packet-canonical-ack-birth-association/5",
                birth_id: DIGEST_BASE64,
                private_launch: inputs.private_launch,
                host_executable: inputs.host_executable,
            },
            maximum,
        )?;
        let maximum_pid = crucible_node_contract::U64::new(u64::MAX);
        let kernel = NodeRuntime::capture_serialization_storage(
            &KernelFields {
                schema: "source-owned.packet-canonical-ack-kernel-binding/5",
                controller: KernelPeer {
                    pid: maximum_pid,
                    uid: maximum_pid,
                    executable: inputs.host_executable,
                },
                native: KernelPeer {
                    pid: maximum_pid,
                    uid: maximum_pid,
                    executable: self.original_host_sdk_executable_data()?,
                },
            },
            maximum,
        )?;
        let assigned = assigned_admit_storage_data(frame_bytes, initial_sdk_quote)?;
        let context = NodeRuntime::capture_serialization_storage(
            &ContextFields {
                schema: "source-owned.packet-canonical-ack-admission-context/5",
                algorithm: PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM,
                source_birth: DIGEST_BASE64,
                kernel_binding: DIGEST_BASE64,
                policy_binding: DIGEST_BASE64,
                host_registration: DIGEST_BASE64,
                native_registration: DIGEST_BASE64,
                hello_request: DIGEST_BASE64,
                hello_response: DIGEST_BASE64,
                assigned_admit: DIGEST_BASE64,
            },
            maximum,
        )?;
        let proof = NodeRuntime::capture_serialization_storage(&ProofFields {
            schema: crucible_node_provider::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
            algorithm: PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM,
            context_digest: DIGEST_BASE64, mac: DIGEST_BASE64,
        }, maximum)?;
        // All five normalized Values remain independently retained. The policy
        // embeds a second full source Value plus the actual negotiated roster;
        // the registration occurrence bound supplies its closed planned roster
        // fields. Explicit wrapper map/key events are counted separately.
        let normalized_birth = add(&[
            source_json,
            registration_json,
            birth_fields,
            wrapper_fields(&["source_binding", "expected_host_registration"], maximum)?,
        ])?;
        let normalized_policy = add(&[
            source_json,
            registration_json,
            NodeRuntime::capture_serialization_storage(
                &"source-owned.packet-canonical-ack-policy-binding/5",
                maximum,
            )?,
            wrapper_fields(
                &[
                    "schema",
                    "source_binding",
                    "negotiated",
                    "limits",
                    "features",
                    "extensions",
                    "envelope_extensions",
                ],
                maximum,
            )?,
        ])?;
        let native_registration = add(&[
            registration_json,
            // The native connection spelling replaces the planned host ID.
            // Count its complete new String/canonical events independently;
            // no unused typed pool is silently used as string credit.
            NodeRuntime::capture_serialization_storage(
                &"packet-native5-original-connection",
                maximum,
            )?,
        ])?;
        let typed_admit_clone =
            self.original_complete_installation_storage_data_with_error::<RuntimeError>(maximum)?;
        let retained = add(&[normalized_birth, kernel, normalized_policy, native_registration,
            assigned, context, proof,
            // Provider331 independently charges the Source preparation's
            // typed DiscoverResult and RealizeResult copies.
            size_of::<PacketCanonicalAckAdmissionContext>(), size_of::<PacketCanonicalAckAdmissionProof>(),
            8 * 32, 2 * 32,
            "source-owned.packet-canonical-ack-admission-context/5".len(),
            2 * PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.len(),
            crucible_node_provider::reference_packet::service::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE.len(),
        ])?;
        let transient = add(&[
            // Installation identity, full provider reference and OwnerBinding
            // hashes are sequential; one complete actual installation projection
            // conservatively dominates each proper closed subprojection.
            installation_phase,
            crate::node_adapters::cnp::semantic::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics::requested_bytes(),
            // Each Source-created AdmitRequest clones a proper typed subset of
            // this actual installation. The existing exhaustive owning walk
            // supplies a conservative whole-subgraph clone ceiling: String/Vec
            // capacities and complete tree-node pools dominate their standard
            // Clone requests; Rc handles allocate no new payload. Prepare,
            // expected-body sealing and retain-world clones are sequential.
            typed_admit_clone,
            // The context proof independently canonicalizes the full context,
            // then stores the proof Value while its typed two-digest proof lives.
            context, proof, MAXIMUM_CANONICAL_ACK_ADMISSION_CONTEXT_BYTES,
            MAXIMUM_CANONICAL_ACK_ADMISSION_PROOF_BYTES,
            size_of::<blake3::Hasher>(), 3 * 32,
            // True Bytes::serialize has one live 43-byte base64 String before
            // the counter sink; the projection uses the same fixed text width.
            32, 43,
            // Full private-host currentness uses the same retained file and
            // same fixed stream bank; it is separate from child currentness.
            super::super::PacketCompleteAckPeerBootMaterial::original_native_startup_authentication_scratch_data(),
            // Existing native UID lookup formats a bounded /proc/u32 path.
            12, 24, 17, size_of::<std::fs::Metadata>(),
        ])?;
        let data = OriginalInitialSourceStorage {
            retained,
            transient,
            scratch: Self::original_initial_source_counter_scratch_data(),
        };
        if data.requested_peak_data()? > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(data)
    }

    pub(in crate::node_adapters::cnp::semantic) fn original_initial_source_counter_scratch_data()
    -> usize {
        NodeRuntime::capture_serialization_counter_scratch_data()
            + original_host_source_json_counter_scratch_data()
            + size_of::<InstalledProjection<'static>>() + size_of::<BirthFields<'static>>()
            + size_of::<KernelFields<'static>>() + size_of::<ContextFields>() + size_of::<ProofFields>()
            + crate::node_adapters::cnp::semantic::initial_lifecycle_diagnostics::OriginalInitialLifecycleDiagnostics::counter_scratch_bytes()
            + size_of::<OriginalInitialSourceStorage>() + size_of::<[usize; 16]>()
            + size_of::<std::cell::Ref<'static, Option<OriginalAckPeerBirth>>>()
            + size_of::<Option<&'static PacketNativeHostInitialLifecycleStorageData>>() + 20
    }
}

fn assigned_admit_storage_data(
    frame_bytes: usize,
    initial_sdk_quote: Option<&PacketNativeHostInitialLifecycleStorageData>,
) -> Result<usize, RuntimeError> {
    match initial_sdk_quote {
        // Only the initial SDK caller supplies its same-launch opaque quote,
        // after authenticating complete Source/launch correspondence. The
        // actual Source separately retains this additional normalized Value.
        Some(quote) => Ok(quote.source_assigned_admit_requested_bytes_data()),
        // General collecting validation has no such SDK loan. Keep its full
        // prior raw-frame bound rather than inferring tighter correspondence.
        None => original_host_source_json_extent_storage_data(frame_bytes)
            .map_err(|_| RuntimeError::ResourceLimit),
    }
}

fn wrapper_fields(fields: &[&str], maximum: usize) -> Result<usize, RuntimeError> {
    // A map projection charges the actual key strings, B-tree and canonical
    // UTF16 nodes. Empty values are supplemented by their independent rows.
    struct Fields<'a>(&'a [&'a str]);
    impl Serialize for Fields<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(self.0.len()))?;
            for field in self.0 {
                map.serialize_entry(field, "")?;
            }
            map.end()
        }
    }
    NodeRuntime::capture_serialization_storage(&Fields(fields), maximum)
}

fn add(values: &[usize]) -> Result<usize, RuntimeError> {
    values.iter().try_fold(0usize, |sum, value| {
        sum.checked_add(*value).ok_or(RuntimeError::ResourceLimit)
    })
}

impl OriginalAckPeerAssociation {
    pub(in crate::node_adapters::cnp::semantic) fn initial_lifecycle_descriptor_views_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        self.native
            .as_ref()
            .map(|native| native.retained_descriptor_views_precredit_data())
            .transpose()
            .map(|count| count.unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::Bytes;
    use crucible_node_provider::reference_packet::service::ack_emitter::{
        PACKET_CANONICAL_ACK_ADMISSION_FEATURE, canonical_ack_admission_proof_data,
    };

    #[test]
    fn collecting_without_same_sdk_quote_keeps_generic_assigned_frame_bound() {
        for frame_bytes in [1, 4096, 65_536] {
            let actual = assigned_admit_storage_data(frame_bytes, None).unwrap();
            assert_eq!(
                actual,
                original_host_source_json_extent_storage_data(frame_bytes).unwrap()
            );
        }
        assert!(assigned_admit_storage_data(0, None).is_err());
    }

    #[test]
    fn original_initial_signing_projection_matches_actual_context_and_proof_grammar() {
        let digest = || Bytes::new(vec![0; 32]);
        let actual = PacketCanonicalAckAdmissionContext {
            schema: "source-owned.packet-canonical-ack-admission-context/5".into(),
            algorithm: PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM.into(),
            source_birth: digest(),
            kernel_binding: digest(),
            policy_binding: digest(),
            host_registration: digest(),
            native_registration: digest(),
            hello_request: digest(),
            hello_response: digest(),
            assigned_admit: digest(),
        };
        let projected = ContextFields {
            schema: "source-owned.packet-canonical-ack-admission-context/5",
            algorithm: PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM,
            source_birth: DIGEST_BASE64,
            kernel_binding: DIGEST_BASE64,
            policy_binding: DIGEST_BASE64,
            host_registration: DIGEST_BASE64,
            native_registration: DIGEST_BASE64,
            hello_request: DIGEST_BASE64,
            hello_response: DIGEST_BASE64,
            assigned_admit: DIGEST_BASE64,
        };

        actual.validate_data().unwrap();
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&projected).unwrap()
        );
        let declared = NodeRuntime::capture_serialization_storage(&projected, usize::MAX).unwrap();
        assert_eq!(
            declared,
            NodeRuntime::capture_serialization_storage(&actual, usize::MAX).unwrap()
        );
        assert_eq!(
            NodeRuntime::capture_serialization_storage(&projected, declared - 1),
            Err(RuntimeError::ResourceLimit)
        );

        let proof = canonical_ack_admission_proof_data(&[73; 32], &actual).unwrap();
        let proof_projection = ProofFields {
            schema: PACKET_CANONICAL_ACK_ADMISSION_FEATURE,
            algorithm: PACKET_CANONICAL_ACK_ADMISSION_ALGORITHM,
            context_digest: DIGEST_BASE64,
            mac: DIGEST_BASE64,
        };
        // Different digest contents preserve the exact43-byte base64 fields;
        // the actual normative proof determines every key/schema/algorithm.
        assert_eq!(
            NodeRuntime::capture_serialization_storage(&proof_projection, usize::MAX).unwrap(),
            NodeRuntime::capture_serialization_storage(&proof, usize::MAX).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&proof)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            serde_json::to_value(&proof_projection)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .collect::<Vec<_>>()
        );
    }
}

impl PacketCompleteSemanticSource {
    /// Quotes this original Source's closed validation during collecting construction.
    ///
    /// The completed Source owns the same immutable launch, registration and
    /// installed DTOs used by initial lifecycle validation. Revalidation rebuilds
    /// proper subprojections of those same closed normalization/signing shapes.
    /// Their complete existing construction quote is conservatively charged
    /// again as temporary work, with no refund of the retained original owners.
    /// It does not authorize socket, SDK, Admit, native or runtime construction.
    ///
    /// Native guard currentness, graph policy callbacks, daemon file/kernel
    /// validation and their private failure owners remain separate caller rows.
    /// The caller admits this method's fixed counter before entering it.
    ///
    /// # Errors
    /// Refuses foreign or unavailable original birth, missing actual completed
    /// association, unsupported storage or a checked sum beyond the ceiling.
    pub fn original_collecting_validation_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let association_loan = self
            .ack_peer_association
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let association = association_loan
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !association.completed_mechanism.get() || association.failed || !association.ready {
            return Err(RuntimeError::OutstandingObligations);
        }
        drop(association_loan);
        // No new receive occurs here. The largest independently retained
        // assigned request is the already selected original message bound.
        let frame_bytes = self
            .selected_storage_selection()
            .map_err(|_| RuntimeError::ForeignAuthority)?
            .limits
            .frame_bytes;
        let frame_bytes =
            usize::try_from(frame_bytes.get()).map_err(|_| RuntimeError::ResourceLimit)?;
        self.original_initial_source_storage_data(frame_bytes, None, maximum)?
            .requested_peak_data()
    }

    /// Names this exact Source validation quote's fixed counter views.
    pub fn original_collecting_validation_counter_scratch_data() -> usize {
        Self::original_initial_source_counter_scratch_data()
            + std::mem::size_of::<std::cell::Ref<'static, Option<OriginalAckPeerAssociation>>>()
            + std::mem::size_of::<usize>()
    }
}
