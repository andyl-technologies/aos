//! Sole ordered structural validator for public request DATA and scalar helpers.

use aos_proto::aos::sandbox::v1 as wire;

use super::{
    DormantSandboxOutputV1, DormantSandboxRequestKindV1, DormantSandboxRoutingErrorV1,
    PublicSandboxRequestDataV1,
};
use crate::public_api::limits::MAXIMUM_CLI_WAIT_NANOSECONDS;
use crate::public_api::limits::{
    MAXIMUM_ENDPOINT_PROOF_BYTES, MAXIMUM_EXEC_ARGUMENT_BYTES, MAXIMUM_EXEC_ARGUMENT_VECTOR_BYTES,
    MAXIMUM_EXEC_ARGUMENTS,
};
use crate::public_api::proto_json::validate_sandbox_tree_preorder_state_v1;
use crate::public_api::registry::execution_required_features_present;

impl PublicSandboxRequestDataV1 {
    /// Validates invariant-bearing scalar fields before any transport can see the request.
    ///
    /// # Errors
    ///
    /// Returns [`DormantSandboxRoutingErrorV1::InvalidRequest`] for missing
    /// identities, mutation fences, descriptors, commands, or recovery actions.
    pub fn validate(&self) -> Result<(), DormantSandboxRoutingErrorV1> {
        use DormantSandboxRequestKindV1 as K;

        let valid = match &self.kind {
            K::PlanCreate(r) => {
                nonempty(&r.project_id)
                    && nonempty(&r.expected_project_resource_version)
                    && descriptor_present(r.specification.as_option())
                    && descriptor_present(r.requested_policy.as_option())
                    && valid_features(&r.required_features)
                    && (r.parent_sandbox_id.is_empty()
                        == r.expected_parent_resource_version.is_empty())
            }
            K::Create(r) => {
                nonempty(&r.project_id)
                    && nonempty(&r.expected_project_resource_version)
                    && descriptor_present(r.specification.as_option())
                    && descriptor_present(r.requested_policy.as_option())
                    && nonempty(&r.idempotency_key)
                    && r.operation_timeout.as_option().is_some_and(|timeout| {
                        (1..=MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout.nanoseconds)
                    })
                    && valid_features(&r.required_features)
                    && (r.parent_sandbox_id.is_empty()
                        == r.expected_parent_resource_version.is_empty())
            }
            K::GetSandbox(r) => nonempty(&r.sandbox_id),
            K::GetExecution(r) => nonempty(&r.execution_id),
            K::GetView(r) => nonempty(&r.view_id),
            K::GetAttachment(r) => nonempty(&r.attachment_id),
            K::GetSnapshot(r) => nonempty(&r.snapshot_id),
            K::GetOperation(r) => nonempty(&r.operation_id),
            K::ListSandboxes(r) => {
                nonempty(&r.project_id)
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::ListExecutions(r) => {
                nonempty(&r.sandbox_id)
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::ListSnapshots(r) => {
                (nonempty(&r.project_id) || nonempty(&r.sandbox_id))
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::Tree(r) => valid_tree_request_v1(r),
            K::Children(r) => {
                nonempty(&r.parent_sandbox_id)
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::Ancestors(r) => {
                nonempty(&r.sandbox_id)
                    && (1..=1_024).contains(&r.bounded_depth)
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::PlanPolicy(r) => {
                nonempty(&r.sandbox_id)
                    && nonempty(&r.expected_resource_version)
                    && descriptor_present(r.requested_policy.as_option())
            }
            K::UpdatePolicy(r) => {
                nonempty(&r.sandbox_id)
                    && descriptor_present(r.requested_policy.as_option())
                    && nonempty(&r.expected_plan_digest)
                    && mutation_resource_only(r.mutation.as_option())
            }
            K::Start(r) => {
                nonempty(&r.sandbox_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::Stop(r) | K::Suspend(r) | K::Resume(r) => {
                nonempty(&r.sandbox_id) && mutation_with_incarnation(r.mutation.as_option())
            }
            K::Exec(r) => {
                nonempty(&r.sandbox_id)
                    && r.command.as_option().is_some_and(valid_command)
                    && nonempty(&r.client_public_key)
                    && nonempty(&r.proof_of_possession)
                    && mutation_with_incarnation(r.mutation.as_option())
                    && r.mutation.as_option().is_some_and(|mutation| {
                        crate::public_api::contains_semantic_features_v1(
                            &mutation.required_features,
                            &[crate::public_api::EXECUTION_CREATE_HOLDER_PROOF_FEATURE_V1],
                        )
                    })
                    && r.command.as_option().is_some_and(|command| {
                        execution_required_features_present(
                            command,
                            &r.mutation
                                .as_option()
                                .map_or(&[][..], |mutation| mutation.required_features.as_slice()),
                        )
                    })
            }
            K::ExecutionControl(r) => {
                // The guest-agent resize effect carries each dimension as u16.
                nonempty(&r.execution_id)
                    && mutation_with_incarnation(r.mutation.as_option())
                    && match r.action.to_i32() {
                        1 => r.terminal_rows == 0
                            && r.terminal_columns == 0
                            && r.signal.to_i32() == 0
                            && (1..=MAXIMUM_ENDPOINT_PROOF_BYTES)
                                .contains(&r.client_public_key.len())
                            && (1..=MAXIMUM_ENDPOINT_PROOF_BYTES)
                                .contains(&r.proof_of_possession.len())
                            && r.mutation.as_option().is_some_and(|mutation| {
                                crate::public_api::contains_semantic_features_v1(
                                    &mutation.required_features,
                                    &[crate::public_api::EXECUTION_ATTACH_HOLDER_PROOF_FEATURE_V1],
                                )
                            }),
                        2 => {
                            (1..=u32::from(u16::MAX)).contains(&r.terminal_rows)
                                && (1..=u32::from(u16::MAX)).contains(&r.terminal_columns)
                                && r.signal.to_i32() == 0
                                && r.client_public_key.is_empty()
                                && r.proof_of_possession.is_empty()
                        }
                        3 => {
                            r.terminal_rows == 0
                                && r.terminal_columns == 0
                                && (1..=7).contains(&r.signal.to_i32())
                                && r.client_public_key.is_empty()
                                && r.proof_of_possession.is_empty()
                        }
                        _ => false,
                    }
            }
            K::CancelExec(r) => {
                nonempty(&r.execution_id) && mutation_with_incarnation(r.mutation.as_option())
            }
            K::CancelOperation(r) => {
                nonempty(&r.operation_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::Snapshot(r) => {
                nonempty(&r.sandbox_id)
                    && (1..=2).contains(&r.requested_availability.to_i32())
                    && mutation_with_incarnation(r.mutation.as_option())
            }
            K::DeleteSnapshot(r) => {
                nonempty(&r.snapshot_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::Restore(r) => {
                nonempty(&r.snapshot_id)
                    && nonempty(&r.target_sandbox_id)
                    && descriptor_present(r.requested_policy.as_option())
                    && mutation_resource_only(r.mutation.as_option())
            }
            K::Fork(r) => {
                nonempty(&r.snapshot_id)
                    && nonempty(&r.target_project_id)
                    && nonempty(&r.expected_project_resource_version)
                    && descriptor_present(r.requested_policy.as_option())
                    && nonempty(&r.idempotency_key)
                    && r.operation_timeout.as_option().is_some_and(|timeout| {
                        (1..=MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout.nanoseconds)
                    })
                    && valid_features(&r.required_features)
                    && crate::public_api::contains_semantic_features_v1(
                        &r.required_features,
                        &[crate::public_api::SNAPSHOT_PROJECT_VERSION_FENCE_FEATURE_V1],
                    )
                    && (r.parent_sandbox_id.is_empty()
                        == r.expected_parent_resource_version.is_empty())
            }
            K::Delete(r) => {
                nonempty(&r.sandbox_id)
                    && nonempty(&r.expected_plan_digest)
                    && mutation_resource_only(r.mutation.as_option())
                    && (!r.force
                        || r.mutation.as_option().is_some_and(|mutation| {
                            crate::public_api::contains_semantic_features_v1(
                                &mutation.required_features,
                                &[crate::public_api::FORCE_DELETE_FEATURE_V1],
                            )
                        }))
            }
            K::Events(r) => {
                nonempty(&r.project_id)
                    && !r.resource_types.is_empty()
                    && r.resource_types.len() <= 64
                    && valid_features(&r.observation_features)
                    && r.resume_after.as_option().is_none_or(|cursor| {
                        nonempty(&cursor.opaque_cursor)
                            && cursor.opaque_cursor.len()
                                <= crate::public_api::limits::MAXIMUM_CLI_OPAQUE_BYTES
                    })
            }
            K::ViewCreate(r) => {
                nonempty(&r.project_id)
                    && descriptor_present(r.revision.as_option())
                    && nonempty(&r.expected_project_resource_version)
                    && nonempty(&r.idempotency_key)
                    && r.operation_timeout.as_option().is_some_and(|timeout| {
                        (1..=MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout.nanoseconds)
                    })
                    && valid_features(&r.required_features)
            }
            K::ViewAttach(r) => {
                nonempty(&r.sandbox_id)
                    && nonempty(&r.view_id)
                    && descriptor_present(r.view_revision.as_option())
                    && nonempty(&r.destination_slot_id)
                    && (1..=5).contains(&r.mutation_mode.to_i32())
                    && mutation_with_incarnation(r.mutation.as_option())
                    && (!r.noexec
                        || r.mutation.as_option().is_some_and(|mutation| {
                            crate::public_api::contains_semantic_features_v1(
                                &mutation.required_features,
                                &[crate::public_api::ATTACHMENT_NOEXEC_FEATURE_V1],
                            )
                        }))
            }
            K::ViewReplace(r) => {
                nonempty(&r.attachment_id)
                    && nonempty(&r.new_view_id)
                    && descriptor_present(r.new_view_revision.as_option())
                    && mutation_resource_only(r.mutation.as_option())
            }
            K::ViewDetach(r) => {
                nonempty(&r.attachment_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::ViewRelease(r) => {
                nonempty(&r.view_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::ViewList(r) => {
                nonempty(&r.project_id)
                    && valid_page_size(r.page_size)
                    && valid_optional_opaque(&r.page_token)
            }
            K::CacheStatus(r) => nonempty(&r.project_id) != nonempty(&r.sandbox_id),
            K::CachePin(r) => {
                descriptor_present(r.object.as_option())
                    && valid_cache_consumer(&r.view_id, &r.attachment_id)
                    && mutation_resource_only(r.mutation.as_option())
                    && r.mutation.as_option().is_some_and(|mutation| {
                        crate::public_api::contains_semantic_features_v1(
                            &mutation.required_features,
                            &[crate::public_api::CACHE_CONSUMER_PIN_FEATURE_V1],
                        )
                    })
            }
            K::CacheUnpin(r) => {
                descriptor_present(r.object.as_option())
                    && valid_cache_consumer(&r.view_id, &r.attachment_id)
                    && mutation_resource_only(r.mutation.as_option())
                    && r.mutation.as_option().is_some_and(|mutation| {
                        crate::public_api::contains_semantic_features_v1(
                            &mutation.required_features,
                            &[crate::public_api::CACHE_CONSUMER_PIN_FEATURE_V1],
                        )
                    })
            }
            K::CapabilitiesPublicApi(_) => true,
            K::CapabilitiesNode(r) => nonempty(&r.node_id),
            K::CapabilityAttenuate(r) => {
                r.parent_capability_handle.len() == 32
                    && nonempty(&r.attenuation)
                    && r.holder_channel_binding.len() == 32
                    && nonempty(&r.idempotency_key)
                    && nonempty(&r.expected_parent_resource_version)
            }
            K::CapabilityInspect(r) => r.capability_handle.len() == 32,
            K::CapabilityRenew(r) => {
                r.capability_handle.len() == 32
                    && r.requested_expiry.as_option().is_some_and(|timestamp| {
                        (-62_135_596_800..=253_402_300_799).contains(&timestamp.seconds)
                            && timestamp.nanoseconds < 1_000_000_000
                    })
                    && mutation_resource_only(r.mutation.as_option())
            }
            K::CapabilityRevoke(r) => {
                nonempty(&r.capability_id) && mutation_resource_only(r.mutation.as_option())
            }
            K::OperatorRecover(r) => validate_operator_recovery_request_v1(r).is_ok(),
            K::Completions(_) => self.output == DormantSandboxOutputV1::Human,
        };

        let framing_is_valid =
            self.output != DormantSandboxOutputV1::JsonLines || self.kind.supports_json_lines();
        if valid && framing_is_valid {
            Ok(())
        } else {
            Err(DormantSandboxRoutingErrorV1::InvalidRequest)
        }
    }
}

fn nonempty(value: &[u8]) -> bool {
    !value.is_empty()
}

fn valid_cache_consumer(view_id: &[u8], attachment_id: &[u8]) -> bool {
    let valid_identity = |value: &[u8]| value.len() == 16 && value.iter().any(|byte| *byte != 0);
    valid_identity(view_id) && (attachment_id.is_empty() || valid_identity(attachment_id))
}

fn descriptor_present(value: Option<&wire::ObjectDescriptor>) -> bool {
    value.is_some_and(|descriptor| {
        !descriptor.media_type.is_empty()
            && descriptor.sha256.len() == 32
            && descriptor.sha256.iter().any(|byte| *byte != 0)
            && descriptor.encoded_size > 0
    })
}

fn mutation_shape(value: Option<&wire::MutationContext>) -> bool {
    value.is_some_and(|mutation| {
        !mutation.idempotency_key.is_empty()
            && mutation.idempotency_key.len()
                <= crate::public_api::limits::MAXIMUM_IDEMPOTENCY_KEY_BYTES
            && !mutation.expected_resource_version.is_empty()
            && mutation.expected_resource_version.len()
                <= crate::public_api::limits::MAXIMUM_CLI_OPAQUE_BYTES
            && mutation
                .operation_timeout
                .as_option()
                .is_some_and(|timeout| {
                    (1..=MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout.nanoseconds)
                })
            && valid_features(&mutation.required_features)
    })
}

fn mutation_resource_only(value: Option<&wire::MutationContext>) -> bool {
    mutation_shape(value)
        && value.is_some_and(|mutation| mutation.expected_incarnation_id.is_empty())
}

fn mutation_with_incarnation(value: Option<&wire::MutationContext>) -> bool {
    mutation_shape(value)
        && value.is_some_and(|mutation| {
            mutation.expected_incarnation_id.len() == 16
                && mutation
                    .expected_incarnation_id
                    .iter()
                    .any(|byte| *byte != 0)
        })
}

fn valid_page_size(value: u32) -> bool {
    (1..=1_024).contains(&value)
}

pub(super) fn valid_tree_request_v1(request: &wire::ListDescendantsRequest) -> bool {
    let continuation_is_valid = match (
        request.page_token.is_empty(),
        request.expected_preorder_before.as_option(),
    ) {
        (true, None) => true,
        (false, Some(state)) => {
            state.emitted_nodes > 0
                && state
                    .open_path
                    .first()
                    .is_some_and(|root| root == &request.sandbox_id)
                && validate_sandbox_tree_preorder_state_v1(state).is_ok()
        }
        _ => false,
    };
    nonempty(&request.sandbox_id)
        && request.sandbox_id.len() == 16
        && (1..=1_024).contains(&request.maximum_depth)
        && valid_page_size(request.page_size)
        && valid_optional_opaque(&request.page_token)
        && continuation_is_valid
}

fn valid_optional_opaque(value: &[u8]) -> bool {
    value.is_empty() || value.len() <= crate::public_api::limits::MAXIMUM_CLI_OPAQUE_BYTES
}

fn valid_command(command: &wire::Command) -> bool {
    let direct = command
        .arguments
        .first()
        .is_some_and(|program| !program.is_empty())
        && command.sandbox_shell.is_empty();
    let shell = command.arguments.is_empty()
        && !command.sandbox_shell.is_empty()
        && command.sandbox_shell.len() <= MAXIMUM_EXEC_ARGUMENT_BYTES
        && !command.sandbox_shell.contains(&0);
    // The runtime execution effect encodes PTY geometry as two u16 values.
    let io_shape_is_valid = match command.io_mode.to_i32() {
        1 => {
            !command.allocate_terminal
                && command.terminal_rows == 0
                && command.terminal_columns == 0
                && command.detached_capture_bytes == 0
                && command.maximum_stdout_bytes.is_none()
                && command.maximum_stderr_bytes.is_none()
        }
        2 => {
            command.allocate_terminal
                && (1..=u32::from(u16::MAX)).contains(&command.terminal_rows)
                && (1..=u32::from(u16::MAX)).contains(&command.terminal_columns)
                && command.detached_capture_bytes == 0
                && command.maximum_stdout_bytes.is_none()
                && command.maximum_stderr_bytes.is_none()
        }
        3 => {
            !command.allocate_terminal
                && command.terminal_rows == 0
                && command.terminal_columns == 0
                && crate::public_api::portable_resource::checked_detached_capture_bytes(command)
                    .is_some()
        }
        _ => false,
    };
    let argument_bytes = command.arguments.iter().map(Vec::len).sum::<usize>();
    (direct || shell)
        && command.arguments.len() <= MAXIMUM_EXEC_ARGUMENTS
        && command
            .arguments
            .iter()
            .all(|argument| argument.len() <= MAXIMUM_EXEC_ARGUMENT_BYTES && !argument.contains(&0))
        && argument_bytes <= MAXIMUM_EXEC_ARGUMENT_VECTOR_BYTES
        && command
            .execution_timeout
            .as_option()
            .is_some_and(|timeout| {
                (1..=MAXIMUM_CLI_WAIT_NANOSECONDS).contains(&timeout.nanoseconds)
            })
        && io_shape_is_valid
        && valid_features(&command.stream_features)
        && valid_environment(&command.environment)
        && valid_relative_path(&command.working_directory)
}

fn valid_features(features: &[wire::Feature]) -> bool {
    crate::public_api::portable::CheckedFeatureSetV1::try_from(features.to_vec()).is_ok()
}

fn valid_environment(environment: &[wire::EnvironmentVariable]) -> bool {
    let total_bytes = environment.iter().try_fold(0_usize, |total, variable| {
        total
            .checked_add(variable.name.len())?
            .checked_add(variable.value.len())
    });
    environment.len() <= crate::public_api::limits::MAXIMUM_EXEC_ENVIRONMENT
        && total_bytes
            .is_some_and(|bytes| bytes <= crate::public_api::limits::MAXIMUM_EXEC_ENVIRONMENT_BYTES)
        && environment.iter().all(|variable| {
            !variable.name.is_empty()
                && variable.name.len()
                    <= crate::public_api::limits::MAXIMUM_EXEC_ENVIRONMENT_NAME_BYTES
                && variable.value.len()
                    <= crate::public_api::limits::MAXIMUM_EXEC_ENVIRONMENT_VALUE_BYTES
                && variable.name.len() + 1 + variable.value.len() + 1
                    <= aos_sandbox_core::MAX_EXECUTION_STRING_BYTES
                && !variable.value.contains(&0)
                && variable.name.bytes().enumerate().all(|(index, byte)| {
                    byte == b'_'
                        || byte.is_ascii_alphabetic()
                        || (index > 0 && byte.is_ascii_digit())
                })
        })
        && environment
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
}

fn valid_relative_path(path: &[u8]) -> bool {
    path.is_empty()
        || (!path.starts_with(b"/")
            && !path.contains(&0)
            && path
                .split(|byte| *byte == b'/')
                .all(|component| !component.is_empty() && component != b"." && component != b".."))
}

/// Validates an untrusted operator-recovery request without adopting authority.
///
/// The identity, descriptor, and scalar checks retain their established order.
/// The Controller independently binds current evidence and authenticated
/// provenance before recovery can be admitted.
///
/// # Errors
///
/// Returns the established invalid-request error for an invalid identity,
/// missing or malformed descriptor, version, action, or idempotency key.
pub fn validate_operator_recovery_request_v1(
    value: &wire::OperatorRecoveryRequest,
) -> Result<(), DormantSandboxRoutingErrorV1> {
    let resource_id: [u8; 16] = value
        .resource_id
        .as_slice()
        .try_into()
        .map_err(|_| DormantSandboxRoutingErrorV1::InvalidRequest)?;
    let evidence = value
        .evidence
        .as_option()
        .ok_or(DormantSandboxRoutingErrorV1::InvalidRequest)?
        .clone();
    crate::public_api::portable::CheckedObjectDescriptorV1::try_from(evidence.clone())
        .map_err(|_| DormantSandboxRoutingErrorV1::InvalidRequest)?;
    if resource_id == [0; 16]
        || value.expected_resource_version.is_empty()
        || value.expected_resource_version.len()
            > crate::public_api::limits::MAXIMUM_CLI_OPAQUE_BYTES
        || !(1..=4).contains(&value.action.to_i32())
        || value.idempotency_key.is_empty()
        || value.idempotency_key.len() > crate::public_api::limits::MAXIMUM_IDEMPOTENCY_KEY_BYTES
    {
        return Err(DormantSandboxRoutingErrorV1::InvalidRequest);
    }
    Ok(())
}
