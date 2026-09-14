//! Deeply checked established public resources used by portable clients.
//!
//! These wrappers retain generated protobuf messages after validating their
//! complete nested shape. They are render projections, not another wire schema.

use aos_proto::aos::sandbox::v1::{
    Attachment, AttachmentPhase, Capability, Execution, ExecutionPhase, FilesystemView,
    NodeCapabilities, Snapshot, SnapshotAvailability, SnapshotPhase, ViewMutation, ViewPhase,
};
use buffa::Message as _;

use super::model::{ClientStateItem, OpaqueResponseBytesV1, OpaqueResponseKindV1};
use super::registry::{checked_timestamp, validate_descriptor_media, validate_features};
use super::resource::{
    checked_conditions, exact_nonzero_id, validate_resource_size, InvalidPublicResource,
    MAXIMUM_SAFE_MESSAGE_BYTES,
};

const MAXIMUM_COMMAND_ARGUMENTS: usize = 1_024;
const MAXIMUM_COMMAND_ARGUMENT_BYTES: usize = 1024 * 1024;
const MAXIMUM_COMMAND_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_ENVIRONMENT_ROWS: usize = 256;
const MAXIMUM_ENVIRONMENT_NAME_BYTES: usize = 256;
const MAXIMUM_ENVIRONMENT_VALUE_BYTES: usize = 1024 * 1024;
const MAXIMUM_RELATIVE_PATH_BYTES: usize = 4 * 1024;
const MAXIMUM_ENDPOINT_TEXT_BYTES: usize = 4 * 1024;

macro_rules! checked_public_resource {
    ($name:ident, $message:ty) => {
        impl super::client_state_sealed::Sealed for $name {}

        impl ClientStateItem for $name {
            fn encoded_byte_cost(&self) -> usize {
                self.0.compute_size() as usize
            }
        }

        impl $name {
            /// Returns the deeply checked established protobuf resource.
            #[must_use]
            pub const fn as_proto(&self) -> &$message {
                &self.0
            }

            /// Consumes the wrapper and returns the established protobuf resource.
            #[must_use]
            pub fn into_proto(self) -> $message {
                self.0
            }
        }
    };
}

/// Stores one deeply checked established execution resource.
#[derive(Clone, PartialEq)]
pub struct CheckedExecutionResourceV1 {
    wire: Execution,
    public_wire: Execution,
}

impl std::fmt::Debug for CheckedExecutionResourceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CheckedExecutionResourceV1")
            .field("phase", &self.public_wire.phase)
            .field("encoded_bytes", &self.wire.compute_size())
            .field("holder_credentials", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl TryFrom<Execution> for CheckedExecutionResourceV1 {
    type Error = InvalidPublicResource;

    fn try_from(value: Execution) -> Result<Self, Self::Error> {
        validate_resource_size(&value)?;
        exact_nonzero_id(&value.execution_id)?;
        exact_nonzero_id(&value.sandbox_id)?;
        exact_nonzero_id(&value.sandbox_incarnation_id)?;
        exact_nonzero_id(&value.audit_id)?;
        checked_version(&value.resource_version)?;

        let command = value
            .command
            .as_option()
            .ok_or(InvalidPublicResource::Unspecified)?;
        validate_command(command)?;
        let phase = value
            .phase
            .as_known()
            .filter(|phase| *phase != ExecutionPhase::EXECUTION_PHASE_UNSPECIFIED)
            .ok_or(InvalidPublicResource::UnknownRegistryValue)?;
        if let Some(access) = value.access.as_option() {
            if access.port == 0
                || access.port > u32::from(u16::MAX)
                || !safe_text(&access.host, MAXIMUM_ENDPOINT_TEXT_BYTES)
                || !safe_text(&access.user, MAXIMUM_ENDPOINT_TEXT_BYTES)
                || access.host_public_key.is_empty()
                || access.client_certificate.is_empty()
            {
                return Err(InvalidPublicResource::InvalidScalar);
            }
            checked_timestamp(
                access
                    .expires_at
                    .as_option()
                    .ok_or(InvalidPublicResource::Unspecified)?,
            )?;
            if exact_nonzero_id(&access.execution_id)? != exact_nonzero_id(&value.execution_id)?
                || exact_nonzero_id(&access.sandbox_incarnation_id)?
                    != exact_nonzero_id(&value.sandbox_incarnation_id)?
            {
                return Err(InvalidPublicResource::InvalidPlacement);
            }
            exact_nonzero_id(&access.principal_id)?;
            if exact_nonzero_id(&access.audit_id)? != exact_nonzero_id(&value.audit_id)? {
                return Err(InvalidPublicResource::InvalidPlacement);
            }
            validate_features(&access.stream_features)?;
        }
        let is_terminal = matches!(
            phase,
            ExecutionPhase::EXECUTION_PHASE_EXITED
                | ExecutionPhase::EXECUTION_PHASE_CANCELED
                | ExecutionPhase::EXECUTION_PHASE_FAILED
                | ExecutionPhase::EXECUTION_PHASE_LOST
        );
        if (phase == ExecutionPhase::EXECUTION_PHASE_EXITED && value.result.as_option().is_none())
            || (!is_terminal && value.result.as_option().is_some())
        {
            return Err(InvalidPublicResource::InvalidOperationState);
        }
        if let Some(result) = value.result.as_option() {
            if result.termination_reason.len() > MAXIMUM_SAFE_MESSAGE_BYTES
                || result.termination_reason.chars().any(char::is_control)
            {
                return Err(InvalidPublicResource::InvalidCode);
            }
            checked_timestamp(
                result
                    .exited_at
                    .as_option()
                    .ok_or(InvalidPublicResource::Unspecified)?,
            )?;
        }
        checked_conditions(&value.conditions)?;
        let mut public_wire = value.clone();
        public_wire.access = Default::default();
        Ok(Self {
            wire: value,
            public_wire,
        })
    }
}

impl super::client_state_sealed::Sealed for CheckedExecutionResourceV1 {}

impl ClientStateItem for CheckedExecutionResourceV1 {
    fn encoded_byte_cost(&self) -> usize {
        self.wire.compute_size() as usize
    }
}

impl CheckedExecutionResourceV1 {
    /// Returns a checked public execution with holder credentials removed.
    #[must_use]
    pub const fn as_proto(&self) -> &Execution {
        &self.public_wire
    }

    /// Consumes the wrapper and returns the redacted established resource.
    #[must_use]
    pub fn into_proto(self) -> Execution {
        self.public_wire
    }
}

/// Stores one deeply checked established filesystem-view resource.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedFilesystemViewResourceV1(FilesystemView);

impl TryFrom<FilesystemView> for CheckedFilesystemViewResourceV1 {
    type Error = InvalidPublicResource;

    fn try_from(value: FilesystemView) -> Result<Self, Self::Error> {
        validate_resource_size(&value)?;
        exact_nonzero_id(&value.view_id)?;
        exact_nonzero_id(&value.project_id)?;
        checked_version(&value.resource_version)?;
        validate_descriptor_media(
            value
                .revision
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
            "application/vnd.aos.sandbox.view.v1+cbor",
        )?;
        value
            .phase
            .as_known()
            .filter(|phase| *phase != ViewPhase::VIEW_PHASE_UNSPECIFIED)
            .ok_or(InvalidPublicResource::UnknownRegistryValue)?;
        checked_conditions(&value.conditions)?;
        Ok(Self(value))
    }
}

checked_public_resource!(CheckedFilesystemViewResourceV1, FilesystemView);

/// Stores one deeply checked established attachment resource.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedAttachmentResourceV1(Attachment);

impl TryFrom<Attachment> for CheckedAttachmentResourceV1 {
    type Error = InvalidPublicResource;

    fn try_from(value: Attachment) -> Result<Self, Self::Error> {
        validate_resource_size(&value)?;
        exact_nonzero_id(&value.attachment_id)?;
        exact_nonzero_id(&value.sandbox_id)?;
        exact_nonzero_id(&value.destination_slot_id)?;
        checked_version(&value.resource_version)?;
        validate_descriptor_media(
            value
                .view_revision
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
            "application/vnd.aos.sandbox.view.v1+cbor",
        )?;
        value
            .mutation
            .as_known()
            .filter(|mutation| *mutation != ViewMutation::VIEW_MUTATION_UNSPECIFIED)
            .ok_or(InvalidPublicResource::UnknownRegistryValue)?;
        value
            .phase
            .as_known()
            .filter(|phase| *phase != AttachmentPhase::ATTACHMENT_PHASE_UNSPECIFIED)
            .ok_or(InvalidPublicResource::UnknownRegistryValue)?;
        if value.desired_generation == 0 || value.source_generation == 0 {
            return Err(InvalidPublicResource::Unspecified);
        }
        checked_conditions(&value.conditions)?;
        Ok(Self(value))
    }
}

checked_public_resource!(CheckedAttachmentResourceV1, Attachment);

/// Stores one deeply checked established snapshot resource.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedSnapshotResourceV1(Snapshot);

impl TryFrom<Snapshot> for CheckedSnapshotResourceV1 {
    type Error = InvalidPublicResource;

    fn try_from(value: Snapshot) -> Result<Self, Self::Error> {
        validate_resource_size(&value)?;
        exact_nonzero_id(&value.snapshot_id)?;
        exact_nonzero_id(&value.source_sandbox_id)?;
        exact_nonzero_id(&value.project_id)?;
        checked_version(&value.resource_version)?;
        validate_descriptor_media(
            value
                .manifest
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
            "application/vnd.aos.sandbox.snapshot.v1+cbor",
        )?;
        value
            .phase
            .as_known()
            .filter(|phase| *phase != SnapshotPhase::SNAPSHOT_PHASE_UNSPECIFIED)
            .ok_or(InvalidPublicResource::UnknownRegistryValue)?;
        value
            .availability
            .as_known()
            .filter(|availability| {
                *availability != SnapshotAvailability::SNAPSHOT_AVAILABILITY_UNSPECIFIED
            })
            .ok_or(InvalidPublicResource::UnknownRegistryValue)?;
        checked_conditions(&value.conditions)?;
        checked_timestamp(
            value
                .created_at
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
        )?;
        Ok(Self(value))
    }
}

checked_public_resource!(CheckedSnapshotResourceV1, Snapshot);

/// Stores one deeply checked established non-secret capability summary.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedCapabilityResourceV1(Capability);

impl TryFrom<Capability> for CheckedCapabilityResourceV1 {
    type Error = InvalidPublicResource;

    fn try_from(value: Capability) -> Result<Self, Self::Error> {
        validate_resource_size(&value)?;
        exact_nonzero_id(&value.capability_id)?;
        exact_nonzero_id(&value.project_id)?;
        if !value.sandbox_id.is_empty() {
            exact_nonzero_id(&value.sandbox_id)?;
        }
        exact_nonzero_id(&value.holder_principal_id)?;
        checked_version(&value.resource_version)?;
        let not_before = checked_timestamp(
            value
                .not_before
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
        )?;
        let expires_at = checked_timestamp(
            value
                .expires_at
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
        )?;
        if expires_at <= not_before {
            return Err(InvalidPublicResource::InvalidScalar);
        }
        validate_descriptor_media(
            value
                .effective_policy
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
            "application/vnd.aos.sandbox.policy.v1+cbor",
        )?;
        Ok(Self(value))
    }
}

checked_public_resource!(CheckedCapabilityResourceV1, Capability);

/// Stores one deeply checked public node-capability observation.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedNodeCapabilitiesV1(NodeCapabilities);

impl TryFrom<NodeCapabilities> for CheckedNodeCapabilitiesV1 {
    type Error = InvalidPublicResource;

    fn try_from(value: NodeCapabilities) -> Result<Self, Self::Error> {
        validate_resource_size(&value)?;
        exact_nonzero_id(&value.node_id)?;
        checked_version(&value.resource_version)?;
        if value.capability_generation == 0 || value.capabilities.len() > 128 {
            return Err(InvalidPublicResource::CollectionNotCanonical);
        }
        for capability in &value.capabilities {
            let feature = capability
                .feature
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?;
            validate_features(std::slice::from_ref(feature))?;
            if capability.conformance_fixture_digest.len() != 32
                || capability
                    .conformance_fixture_digest
                    .iter()
                    .all(|byte| *byte == 0)
                || (capability.available && !capability.unavailable_reason.is_empty())
                || (!capability.available
                    && !safe_text(&capability.unavailable_reason, MAXIMUM_SAFE_MESSAGE_BYTES))
            {
                return Err(InvalidPublicResource::InvalidScalar);
            }
        }
        if !value.capabilities.windows(2).all(|pair| {
            let previous = pair[0].feature.as_option();
            let next = pair[1].feature.as_option();
            match (previous, next) {
                (Some(previous), Some(next)) => {
                    (&previous.namespace, previous.major, previous.minor)
                        < (&next.namespace, next.major, next.minor)
                }
                _ => false,
            }
        }) {
            return Err(InvalidPublicResource::CollectionNotCanonical);
        }
        checked_timestamp(
            value
                .observed_at
                .as_option()
                .ok_or(InvalidPublicResource::Unspecified)?,
        )?;
        Ok(Self(value))
    }
}

checked_public_resource!(CheckedNodeCapabilitiesV1, NodeCapabilities);

fn checked_version(value: &[u8]) -> Result<(), InvalidPublicResource> {
    OpaqueResponseBytesV1::from_response(value.to_vec(), OpaqueResponseKindV1::ResourceVersion)?;
    Ok(())
}

fn validate_command(
    command: &aos_proto::aos::sandbox::v1::Command,
) -> Result<(), InvalidPublicResource> {
    if command.arguments.first().is_none_or(Vec::is_empty)
        || command.arguments.len() > MAXIMUM_COMMAND_ARGUMENTS
    {
        return Err(InvalidPublicResource::CollectionNotCanonical);
    }
    let argument_bytes = command
        .arguments
        .iter()
        .try_fold(0_usize, |total, argument| {
            if argument.len() > MAXIMUM_COMMAND_ARGUMENT_BYTES || argument.contains(&0) {
                return Err(InvalidPublicResource::InvalidScalar);
            }
            total
                .checked_add(argument.len())
                .ok_or(InvalidPublicResource::ResourceTooLarge)
        })?;
    if argument_bytes > MAXIMUM_COMMAND_BYTES
        || command.environment.len() > MAXIMUM_ENVIRONMENT_ROWS
    {
        return Err(InvalidPublicResource::CollectionNotCanonical);
    }
    let mut environment_bytes = 0_usize;
    let mut previous_name: Option<&str> = None;
    for variable in &command.environment {
        if !valid_environment_name(&variable.name)
            || variable.value.len() > MAXIMUM_ENVIRONMENT_VALUE_BYTES
            || variable.value.contains(&0)
            || previous_name.is_some_and(|previous| previous >= variable.name.as_str())
        {
            return Err(InvalidPublicResource::CollectionNotCanonical);
        }
        environment_bytes = environment_bytes
            .checked_add(variable.name.len())
            .and_then(|total| total.checked_add(variable.value.len()))
            .ok_or(InvalidPublicResource::ResourceTooLarge)?;
        previous_name = Some(&variable.name);
    }
    if environment_bytes > MAXIMUM_COMMAND_BYTES || !valid_relative_path(&command.working_directory)
    {
        return Err(InvalidPublicResource::InvalidScalar);
    }
    Ok(())
}

fn valid_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAXIMUM_ENVIRONMENT_NAME_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}

fn valid_relative_path(value: &[u8]) -> bool {
    if value.is_empty() {
        return true;
    }
    value.len() <= MAXIMUM_RELATIVE_PATH_BYTES
        && !value.contains(&0)
        && value.first() != Some(&b'/')
        && value.last() != Some(&b'/')
        && value
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

fn safe_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}
