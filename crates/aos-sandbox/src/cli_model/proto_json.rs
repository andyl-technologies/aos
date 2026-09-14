//! Bounded ProtoJSON rendering from checked established-message projections.

use std::fmt;

use aos_proto::aos::sandbox::v1::{
    ListAncestorsResponse, ListChildrenResponse, ListDescendantsResponse, ListExecutionsResponse,
    ListSandboxesResponse, ListSnapshotsResponse, ListViewsResponse, PageInfo,
};
use buffa::Message as _;

use crate::controller_query::event::CheckedWatchEventV1;
use crate::controller_query::model::MAXIMUM_OPAQUE_RESPONSE_BYTES;
use crate::controller_query::portable_resource::{
    CheckedAttachmentResourceV1, CheckedCapabilityResourceV1, CheckedExecutionResourceV1,
    CheckedFilesystemViewResourceV1, CheckedNodeCapabilitiesV1, CheckedSnapshotResourceV1,
};
use crate::controller_query::resource::{
    CheckedOperationResourceV1, CheckedSandboxResourceV1, InvalidPublicResource,
};

/// Maximum bytes in one checked structured output document.
pub const MAXIMUM_PROTO_JSON_BYTES: usize = 16 * 1024 * 1024;
/// Maximum resources in one checked structured list document.
pub const MAXIMUM_PROTO_JSON_LIST_ITEMS: usize = 1_024;

/// Identifies the only schemas a structured renderer may emit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuredOutputSchemaV1 {
    /// Uses the established sandbox resource mapping.
    Sandbox,
    /// Uses the established operation resource mapping.
    Operation,
    /// Uses the established execution resource mapping.
    Execution,
    /// Uses the established filesystem-view resource mapping.
    FilesystemView,
    /// Uses the established attachment resource mapping.
    Attachment,
    /// Uses the established snapshot resource mapping.
    Snapshot,
    /// Uses the established capability resource mapping.
    Capability,
    /// Uses the established node-capabilities mapping.
    NodeCapabilities,
    /// Uses the established sandbox list-response mapping.
    SandboxList,
    /// Uses the established child list-response mapping.
    ChildrenList,
    /// Uses the established ancestor list-response mapping.
    AncestorsList,
    /// Uses the established descendant list-response mapping.
    DescendantsList,
    /// Uses the established execution list-response mapping.
    ExecutionList,
    /// Uses the established view list-response mapping.
    ViewList,
    /// Uses the established snapshot list-response mapping.
    SnapshotList,
    /// Uses the established public event mapping.
    Event,
    /// Emits a shell completion script as human text only.
    CompletionScript,
    /// Emits the compiled public feature registry as human text only.
    PublicFeatureRegistryText,
    /// Emits cache status as human text pending an established public schema.
    CacheStatusText,
    /// Emits a policy plan as text pending a closed public reason registry.
    PolicyPlanText,
    /// Emits an immediate execution-control result pending a public response schema.
    ExecutionControlResultText,
}

mod sealed {
    pub trait Sealed {}
}

/// Marks checked projections whose retained message has an established mapping.
pub trait EstablishedProtoJson: sealed::Sealed {
    /// Returns the output schema carried by this checked projection.
    fn output_schema(&self) -> StructuredOutputSchemaV1;

    /// Renders only the retained established generated message.
    #[doc(hidden)]
    fn render_established(&self) -> Result<String, serde_json::Error>;
}

macro_rules! established_resource {
    ($wrapper:ty, $schema:ident) => {
        impl sealed::Sealed for $wrapper {}

        impl EstablishedProtoJson for $wrapper {
            fn output_schema(&self) -> StructuredOutputSchemaV1 {
                StructuredOutputSchemaV1::$schema
            }

            fn render_established(&self) -> Result<String, serde_json::Error> {
                serde_json::to_string(self.as_proto())
            }
        }
    };
}

established_resource!(CheckedSandboxResourceV1, Sandbox);
established_resource!(CheckedOperationResourceV1, Operation);
established_resource!(CheckedExecutionResourceV1, Execution);
established_resource!(CheckedFilesystemViewResourceV1, FilesystemView);
established_resource!(CheckedAttachmentResourceV1, Attachment);
established_resource!(CheckedSnapshotResourceV1, Snapshot);
established_resource!(CheckedCapabilityResourceV1, Capability);
established_resource!(CheckedNodeCapabilitiesV1, NodeCapabilities);

impl sealed::Sealed for CheckedWatchEventV1 {}

impl EstablishedProtoJson for CheckedWatchEventV1 {
    fn output_schema(&self) -> StructuredOutputSchemaV1 {
        StructuredOutputSchemaV1::Event
    }

    fn render_established(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self.as_proto())
    }
}

/// Reports failed, oversized, or structurally invalid established ProtoJSON.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidProtoJson {
    /// An established generated message failed deep public validation.
    #[error("established ProtoJSON source is not a valid public resource")]
    InvalidResource,
    /// Established serialization failed.
    #[error("established ProtoJSON serialization failed")]
    Serialization,
    /// The rendered document is empty or exceeds its byte ceiling.
    #[error("established ProtoJSON exceeds its output bound")]
    Size,
}

impl From<InvalidPublicResource> for InvalidProtoJson {
    fn from(_: InvalidPublicResource) -> Self {
        Self::InvalidResource
    }
}

/// Stores one compact document rendered from a checked established message.
#[derive(Clone, Eq, PartialEq)]
pub struct CheckedProtoJsonV1 {
    schema: StructuredOutputSchemaV1,
    rendered: String,
}

impl CheckedProtoJsonV1 {
    /// Serializes a closed-registry checked projection using its established mapping.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidProtoJson`] for serialization failure or size overflow.
    pub fn render<T: EstablishedProtoJson>(message: &T) -> Result<Self, InvalidProtoJson> {
        let rendered = message
            .render_established()
            .map_err(|_| InvalidProtoJson::Serialization)?;
        if rendered.is_empty() || rendered.len() > MAXIMUM_PROTO_JSON_BYTES {
            Err(InvalidProtoJson::Size)
        } else {
            Ok(Self {
                schema: message.output_schema(),
                rendered,
            })
        }
    }

    /// Returns the checked established schema carried by this document.
    #[must_use]
    pub const fn schema(&self) -> StructuredOutputSchemaV1 {
        self.schema
    }

    /// Returns the compact established ProtoJSON document.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.rendered
    }
}

impl fmt::Debug for CheckedProtoJsonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckedProtoJsonV1")
            .field("schema", &self.schema)
            .field("redacted_bytes", &self.rendered.len())
            .finish_non_exhaustive()
    }
}

/// Stores one deeply checked established list or tree response.
#[derive(Clone, PartialEq)]
pub struct CheckedListProtoJsonV1 {
    schema: StructuredOutputSchemaV1,
    wire: CheckedListWireV1,
}

#[derive(Clone, PartialEq)]
enum CheckedListWireV1 {
    Sandboxes(ListSandboxesResponse),
    Children(ListChildrenResponse),
    Ancestors(ListAncestorsResponse),
    Descendants(ListDescendantsResponse),
    Executions(ListExecutionsResponse),
    Views(ListViewsResponse),
    Snapshots(ListSnapshotsResponse),
}

impl fmt::Debug for CheckedListProtoJsonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckedListProtoJsonV1")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

macro_rules! checked_list_conversion {
    ($message:ty, $field:ident, $variant:ident, $wrapper:ty, $schema:expr) => {
        impl TryFrom<$message> for CheckedListProtoJsonV1 {
            type Error = InvalidProtoJson;

            fn try_from(value: $message) -> Result<Self, Self::Error> {
                if value.$field.len() > MAXIMUM_PROTO_JSON_LIST_ITEMS
                    || value.compute_size() as usize > MAXIMUM_PROTO_JSON_BYTES
                {
                    return Err(InvalidProtoJson::InvalidResource);
                }
                let page = value
                    .page
                    .as_option()
                    .ok_or(InvalidProtoJson::InvalidResource)?;
                validate_page(page)?;
                if value.$field.is_empty() && !page.next_page_token.is_empty() {
                    return Err(InvalidProtoJson::InvalidResource);
                }
                for resource in &value.$field {
                    <$wrapper>::try_from(resource.clone())?;
                }
                Ok(Self {
                    schema: $schema,
                    wire: CheckedListWireV1::$variant(value),
                })
            }
        }
    };
}

checked_list_conversion!(
    ListSandboxesResponse,
    sandboxes,
    Sandboxes,
    CheckedSandboxResourceV1,
    StructuredOutputSchemaV1::SandboxList
);
checked_list_conversion!(
    ListChildrenResponse,
    children,
    Children,
    CheckedSandboxResourceV1,
    StructuredOutputSchemaV1::ChildrenList
);
checked_list_conversion!(
    ListAncestorsResponse,
    ancestors,
    Ancestors,
    CheckedSandboxResourceV1,
    StructuredOutputSchemaV1::AncestorsList
);
checked_list_conversion!(
    ListDescendantsResponse,
    descendants,
    Descendants,
    CheckedSandboxResourceV1,
    StructuredOutputSchemaV1::DescendantsList
);
impl TryFrom<ListExecutionsResponse> for CheckedListProtoJsonV1 {
    type Error = InvalidProtoJson;

    fn try_from(mut value: ListExecutionsResponse) -> Result<Self, Self::Error> {
        if value.executions.len() > MAXIMUM_PROTO_JSON_LIST_ITEMS
            || value.compute_size() as usize > MAXIMUM_PROTO_JSON_BYTES
        {
            return Err(InvalidProtoJson::InvalidResource);
        }
        let page = value
            .page
            .as_option()
            .ok_or(InvalidProtoJson::InvalidResource)?;
        validate_page(page)?;
        if value.executions.is_empty() && !page.next_page_token.is_empty() {
            return Err(InvalidProtoJson::InvalidResource);
        }
        let checked = value
            .executions
            .drain(..)
            .map(CheckedExecutionResourceV1::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        value.executions = checked
            .into_iter()
            .map(CheckedExecutionResourceV1::into_proto)
            .collect();
        Ok(Self {
            schema: StructuredOutputSchemaV1::ExecutionList,
            wire: CheckedListWireV1::Executions(value),
        })
    }
}
checked_list_conversion!(
    ListViewsResponse,
    views,
    Views,
    CheckedFilesystemViewResourceV1,
    StructuredOutputSchemaV1::ViewList
);
checked_list_conversion!(
    ListSnapshotsResponse,
    snapshots,
    Snapshots,
    CheckedSnapshotResourceV1,
    StructuredOutputSchemaV1::SnapshotList
);

impl sealed::Sealed for CheckedListProtoJsonV1 {}

impl EstablishedProtoJson for CheckedListProtoJsonV1 {
    fn output_schema(&self) -> StructuredOutputSchemaV1 {
        self.schema
    }

    fn render_established(&self) -> Result<String, serde_json::Error> {
        match &self.wire {
            CheckedListWireV1::Sandboxes(value) => serde_json::to_string(value),
            CheckedListWireV1::Children(value) => serde_json::to_string(value),
            CheckedListWireV1::Ancestors(value) => serde_json::to_string(value),
            CheckedListWireV1::Descendants(value) => serde_json::to_string(value),
            CheckedListWireV1::Executions(value) => serde_json::to_string(value),
            CheckedListWireV1::Views(value) => serde_json::to_string(value),
            CheckedListWireV1::Snapshots(value) => serde_json::to_string(value),
        }
    }
}

fn validate_page(value: &PageInfo) -> Result<(), InvalidProtoJson> {
    let revision_is_valid = !value.immutable_list_revision.is_empty()
        && value.immutable_list_revision.len() <= MAXIMUM_OPAQUE_RESPONSE_BYTES;
    let token_is_valid = value.next_page_token.len() <= MAXIMUM_OPAQUE_RESPONSE_BYTES;
    if revision_is_valid && token_is_valid {
        Ok(())
    } else {
        Err(InvalidProtoJson::InvalidResource)
    }
}
