//! Exact immutable record scopes supplied to installed extension semantics.
//!
//! A scope describes admission data, not live execution authority. Its record
//! identity covers the entire containing object, including the exact extension
//! parameters, rather than only a vendor's feature name.

use crucible_node_contract::{
    HashRef, Id, NodeBinding, NodeDescriptor, OperatingMode, WorldBinding, canonical,
};
use serde::{Deserialize, Serialize};

use crate::node_admission::{
    AdmissionError, AdmissionLimits, AdmissionRequest, AdmissionSubject, evidence::bounded_core,
};

/// Identifies one independently qualified identity-bearing core record location.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionRecordKind {
    /// Selects the complete logical node descriptor.
    NodeDescriptor,
    /// Selects a directed port's complete semantics and ownership.
    PortDescriptor,
    /// Selects a port's directed lane.
    LaneDescriptor,
    /// Selects an independently installed payload or state schema.
    SchemaRef,
    /// Selects one advertised or chosen operation facet.
    FacetSelection,
    /// Selects the actual operating mode and timing policy.
    OperatingContract,
    /// Selects the actual implementation's advertised capability profile.
    CapabilityProfile,
    /// Selects an independently qualified guarantee profile.
    GuaranteeProfile,
    /// Selects one actual implementation artifact identity.
    ArtifactIdentity,
    /// Selects the complete installed implementation identity.
    ImplementationIdentity,
    /// Selects the node's durable execution compatibility record.
    BindingCompatibility,
    /// Selects the operational wrapper excluded from durable compatibility.
    NodeBinding,
    /// Selects operational native authority excluded from durable compatibility.
    LiveAuthority,
    /// Selects the immutable complete world's contract.
    WorldBinding,
    /// Selects a world or owner reference to an actual node binding.
    NodeBindingRef,
    /// Selects an execution or capture owner's complete binding.
    OwnerBinding,
    /// Selects a public connection's complete semantics and custody.
    ConnectionDescriptor,
}

impl ExtensionRecordKind {
    /// Reports whether the containing object binds durable world semantics.
    pub fn is_durable(self) -> bool {
        !matches!(self, Self::NodeBinding | Self::LiveAuthority)
    }
}

/// Binds an extension application to the exact immutable world and record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtensionApplicationScope {
    world_hash: HashRef,
    record_kind: ExtensionRecordKind,
    record_hash: HashRef,
    node: Option<Id>,
    binding_hash: Option<HashRef>,
    record_path: ExtensionRecordPath,
}

/// Disambiguates identically named records at different positions in a world.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExtensionRecordPath {
    /// Names the root world record.
    World,
    /// Names a record directly owned by the scoped node.
    Node,
    /// Names one port within the scoped node.
    Port {
        /// Names the exact containing port.
        port: Id,
    },
    /// Names one directed lane within a port.
    Lane {
        /// Names the exact containing port.
        port: Id,
        /// Names the directed lane.
        lane: Id,
    },
    /// Names the schema at one directed lane, independently of other schema uses.
    LaneSchema {
        /// Names the containing port.
        port: Id,
        /// Names the containing directed lane.
        lane: Id,
        /// Names the exact schema.
        schema: Id,
    },
    /// Names a format in the installed implementation's schema inventory.
    ImplementationSchema {
        /// Names the exact installed format.
        schema: Id,
        /// Disambiguates simultaneously installed editions of one format.
        version: u16,
    },
    /// Names an operation facet in an implementation's advertised capability.
    AdvertisedFacet {
        /// Names the actual advertised facet.
        facet: Id,
    },
    /// Names an operation facet selected by the operating contract.
    SelectedFacet {
        /// Names the actual selected facet.
        facet: Id,
    },
    /// Names one artifact in the installed implementation.
    Artifact {
        /// Names the actual measured artifact.
        artifact: Id,
    },
    /// Names a node binding reference directly in the world.
    WorldNodeBindingRef {
        /// Names the actual selected node.
        node: Id,
    },
    /// Names a node binding reference inside a specific owner.
    OwnerNodeBindingRef {
        /// Names the authoritative execution or capture owner.
        owner: Id,
        /// Names the actual participant node.
        node: Id,
    },
    /// Names an execution or capture owner.
    Owner {
        /// Names the exact owner.
        owner: Id,
    },
    /// Names one public connection.
    Connection {
        /// Names the exact connection.
        connection: Id,
    },
    /// Names the payload schema of one public connection.
    ConnectionSchema {
        /// Names the containing connection.
        connection: Id,
        /// Names the exact payload schema.
        schema: Id,
    },
}

impl ExtensionApplicationScope {
    /// Borrows the complete immutable world identity.
    pub fn world_hash(&self) -> &HashRef {
        &self.world_hash
    }

    /// Returns the exact containing record location.
    pub fn record_kind(&self) -> ExtensionRecordKind {
        self.record_kind
    }

    /// Borrows the complete containing record identity, including all parameters.
    pub fn record_hash(&self) -> &HashRef {
        &self.record_hash
    }

    /// Borrows the logical node, when the record belongs to one node.
    pub fn node(&self) -> Option<&Id> {
        self.node.as_ref()
    }

    /// Borrows the selected durable node contract when the record is node scoped.
    pub fn binding_hash(&self) -> Option<&HashRef> {
        self.binding_hash.as_ref()
    }

    /// Borrows the exact typed position of the record within this graph.
    pub fn record_path(&self) -> &ExtensionRecordPath {
        &self.record_path
    }

    /// Computes the exact domain-separated application identity.
    ///
    /// # Errors
    /// Refuses a failure to canonically encode the already bounded scope.
    pub fn identity(&self) -> Result<HashRef, crucible_node_contract::ContractError> {
        canonical::json_hash("cnp.extension-application.v1", self)
    }
}

/// Borrows actual selected graph records for installed semantic qualification.
pub struct ExtensionApplication<'a> {
    pub(super) scope: ExtensionApplicationScope,
    pub(super) graph: &'a AdmissionRequest<'a>,
}

pub(in crate::node_admission) struct RecordPlacement<'a> {
    pub kind: ExtensionRecordKind,
    pub node: Option<&'a Id>,
    pub path: ExtensionRecordPath,
}

impl<'a> RecordPlacement<'a> {
    pub(in crate::node_admission) fn node(kind: ExtensionRecordKind, node: &'a Id) -> Self {
        Self {
            kind,
            node: Some(node),
            path: ExtensionRecordPath::Node,
        }
    }
}

impl<'a> ExtensionApplication<'a> {
    /// Borrows the immutable exact record application scope.
    pub fn scope(&self) -> &ExtensionApplicationScope {
        &self.scope
    }

    /// Borrows the complete authored world without conferring activation authority.
    pub fn world(&self) -> &WorldBinding {
        self.graph.world
    }

    /// Borrows every actual resolved descriptor for whole-world interpretation.
    pub fn descriptors(&self) -> &[NodeDescriptor] {
        self.graph.descriptors
    }

    /// Borrows every selected node contract without conferring live custody.
    pub fn bindings(&self) -> &[NodeBinding] {
        self.graph.bindings
    }

    /// Borrows the complete actual execution and capture ownership selections.
    pub fn owners(&self) -> &[crucible_node_contract::OwnerBinding] {
        self.graph.owners
    }

    /// Borrows the exact scenario guarantees and explicitly accepted restrictions.
    pub fn requirements(&self) -> &crate::node_admission::ScenarioRequirements {
        self.graph.requirements
    }

    /// Borrows the actual node descriptor when this application is node scoped.
    pub fn node(&self) -> Option<&NodeDescriptor> {
        let node = self.scope.node()?;
        self.graph
            .descriptors
            .iter()
            .find(|descriptor| &descriptor.id == node)
    }

    /// Borrows the actual selected node binding when this application is node scoped.
    pub fn binding(&self) -> Option<&NodeBinding> {
        let node = self.scope.node()?;
        self.graph
            .bindings
            .iter()
            .find(|binding| &binding.compatibility.node_id == node)
    }

    /// Returns the actual selected mode independently of registered role names.
    pub fn mode(&self) -> Option<OperatingMode> {
        self.binding()
            .map(|binding| binding.compatibility.operating_contract.mode)
    }

    pub(super) fn subject(&self) -> AdmissionSubject {
        if let Some(node) = &self.scope.node {
            return AdmissionSubject::Node(node.clone());
        }
        match &self.scope.record_path {
            ExtensionRecordPath::Owner { owner } => AdmissionSubject::Owner(owner.clone()),
            ExtensionRecordPath::Connection { connection }
            | ExtensionRecordPath::ConnectionSchema { connection, .. } => {
                AdmissionSubject::Connection(connection.clone())
            }
            _ => AdmissionSubject::World,
        }
    }

    pub(super) fn for_record(
        graph: &'a AdmissionRequest<'a>,
        world_hash: &HashRef,
        record: &(impl Serialize + ?Sized),
        extensions: &crucible_node_contract::Extensions,
        placement: RecordPlacement<'_>,
        limits: AdmissionLimits,
    ) -> Result<Self, AdmissionError> {
        validate_placement(graph, &placement)?;
        super::selected::check_shapes(extensions)?;
        bounded_core(&record, limits.maximum_core_object_bytes)?;
        let record_hash = canonical::json_hash("cnp.extension-application-record.v1", &record)
            .map_err(crate::node_admission::nodes::schema_error)?;
        let binding_hash = placement
            .node
            .map(|node| {
                graph
                    .bindings
                    .iter()
                    .find(|binding| &binding.compatibility.node_id == node)
                    .ok_or_else(|| {
                        crate::node_admission::error::refuse(
                            crate::node_admission::AdmissionStage::Authenticate,
                            AdmissionSubject::Node(node.clone()),
                            crate::node_admission::AdmissionCode::IdentityMismatch,
                            "extension scope belongs to an actual selected node",
                            "extension application names an undeclared node",
                        )
                    })?
                    .compatibility
                    .identity()
                    .map_err(crate::node_admission::nodes::schema_error)
            })
            .transpose()?;
        Ok(Self {
            scope: ExtensionApplicationScope {
                world_hash: world_hash.clone(),
                record_kind: placement.kind,
                record_hash,
                node: placement.node.cloned(),
                binding_hash,
                record_path: placement.path,
            },
            graph,
        })
    }
}

fn validate_placement(
    graph: &AdmissionRequest<'_>,
    placement: &RecordPlacement<'_>,
) -> Result<(), AdmissionError> {
    use ExtensionRecordKind as Kind;
    use ExtensionRecordPath as Path;

    let descriptor = placement.node.and_then(|node| {
        graph
            .descriptors
            .iter()
            .find(|descriptor| &descriptor.id == node)
    });
    let binding = placement.node.and_then(|node| {
        graph
            .bindings
            .iter()
            .find(|binding| &binding.compatibility.node_id == node)
    });
    let node_present = descriptor.is_some() && binding.is_some();
    let valid = match (placement.kind, &placement.path) {
        (Kind::WorldBinding, Path::World) => placement.node.is_none(),
        (Kind::OwnerBinding, Path::Owner { owner }) => {
            placement.node.is_none() && graph.owners.iter().any(|actual| &actual.owner.id == owner)
        }
        (Kind::ConnectionDescriptor, Path::Connection { connection }) => {
            placement.node.is_none()
                && graph
                    .world
                    .connections
                    .iter()
                    .any(|actual| &actual.id == connection)
        }
        (Kind::SchemaRef, Path::ConnectionSchema { connection, schema }) => {
            placement.node.is_none()
                && graph
                    .world
                    .connections
                    .iter()
                    .any(|actual| &actual.id == connection && &actual.payload_schema.id == schema)
        }
        (Kind::NodeBindingRef, Path::WorldNodeBindingRef { node }) => {
            node_present
                && placement.node == Some(node)
                && graph
                    .world
                    .node_bindings
                    .iter()
                    .any(|actual| &actual.node_id == node)
        }
        (Kind::NodeBindingRef, Path::OwnerNodeBindingRef { owner, node }) => {
            node_present
                && placement.node == Some(node)
                && graph.owners.iter().any(|actual| {
                    &actual.owner.id == owner
                        && actual
                            .node_bindings
                            .iter()
                            .any(|binding| &binding.node_id == node)
                })
        }
        (Kind::PortDescriptor, Path::Port { port }) => {
            descriptor.is_some_and(|actual| actual.ports.iter().any(|actual| &actual.id == port))
                && binding.is_some()
        }
        (Kind::LaneDescriptor, Path::Lane { port, lane }) => {
            descriptor.is_some_and(|actual| {
                actual.ports.iter().any(|actual| {
                    &actual.id == port && actual.lanes.iter().any(|actual| &actual.id == lane)
                })
            }) && binding.is_some()
        }
        (Kind::SchemaRef, Path::LaneSchema { port, lane, schema }) => {
            descriptor.is_some_and(|actual| {
                actual.ports.iter().any(|actual| {
                    &actual.id == port
                        && actual
                            .lanes
                            .iter()
                            .any(|actual| &actual.id == lane && &actual.payload_schema.id == schema)
                })
            }) && binding.is_some()
        }
        (Kind::SchemaRef, Path::ImplementationSchema { schema, version }) => {
            node_present
                && binding.is_some_and(|actual| {
                    actual
                        .compatibility
                        .implementation
                        .formats
                        .iter()
                        .any(|actual| &actual.id == schema && actual.version == *version)
                })
        }
        (Kind::ArtifactIdentity, Path::Artifact { artifact }) => {
            node_present
                && binding.is_some_and(|actual| {
                    actual
                        .compatibility
                        .implementation
                        .artifacts
                        .iter()
                        .any(|actual| &actual.id == artifact)
                })
        }
        (Kind::FacetSelection, Path::SelectedFacet { facet }) => {
            node_present
                && binding.is_some_and(|actual| {
                    actual
                        .compatibility
                        .operating_contract
                        .facets
                        .iter()
                        .any(|actual| &actual.id == facet)
                })
        }
        // Advertised facets belong to the separately verified capability blob.
        // Its private admission caller supplies the actual bounded record.
        (Kind::FacetSelection, Path::AdvertisedFacet { .. }) => node_present,
        (
            Kind::NodeDescriptor
            | Kind::OperatingContract
            | Kind::CapabilityProfile
            | Kind::GuaranteeProfile
            | Kind::ImplementationIdentity
            | Kind::BindingCompatibility
            | Kind::NodeBinding
            | Kind::LiveAuthority,
            Path::Node,
        ) => node_present,
        _ => false,
    };
    if !valid {
        return Err(crate::node_admission::error::refuse(
            crate::node_admission::AdmissionStage::Authenticate,
            placement.node.map_or(AdmissionSubject::World, |node| {
                AdmissionSubject::Node(node.clone())
            }),
            crate::node_admission::AdmissionCode::IdentityMismatch,
            "typed extension scope names an actual containing graph record",
            "record kind, path, or actual node/owner/endpoint differs",
        ));
    }
    Ok(())
}
