//! Shared constructors for native resource interface contracts.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use anyhow::Result;

use crate::{
    ArtifactReference, ImplementationKind, IndeterminateSemantics, InterfaceDescriptor,
    InterfaceDocument, InterfaceKey, InterfaceName, LifecycleSemantics, LocalKey, MethodDescriptor,
    OperationFamily, OutcomeSemantics, OutputDescriptor, ProviderImplementation, ValueSchema,
    VersionedDocument,
};

pub(super) const REVISION_MAX_BYTES: u64 = 71;
pub(super) const RESOURCE_PATH_MAX_BYTES: u64 = 4_096;

pub(super) fn revisioned_observation_schema<const N: usize>(
    discriminator: &str,
    fields: [(LocalKey, ValueSchema); N],
) -> Result<ValueSchema> {
    let mut fields = BTreeMap::from(fields);
    fields.insert(
        LocalKey::new("observed_revision")?,
        ValueSchema::Optional {
            value: Box::new(bounded_string(REVISION_MAX_BYTES)),
        },
    );
    fields.insert(
        LocalKey::new("requested_revision")?,
        bounded_string(REVISION_MAX_BYTES),
    );
    fields.insert(
        LocalKey::new("schema")?,
        ValueSchema::StringEnum {
            values: vec![discriminator.to_string()],
        },
    );

    Ok(ValueSchema::Record {
        fields,
        optional_fields: Vec::new(),
    })
}

pub(crate) fn resource_method(
    interface: &InterfaceName,
    name: &str,
    operation_family: OperationFamily,
    parameters: ValueSchema,
    evidence: ValueSchema,
    outputs: BTreeMap<LocalKey, OutputDescriptor>,
) -> Result<(LocalKey, MethodDescriptor)> {
    let method = LocalKey::new(name)?;
    Ok((
        method.clone(),
        MethodDescriptor {
            operation_family,
            parameters,
            target_resource: interface.clone(),
            outputs,
            permitted_operations: vec![method],
            guarantees: Vec::new(),
            outcome: OutcomeSemantics {
                completion_evidence: evidence.clone(),
                observation_evidence: evidence,
                supports_rejected_before_effect: true,
                indeterminate: IndeterminateSemantics::Reconcile,
            },
        },
    ))
}

pub(crate) fn interface_document(
    name: InterfaceName,
    request: ValueSchema,
    methods: BTreeMap<LocalKey, MethodDescriptor>,
    lifecycle: LifecycleSemantics,
) -> Result<InterfaceDocument> {
    Ok(InterfaceDocument {
        schema: InterfaceDocument::SCHEMA.to_string(),
        required_features: Vec::new(),
        interface: InterfaceDescriptor {
            name,
            abi: NonZeroU32::new(1).ok_or_else(|| anyhow::anyhow!("invalid built-in ABI"))?,
            request,
            configuration: None,
            outputs: BTreeMap::new(),
            methods,
            lifecycle,
            guarantees: Vec::new(),
        },
    })
}

pub(crate) fn terminal_provider(
    interface: InterfaceKey,
    handler: LocalKey,
    artifact: ArtifactReference,
) -> Result<ProviderImplementation> {
    Ok(ProviderImplementation {
        owns_resource_kinds: vec![interface.name.clone()],
        state_format: None,
        interface,
        artifact,
        requirements: Vec::new(),
        implementation: ImplementationKind::TerminalHandler { handler },
    })
}

pub(crate) const fn bounded_string(max_length: u64) -> ValueSchema {
    ValueSchema::String {
        max_length,
        syntax: None,
    }
}
