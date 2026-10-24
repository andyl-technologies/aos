//! Joins the full stable registrar DATA leaf to explicit17 authority groups.

use crate::ProviderError;
use crate::handshake::{HistoricalAuthority17, Limits};
use crate::protocol_snapshot::owned11::native::registrar::{
    HistoricalNativeExtensionNegotiation, HistoricalNativeInstallation,
    HistoricalNativeNegotiation, HistoricalNativeNegotiationPolicy,
};
use crate::protocol_snapshot::owned11::state::{next, selected_extensions, tag};
use crate::protocol_snapshot::owned11::typed::{Fields, Ledger, invalid, plain_string};
use crate::retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind};
use crucible_node_format::{ContentRef, Id, IdSet, ImplementationIdentity, SchemaRef, U64};
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{align_of, size_of},
};

/// Identifies actual registrar epoch, gate and concrete empty-registry backing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeRegistrar17GroupIds {
    pub(crate) epoch: usize,
    pub(crate) gate: usize,
    pub(crate) registry: usize,
}

/// Retains every registrar field without installing an issuer or gate.
pub(crate) struct HistoricalNativeRegistrar17 {
    pub(crate) data: HistoricalNativeExtensionNegotiation,
    pub(crate) groups: NativeRegistrar17GroupIds,
}

impl HistoricalNativeRegistrar17 {
    /// Binds complete retained registration history to an independent authority.
    ///
    /// # Errors
    /// Refuses another registration or changed installation/selection history.
    pub(crate) fn authenticate_authority_data(
        &self,
        authority: &HistoricalAuthority17,
    ) -> Result<(), ProviderError> {
        let data = &self.data.negotiation;
        if (self.groups.epoch, self.groups.gate) != authority.group_ids_data()
            || data.installation.session != authority.data.session
            || data.installation.incarnation != authority.data.incarnation
            || data.current_connection.as_ref() != Some(&authority.data.connection)
            || data.epoch != authority.data.epoch
            || data.selected_features.as_ref() != Some(&authority.data.features)
            || authority
                .data
                .extensions
                .as_ref()
                .is_none_or(|selected| selected.as_ref() != self.data.selected.as_ref())
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Reads the complete actual registrar leaf on the enclosing native17 ledger.
///
/// # Errors
/// Refuses omitted/reordered fields, invalid secrets, exact row disagreement or
/// registrar/selection alias inconsistency. It cannot enroll a live connection.
pub(crate) fn read_current_native17_registrar_root_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<HistoricalNativeRegistrar17>,
        NativeRegistrar17GroupIds,
    ),
    ProviderError,
> {
    let mut outer = Fields::array(input)?;
    tag(
        &mut outer,
        "source-private.original-extension-negotiation/11",
    )?;
    let mut fields = Fields::object(next(&mut outer)?)?;
    if plain_string(fields.named("schema")?)? != "source-private.original-negotiation/5" {
        return Err(invalid());
    }
    let mut installation = Fields::array(fields.named("installation")?)?;
    let session = ledger.read::<Id>(next(&mut installation)?, build)?;
    let incarnation = ledger.read::<Id>(next(&mut installation)?, build)?;
    let implementation = ledger.read::<ImplementationIdentity>(next(&mut installation)?, build)?;
    let launch_receipt = ledger.read::<ContentRef>(next(&mut installation)?, build)?;
    let admission_token = secret(next(&mut installation)?, ledger)?;
    installation.finish()?;

    let mut policy = Fields::array(fields.named("policy")?)?;
    let supported_features = ledger.read::<IdSet>(next(&mut policy)?, build)?;
    let required_features = ledger.read::<IdSet>(next(&mut policy)?, build)?;
    let provider_limits = ledger.read::<Limits>(next(&mut policy)?, build)?;
    let required_schemas = ledger.read::<Vec<SchemaRef>>(next(&mut policy)?, build)?;
    let required_guarantees = ledger.read::<ContentRef>(next(&mut policy)?, build)?;
    let envelope_extension_features =
        ledger.read::<BTreeMap<String, Id>>(next(&mut policy)?, build)?;
    policy.finish()?;
    let epoch = ledger.read::<U64>(fields.named("epoch")?, build)?;
    let current_connection =
        ledger.read::<Option<Id>>(fields.named("current_connection")?, build)?;
    let selected_features =
        ledger.read::<Option<IdSet>>(fields.named("selected_features")?, build)?;
    let resume = fields.named("resume_token")?;
    let resume_token = if resume == b"null" {
        None
    } else {
        Some(secret(resume, ledger)?)
    };
    let contained = ledger.read::<bool>(fields.named("contained")?, build)?;
    let hello_request_ids =
        ledger.read::<BTreeSet<Id>>(fields.named("hello_request_ids")?, build)?;
    let epoch_raw = fields.named("shared_epoch")?;
    let shared_epoch = ledger.read::<U64>(epoch_raw, build)?;
    let gate_raw = fields.named("registration_gate_poisoned")?;
    let registration_gate_poisoned = ledger.read::<bool>(gate_raw, build)?;
    fields.finish()?;

    if ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<std::sync::atomic::AtomicU64>(),
    )? != size_of::<std::sync::atomic::AtomicU64>()
        || ledger.row_aligned(
            MetadataRecordKind::Shared,
            1,
            align_of::<std::sync::Mutex<()>>(),
        )? != size_of::<std::sync::Mutex<()>>()
    {
        return Err(invalid());
    }
    // Authority17 emits a JSON number; the unchanged registrar emits U64 text.
    // Their identical decimal token binds the same actual Atomic allocation.
    let epoch_view = plain_string(epoch_raw)?.as_bytes();
    crate::protocol_snapshot::owned11::typed::unsigned(epoch_view)?;
    let epoch_group = ledger.shared(
        MetadataSharedKind::RegistrarEpoch,
        size_of::<std::sync::atomic::AtomicU64>(),
        epoch_view,
        b"",
    )?;
    let gate_group = ledger.shared(
        MetadataSharedKind::RegistrarGate,
        size_of::<std::sync::Mutex<()>>(),
        gate_raw,
        b"",
    )?;
    let mut registry = None;
    for _ in 0..2 {
        let marker = next(&mut outer)?;
        if plain_string(marker)? != "source-private.native-empty-extension-registry/11"
            || ledger.row_aligned(MetadataRecordKind::Shared, 1, 1)? != 0
        {
            return Err(invalid());
        }
        let group = ledger.shared(MetadataSharedKind::InstalledRegistry, 0, marker, b"")?;
        if registry.is_some_and(|prior| prior != group) {
            return Err(invalid());
        }
        registry = Some(group);
    }
    let selected_raw = next(&mut outer)?;
    if selected_raw == b"null" {
        return Err(invalid());
    }
    // The stable selection leaf owns its own complete row/alias validation and
    // builds from the same caller-owned cache only after full child validation.
    let before_selected = ledger.rows.clone();
    ledger.row_aligned(
        MetadataRecordKind::Shared,
        1,
        align_of::<crucible_node_format::ExtensionSelection>(),
    )?;
    ledger.rows = before_selected;
    let selected = selected_extensions(selected_raw, ledger, build)?;
    outer.finish()?;
    let groups = NativeRegistrar17GroupIds {
        epoch: epoch_group,
        gate: gate_group,
        registry: registry.ok_or_else(invalid)?,
    };
    if !build {
        return Ok((None, groups));
    }
    Ok((
        Some(HistoricalNativeRegistrar17 {
            data: HistoricalNativeExtensionNegotiation {
                negotiation: HistoricalNativeNegotiation {
                    installation: HistoricalNativeInstallation {
                        session: session.ok_or_else(invalid)?,
                        incarnation: incarnation.ok_or_else(invalid)?,
                        implementation: implementation.ok_or_else(invalid)?,
                        launch_receipt: launch_receipt.ok_or_else(invalid)?,
                        admission_token,
                    },
                    policy: HistoricalNativeNegotiationPolicy {
                        supported_features: supported_features.ok_or_else(invalid)?,
                        required_features: required_features.ok_or_else(invalid)?,
                        provider_limits: provider_limits.ok_or_else(invalid)?,
                        required_schemas: required_schemas.ok_or_else(invalid)?,
                        required_guarantees: required_guarantees.ok_or_else(invalid)?,
                        envelope_extension_features: envelope_extension_features
                            .ok_or_else(invalid)?,
                    },
                    epoch: epoch.ok_or_else(invalid)?,
                    current_connection: current_connection.ok_or_else(invalid)?,
                    selected_features: selected_features.ok_or_else(invalid)?,
                    resume_token,
                    contained: contained.ok_or_else(invalid)?,
                    hello_request_ids: hello_request_ids.ok_or_else(invalid)?,
                    shared_epoch: shared_epoch.ok_or_else(invalid)?,
                    registration_gate_poisoned: registration_gate_poisoned.ok_or_else(invalid)?,
                },
                installed_registry_group: groups.registry,
                selected: selected.ok_or_else(invalid)?.ok_or_else(invalid)?,
            },
            groups,
        }),
        groups,
    ))
}

fn secret(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<[u8; 32], ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut result = [0; 32];
    for byte in &mut result {
        *byte = ledger
            .read::<u8>(next(&mut fields)?, true)?
            .ok_or_else(invalid)?;
    }
    fields.finish()?;
    Ok(result)
}
