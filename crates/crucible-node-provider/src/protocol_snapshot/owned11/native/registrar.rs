//! Restores original registrar data without reconstructing its authority gate.

use super::super::{
    state::{next, selected_extensions, tag},
    typed::{Fields, HistoricalType, Ledger, invalid, plain_string},
};
use crate::{
    ProviderError,
    handshake::Limits,
    retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind},
};
use crucible_node_contract::{
    ContentRef, ExtensionSelection, Id, IdSet, ImplementationIdentity, SchemaRef, U64,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Retains private installation data without constructing a trusted registrar.
pub struct HistoricalNativeInstallation {
    /// Retains the original authorized session identity and capacity.
    pub session: Id,
    /// Retains the original process incarnation identity and capacity.
    pub incarnation: Id,
    /// Retains the complete measured implementation declaration.
    pub implementation: ImplementationIdentity,
    /// Retains the complete original private launch receipt.
    pub launch_receipt: ContentRef,
    /// Retains the original fixed inline secret without enrolling a fresh peer.
    pub admission_token: [u8; 32],
}

/// Retains all original installed negotiation policy fields as historical data.
pub struct HistoricalNativeNegotiationPolicy {
    /// Retains every supported feature and its original Vec/String capacities.
    pub supported_features: IdSet,
    /// Retains every originally required feature.
    pub required_features: IdSet,
    /// Retains the complete installed receiving limits.
    pub provider_limits: Limits,
    /// Retains every full required schema and original Vec capacity.
    pub required_schemas: Vec<SchemaRef>,
    /// Retains the complete required guarantees reference.
    pub required_guarantees: ContentRef,
    /// Retains exact extension-key to feature associations and key capacities.
    pub envelope_extension_features: BTreeMap<String, Id>,
}

/// Retains complete registrar history without a live epoch or gate constructor.
pub struct HistoricalNativeNegotiation {
    /// Retains the original installation and inline private secret.
    pub installation: HistoricalNativeInstallation,
    /// Retains the entire original negotiation policy.
    pub policy: HistoricalNativeNegotiationPolicy,
    /// Retains the original selected generation.
    pub epoch: U64,
    /// Retains the original current-connection field and its capacity.
    pub current_connection: Option<Id>,
    /// Retains the exact original negotiated features.
    pub selected_features: Option<IdSet>,
    /// Retains the complete fixed inline original resume secret when present.
    pub resume_token: Option<[u8; 32]>,
    /// Retains the sticky historical containment phase.
    pub contained: bool,
    /// Retains every original Hello request identity and key capacity.
    pub hello_request_ids: BTreeSet<Id>,
    /// Retains the original shared epoch value without creating an atomic issuer.
    pub shared_epoch: U64,
    /// Retains the original gate poison state without a synchronization authority.
    pub registration_gate_poisoned: bool,
}

/// Retains the selected typed registrar and exact shared extension slice.
pub struct HistoricalNativeExtensionNegotiation {
    /// Retains every underlying original registrar field.
    pub negotiation: HistoricalNativeNegotiation,
    /// Identifies the checked historical zero-field installed registry group.
    pub installed_registry_group: usize,
    /// Shares the same reconstructed selection as its corresponding authorities.
    pub selected: Arc<[ExtensionSelection]>,
}

fn fixed_secret(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<[u8; 32], ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut bytes = [0u8; 32];
    for byte in &mut bytes {
        *byte = ledger
            .read::<u8>(next(&mut fields)?, true)?
            .ok_or_else(invalid)?;
    }
    fields.finish()?;
    Ok(bytes)
}

impl HistoricalType for HistoricalNativeNegotiation {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        if plain_string(fields.named("schema")?)? != "source-private.original-negotiation/5" {
            return Err(invalid());
        }
        let mut installation = Fields::array(fields.named("installation")?)?;
        let session = ledger.read::<Id>(next(&mut installation)?, build)?;
        let incarnation = ledger.read::<Id>(next(&mut installation)?, build)?;
        let implementation =
            ledger.read::<ImplementationIdentity>(next(&mut installation)?, build)?;
        let launch_receipt = ledger.read::<ContentRef>(next(&mut installation)?, build)?;
        let admission_token = fixed_secret(next(&mut installation)?, ledger)?;
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
        let raw_resume = fields.named("resume_token")?;
        let resume_token = if raw_resume == b"null" {
            None
        } else {
            Some(fixed_secret(raw_resume, ledger)?)
        };
        let contained = ledger.read::<bool>(fields.named("contained")?, build)?;
        let hello_request_ids =
            ledger.read::<BTreeSet<Id>>(fields.named("hello_request_ids")?, build)?;
        let epoch_view = fields.named("shared_epoch")?;
        let shared_epoch = ledger.read::<U64>(epoch_view, build)?;
        let raw_poisoned = fields.named("registration_gate_poisoned")?;
        let registration_gate_poisoned = ledger.read::<bool>(raw_poisoned, build)?;
        fields.finish()?;

        let epoch_layout = std::mem::size_of::<std::sync::atomic::AtomicU64>();
        let gate_layout = std::mem::size_of::<std::sync::Mutex<()>>();
        if ledger.row(MetadataRecordKind::Shared, 1)? != epoch_layout
            || ledger.row(MetadataRecordKind::Shared, 1)? != gate_layout
        {
            return Err(invalid());
        }
        ledger.shared(
            MetadataSharedKind::RegistrarEpoch,
            epoch_layout,
            epoch_view,
            b"",
        )?;
        ledger.shared(
            MetadataSharedKind::RegistrarGate,
            gate_layout,
            b"historical-registration-gate",
            b"",
        )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
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
                envelope_extension_features: envelope_extension_features.ok_or_else(invalid)?,
            },
            epoch: epoch.ok_or_else(invalid)?,
            current_connection: current_connection.ok_or_else(invalid)?,
            selected_features: selected_features.ok_or_else(invalid)?,
            resume_token,
            contained: contained.ok_or_else(invalid)?,
            hello_request_ids: hello_request_ids.ok_or_else(invalid)?,
            shared_epoch: shared_epoch.ok_or_else(invalid)?,
            registration_gate_poisoned: registration_gate_poisoned.ok_or_else(invalid)?,
        }))
    }
}

impl HistoricalType for HistoricalNativeExtensionNegotiation {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::array(input)?;
        tag(
            &mut fields,
            "source-private.original-extension-negotiation/11",
        )?;
        let negotiation = ledger.read::<HistoricalNativeNegotiation>(next(&mut fields)?, build)?;
        let mut installed_registry_group = None;
        for _ in 0..2 {
            let marker = next(&mut fields)?;
            if plain_string(marker)? != "source-private.native-empty-extension-registry/11"
                || ledger.row(MetadataRecordKind::Shared, 1)? != 0
            {
                return Err(invalid());
            }
            let group = ledger.shared(MetadataSharedKind::InstalledRegistry, 0, marker, b"")?;
            if installed_registry_group.is_some_and(|previous| previous != group) {
                return Err(invalid());
            }
            installed_registry_group = Some(group);
        }
        let selected = next(&mut fields)?;
        if selected == b"null" {
            return Err(invalid());
        }
        let selected = selected_extensions(selected, ledger, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            negotiation: negotiation.ok_or_else(invalid)?,
            installed_registry_group: installed_registry_group.ok_or_else(invalid)?,
            selected: selected.ok_or_else(invalid)?.ok_or_else(invalid)?,
        }))
    }
}

// The closed owning walk fails to compile if a historical field is added.
super::super::retained_storage::fields!(
    HistoricalNativeInstallation,
    session,
    incarnation,
    implementation,
    launch_receipt,
    admission_token
);
super::super::retained_storage::fields!(
    HistoricalNativeNegotiationPolicy,
    supported_features,
    required_features,
    provider_limits,
    required_schemas,
    required_guarantees,
    envelope_extension_features
);
super::super::retained_storage::fields!(
    HistoricalNativeNegotiation,
    installation,
    policy,
    epoch,
    current_connection,
    selected_features,
    resume_token,
    contained,
    hello_request_ids,
    shared_epoch,
    registration_gate_poisoned
);
super::super::retained_storage::fields!(
    HistoricalNativeExtensionNegotiation,
    negotiation,
    installed_registry_group,
    selected
);

pub(crate) mod current17;

/// Names actual fixed local and returned headers of this handwritten reader.
///
/// Empty maps and `Option` payloads remain real controls when `build` is false;
/// no tree entries, backing allocations or owning reconstruction are included.
pub(super) fn borrowed_validation_headers_data() -> usize {
    use std::mem::size_of;

    fn header<T>() -> usize {
        size_of::<Option<T>>() + size_of::<Result<Option<T>, ProviderError>>()
    }

    fn field<T: super::super::typed::HistoricalType>() -> usize {
        header::<T>() + T::borrowed_header_counter_scratch_data()
    }

    field::<u8>()
        + field::<Id>()
        + field::<Id>()
        + field::<ImplementationIdentity>()
        + field::<ContentRef>()
        + field::<IdSet>()
        + field::<IdSet>()
        + field::<Limits>()
        + field::<Vec<SchemaRef>>()
        + field::<ContentRef>()
        + field::<BTreeMap<String, Id>>()
        + field::<U64>()
        + field::<Option<Id>>()
        + field::<Option<IdSet>>()
        + field::<bool>()
        + field::<BTreeSet<Id>>()
        + field::<U64>()
        + field::<bool>()
        + field::<HistoricalNativeNegotiation>()
        + header::<HistoricalNativeNegotiation>()
        + header::<HistoricalNativeExtensionNegotiation>()
        + header::<[u8; 32]>()
        + header::<[u8; 32]>()
        + header::<std::sync::Arc<[ExtensionSelection]>>()
        + header::<Option<std::sync::Arc<[ExtensionSelection]>>>()
        + header::<usize>()
        + size_of::<[u8; 32]>()
        + size_of::<Option<[u8; 32]>>()
        + size_of::<std::slice::IterMut<'static, u8>>()
        + size_of::<std::ops::Range<usize>>()
}
