//! Borrows every initialized field of the actual reconstructed import owner.

use super::*;
use crate::protocol_snapshot::restored_settled17::current_import17::{
    BorrowedImport17, import_fields17,
};

import_fields17!(HistoricalNativeInstallation => HistoricalNativeInstallationCurrent17, "source-private.current-import-historical-native-installation/17", {
    session: Id,
    incarnation: Id,
    implementation: ImplementationIdentity,
    launch_receipt: ContentRef,
    admission_token: [u8; 32],
});

import_fields17!(HistoricalNativeNegotiationPolicy => HistoricalNativeNegotiationPolicyCurrent17, "source-private.current-import-historical-native-negotiation-policy/17", {
    supported_features: IdSet,
    required_features: IdSet,
    provider_limits: Limits,
    required_schemas: Vec<SchemaRef>,
    required_guarantees: ContentRef,
    envelope_extension_features: BTreeMap<String, Id>,
});

import_fields17!(HistoricalNativeNegotiation => HistoricalNativeNegotiationCurrent17, "source-private.current-import-historical-native-negotiation/17", {
    installation: HistoricalNativeInstallation,
    policy: HistoricalNativeNegotiationPolicy,
    epoch: U64,
    current_connection: Option<Id>,
    selected_features: Option<IdSet>,
    resume_token: Option<[u8; 32]>,
    contained: bool,
    hello_request_ids: BTreeSet<Id>,
    shared_epoch: U64,
    registration_gate_poisoned: bool,
});

import_fields17!(HistoricalNativeExtensionNegotiation => HistoricalNativeExtensionNegotiationCurrent17, "source-private.current-import-historical-native-extension-negotiation/17", {
    negotiation: HistoricalNativeNegotiation,
    installed_registry_group: usize,
    selected: Arc<[ExtensionSelection]>,
});

/// Names each concrete source, borrowed header and inert output layout.
pub(crate) fn counter_scratch_data() -> usize {
    std::mem::size_of::<HistoricalNativeInstallation>()
        + std::mem::size_of::<HistoricalNativeInstallationCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeInstallation>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeInstallationCurrent17>, crate::ProviderError>,
        >()
        + std::mem::size_of::<HistoricalNativeNegotiationPolicy>()
        + std::mem::size_of::<HistoricalNativeNegotiationPolicyCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeNegotiationPolicy>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeNegotiationPolicyCurrent17>, crate::ProviderError>,
        >()
        + std::mem::size_of::<HistoricalNativeNegotiation>()
        + std::mem::size_of::<HistoricalNativeNegotiationCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeNegotiation>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeNegotiationCurrent17>, crate::ProviderError>,
        >()
        + std::mem::size_of::<HistoricalNativeExtensionNegotiation>()
        + std::mem::size_of::<HistoricalNativeExtensionNegotiationCurrent17>()
        + std::mem::size_of::<BorrowedImport17<'static, HistoricalNativeExtensionNegotiation>>()
        + std::mem::size_of::<
            Result<Option<HistoricalNativeExtensionNegotiationCurrent17>, crate::ProviderError>,
        >()
}
