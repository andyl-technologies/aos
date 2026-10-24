//! Borrows registrar and closed bootstrap lineage from the one native17 plan.

use crate::ProviderError;
use crate::connection::{BorrowedAuthority17Lineage, native17_borrowed_bytes::*};
use crate::protocol_snapshot::{
    native_wholegraph17::BorrowedNativeCurrentGraph17Plan,
    owned11::typed::{Fields, invalid},
};
use crate::reference_packet::service::ack_emitter::{
    BorrowedBootstrap17LineageData, borrow_current_bootstrap17_lineage_data,
};

/// Retains exact negotiation/once facts as borrowed immutable evidence.
pub(crate) struct BorrowedCurrentNativeService17LineageData<'a> {
    pub(crate) installation: &'a [u8],
    pub(crate) policy: &'a [u8],
    pub(crate) current_connection: &'a [u8],
    pub(crate) selected_features: &'a [u8],
    pub(crate) selected_extensions: &'a [u8],
    pub(crate) hello_request_ids: &'a [u8],
    pub(crate) admission_token: &'a [u8],
    pub(crate) resume_token: &'a [u8],
    pub(crate) saved_epoch: u64,
    pub(crate) observed_epoch: u64,
    pub(crate) contained: bool,
    pub(crate) registration_gate_poisoned: bool,
    pub(crate) bootstrap: BorrowedBootstrap17LineageData<'a>,
}

/// Checks complete registrar/authority and immutable bootstrap correspondence.
///
/// # Errors
/// Refuses another saved/observed registration, changed selection, incomplete
/// bootstrap evidence or different independently validated source root groups.
pub(crate) fn borrow_current_native17_service_lineage_data<'a>(
    plan: &BorrowedNativeCurrentGraph17Plan<'a, '_>,
) -> Result<BorrowedCurrentNativeService17LineageData<'a>, ProviderError> {
    let roots = plan.root_spans_data();
    let authority = BorrowedAuthority17Lineage::read(field(roots.connection_data(), "authority")?)?;
    authority.require_live_history()?;
    authority.authenticate_registrar(roots.registrar_data())?;
    let mut registrar = Fields::array(roots.registrar_data())?;
    next(&mut registrar)?;
    let registration = next(&mut registrar)?;
    let installation = field(registration, "installation")?;
    let policy = field(registration, "policy")?;
    let current_connection = field(registration, "current_connection")?;
    let selected_features = field(registration, "selected_features")?;
    let hello_request_ids = field(registration, "hello_request_ids")?;
    let admission_token = item(installation, 4)?;
    let resume_token = field(registration, "resume_token")?;
    let saved_epoch = quoted(field(registration, "epoch")?)?;
    let observed_epoch = quoted(field(registration, "shared_epoch")?)?;
    let contained = boolean(field(registration, "contained")?)?;
    let registration_gate_poisoned = boolean(field(registration, "registration_gate_poisoned")?)?;
    if contained {
        return Err(invalid());
    }
    next(&mut registrar)?;
    next(&mut registrar)?;
    let selected_extensions = next(&mut registrar)?;
    registrar.finish()?;
    let bootstrap =
        borrow_current_bootstrap17_lineage_data(field(roots.service_data(), "bootstrap")?)?;
    let groups = plan.service_groups_data();
    if groups.boot != plan.boot_group_data()
        || groups.policy != plan.policy_group_data()
        || groups.registrar != plan.registrar_groups_data()
        || groups.bootstrap.boot != groups.boot
        || groups.supervisor != plan.connection_groups_data().supervisor
        || groups.deadline != plan.connection_groups_data().deadline
    {
        return Err(invalid());
    }
    Ok(BorrowedCurrentNativeService17LineageData {
        installation,
        policy,
        current_connection,
        selected_features,
        selected_extensions,
        hello_request_ids,
        admission_token,
        resume_token,
        saved_epoch,
        observed_epoch,
        contained,
        registration_gate_poisoned,
        bootstrap,
    })
}
