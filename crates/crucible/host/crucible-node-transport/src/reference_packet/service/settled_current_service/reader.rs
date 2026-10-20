//! Retains the concrete selected service17 leaf and all of its checked roots.

use super::registrar::{
    HistoricalNativeRegistrar17, NativeRegistrar17GroupIds,
    read_current_native17_registrar_root_data,
};
use crate::ProviderError;
use crate::handshake::HistoricalAuthority17;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string,
};
use crate::reference_packet::service::{
    Native5Policy,
    ack_emitter::{
        CurrentBootstrap17GroupIds, HistoricalCurrentBootstrap17, NativeAckBoot,
        read_current_native17_bootstrap_fields_data,
    },
};
use crate::retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind};
use std::{
    cell::{Cell, RefCell},
    mem::{align_of, size_of},
};

/// Identifies independently defined source roots in validation and build passes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CurrentNativeService17GroupIds {
    pub(crate) supervisor: usize,
    pub(crate) boot: usize,
    pub(crate) policy: usize,
    pub(crate) deadline: usize,
    pub(crate) registrar: NativeRegistrar17GroupIds,
    pub(crate) bootstrap: CurrentBootstrap17GroupIds,
}

/// Retains the full original registrar/bootstrap without registering a service.
pub(crate) struct HistoricalCurrentNativeService17 {
    pub(crate) negotiation: HistoricalNativeRegistrar17,
    pub(crate) bootstrap: HistoricalCurrentBootstrap17,
    pub(crate) supervisor: Option<crate::reference_packet::service::HistoricalNativeSupervisor17>,
    groups: CurrentNativeService17GroupIds,
}

impl HistoricalCurrentNativeService17 {
    /// Returns all independently validated historical source groups.
    pub(crate) const fn group_ids_data(&self) -> CurrentNativeService17GroupIds {
        self.groups
    }

    /// Joins full registrar/bootstrap history after the final owner is retained.
    ///
    /// # Errors
    /// Refuses another authority or Bootstrap/Boot association, changed private
    /// raw/DOM history, or incomplete source bootstrap. This creates no issuer.
    pub(crate) fn authenticate_correspondence_data(
        &self,
        authority: &HistoricalAuthority17,
    ) -> Result<(), ProviderError> {
        if self.groups.bootstrap.boot != self.groups.boot {
            return Err(invalid());
        }
        self.negotiation.authenticate_authority_data(authority)?;
        self.bootstrap.authenticate_correspondence_data()
    }
}

impl HistoricalType for HistoricalCurrentNativeService17 {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_current_native17_service_fields_data(input, ledger, build).map(|result| result.0)
    }
}

/// Reads all emitted service fields and binds each role to a complete root.
///
/// # Errors
/// Refuses another schema, unknown/reordered fields, incomplete registrar or
/// bootstrap leaves, mismatched roles/groups or exact shared-layout disagreement.
pub(crate) fn read_current_native17_service_fields_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<HistoricalCurrentNativeService17>,
        CurrentNativeService17GroupIds,
    ),
    ProviderError,
> {
    read_service_fields(input, None, ledger, build)
}

/// Reads the rooted service using component spans sealed by the whole grammar.
///
/// # Errors
/// Refuses wrong closed roles or any malformed full registrar/bootstrap view.
pub(crate) fn read_rooted_current_native17_service_fields_data(
    roots: &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<HistoricalCurrentNativeService17>,
        CurrentNativeService17GroupIds,
    ),
    ProviderError,
> {
    read_service_fields(roots.service_data(), Some(roots), ledger, build)
}

fn read_service_fields(
    input: &[u8],
    roots: Option<
        &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    >,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<HistoricalCurrentNativeService17>,
        CurrentNativeService17GroupIds,
    ),
    ProviderError,
> {
    let mut fields = Fields::object(input)?;
    exact(
        fields.named("schema")?,
        if roots.is_some() {
            "source-private.native-rooted-service/17"
        } else {
            "source-private.native-current-service/17"
        },
    )?;
    let emitted_negotiation = fields.named("negotiation")?;
    let raw_negotiation = if let Some(roots) = roots {
        exact(emitted_negotiation, "native-registrar")?;
        roots.registrar_data()
    } else {
        emitted_negotiation
    };
    let (negotiation, registrar) =
        read_current_native17_registrar_root_data(raw_negotiation, ledger, build)?;
    let (bootstrap, bootstrap_groups) =
        read_current_native17_bootstrap_fields_data(fields.named("bootstrap")?, ledger, build)?;
    let emitted_supervisor = fields.named("supervisor")?;
    let (supervisor_data, supervisor) = if roots.is_some() {
        exact(emitted_supervisor, "native-supervisor")?;
        let layout = crate::reference_packet::service::original_native_supervisor_layout();
        if ledger.row_aligned(
            MetadataRecordKind::Shared,
            1,
            crate::reference_packet::service::original_native_supervisor_alignment17_data(),
        )? != layout
        {
            return Err(invalid());
        }
        (
            None,
            ledger.shared_reference(MetadataSharedKind::NativeSupervisor, layout)?,
        )
    } else {
        crate::reference_packet::service::read_current_native17_supervisor_root_data(
            emitted_supervisor,
            ledger,
            build,
        )?
    };
    exact(fields.named("boot_role")?, "native-boot")?;
    let boot = reference::<RefCell<NativeAckBoot>>(ledger, MetadataSharedKind::NativeBoot)?;
    exact(fields.named("policy_role")?, "native-policy")?;
    let policy = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
    exact(
        fields.named("cut_role")?,
        "historical-operational-cut-no-renewal",
    )?;
    let deadline = reference::<Cell<crate::operational_time::OperationalDeadline>>(
        ledger,
        MetadataSharedKind::OperationalDeadline,
    )?;
    fields.finish()?;
    if bootstrap_groups.boot != boot {
        return Err(invalid());
    }
    let groups = CurrentNativeService17GroupIds {
        supervisor,
        boot,
        policy,
        deadline,
        registrar,
        bootstrap: bootstrap_groups,
    };
    if !build {
        return Ok((None, groups));
    }
    Ok((
        Some(HistoricalCurrentNativeService17 {
            negotiation: negotiation.ok_or_else(invalid)?,
            bootstrap: bootstrap.ok_or_else(invalid)?,
            supervisor: supervisor_data,
            groups,
        }),
        groups,
    ))
}

fn reference<T>(
    ledger: &mut Ledger<'_, '_, '_>,
    kind: MetadataSharedKind,
) -> Result<usize, ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<T>())? != size_of::<T>() {
        return Err(invalid());
    }
    ledger.shared_reference(kind, size_of::<T>())
}

fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}
