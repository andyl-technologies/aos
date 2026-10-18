//! Borrows one genuine Endpoint/Service graph and records its complete roots.
//!
//! One recorder owns the complete native17 metadata/alias pass. Rooted child
//! serializers retain all actual source fields and substitute only closed role
//! literals for payloads defined by this enclosing grammar.

use super::*;
use crate::client::DeadlineStream;
use crate::connection::NativeConnectionPrelude17;
use crate::protocol_snapshot::native_wholegraph17::{
    CURRENT_GRAPH17_FORMAT, CURRENT_PROTOCOL17_FORMAT,
};
use crate::reference_packet::service::native_startup::{
    NativeCaptureOutputCut17, NativeRestoredSettledActionCurrent17,
};
use crate::reference_packet::service::{
    CurrentServiceHistory17, OriginalNativeServiceCaptureContext, ack_emitter::NativeAckBoot,
};
use crate::retained_metadata::{
    MetadataObserver, OrdinaryBytesFormatterDemandData, RetainedProtocolMetadataFacts,
    aliases::MetadataAliasBank, records::MetadataRecordBank,
};
use serde::{Serialize, Serializer, ser::SerializeTuple};
use std::cell::{Ref, RefCell};

/// Retains the actual borrowed source graph beside its completed census banks.
pub(in crate::reference_packet) struct NativeCurrentGraph17Borrowed<'a> {
    endpoint: &'a PacketEndpoint<DeadlineStream>,
    prelude: NativeConnectionPrelude17<'a>,
    service: CurrentServiceHistory17<'a>,
    boot_identity: &'a Rc<RefCell<NativeAckBoot>>,
    boot: Ref<'a, NativeAckBoot>,
    records: &'a MetadataRecordBank,
    aliases: &'a MetadataAliasBank,
    facts: RetainedProtocolMetadataFacts,
    ordinary_bytes_formatter: OrdinaryBytesFormatterDemandData,
    action_cut: Option<(
        &'a NativeRestoredSettledActionCurrent17<'a>,
        &'a NativeCaptureOutputCut17<'a>,
    )>,
}

fn observe_current_graph17_source_data(
    endpoint: &PacketEndpoint<DeadlineStream>,
    prelude: &NativeConnectionPrelude17<'_>,
    service: &CurrentServiceHistory17<'_>,
    boot_identity: &Rc<RefCell<NativeAckBoot>>,
    action_cut: Option<(
        &NativeRestoredSettledActionCurrent17<'_>,
        &NativeCaptureOutputCut17<'_>,
    )>,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    service.observe_registrar_root17_metadata(observer)?;
    prelude.observe_actor_metadata_data(observer)?;
    service.observe_supervisor_root17_metadata(observer)?;
    prelude.observe_codec_metadata_data(observer)?;
    endpoint
        .native
        .observe_settled17_root_hold_metadata_data(observer)?;
    prelude.observe_frames_metadata_data(observer)?;
    prelude.observe_deadline_metadata_data(observer)?;
    prelude.observe_mapping_metadata_data(observer)?;
    endpoint
        .uploads
        .borrowed_owned11_protocol_view(&endpoint.authority)?
        .observe_owned11_metadata(observer)?;
    if let Some((view, cut)) = action_cut {
        NativeAckBoot::observe_current17_with_action_cut_metadata_data(
            boot_identity,
            view,
            cut,
            observer,
        )?;
    } else {
        NativeAckBoot::observe_current17_metadata_data(boot_identity, observer)?;
    }
    prelude
        .connection_data()
        .observe_native_settled17_metadata(observer)?;
    endpoint.observe_settled17_metadata_data(observer)?;
    endpoint
        .native
        .observe_restored_settled_history_metadata_data(observer)?;
    service.observe_rooted_service17_metadata(observer)?;
    Ok(())
}

impl PacketEndpoint<DeadlineStream> {
    /// Records and borrows the complete actual graph without constructing grants.
    ///
    /// Banks belong to the caller's once output owner. This method is the only
    /// recorder reset in the whole walk; child writers never reset either bank.
    ///
    /// # Errors
    /// Refuses changed live parents, unsupported partial capability cuts, busy
    /// children or finite metadata/alias limits. Partial banks remain retained.
    pub(in crate::reference_packet) fn borrowed_current_graph17_data<'a>(
        &'a self,
        context: &'a OriginalNativeServiceCaptureContext<'a>,
        records: &'a mut MetadataRecordBank,
        aliases: &'a mut MetadataAliasBank,
    ) -> Result<NativeCurrentGraph17Borrowed<'a>, ProviderError> {
        self.borrowed_current_graph17_inner_data(context, records, aliases, None)
    }

    /// Borrows the same graph through its authenticated active Capture recorder.
    ///
    /// # Errors
    /// Refuses foreign occurrence/cut roots or the ordinary graph borrower errors.
    pub(in crate::reference_packet) fn borrowed_current_graph17_with_action_cut_data<'a>(
        &'a self,
        context: &'a OriginalNativeServiceCaptureContext<'a>,
        view: &'a NativeRestoredSettledActionCurrent17<'a>,
        cut: &'a NativeCaptureOutputCut17<'a>,
        records: &'a mut MetadataRecordBank,
        aliases: &'a mut MetadataAliasBank,
    ) -> Result<NativeCurrentGraph17Borrowed<'a>, ProviderError> {
        self.borrowed_current_graph17_inner_data(context, records, aliases, Some((view, cut)))
    }

    fn borrowed_current_graph17_inner_data<'a>(
        &'a self,
        context: &'a OriginalNativeServiceCaptureContext<'a>,
        records: &'a mut MetadataRecordBank,
        aliases: &'a mut MetadataAliasBank,
        action_cut: Option<(
            &'a NativeRestoredSettledActionCurrent17<'a>,
            &'a NativeCaptureOutputCut17<'a>,
        )>,
    ) -> Result<NativeCurrentGraph17Borrowed<'a>, ProviderError> {
        if !records.rows().is_empty() || aliases.retained_rows() != 0 {
            return Err(refused());
        }
        self.borrowed_rooted_settled17_data()?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let boot_identity = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let prelude = connection.borrowed_native_prelude17_data()?;
        let service = context.borrowed_current_native17_service_data(
            connection,
            &self.uploads,
            boot_identity,
            &self.policy,
        )?;
        let boot = boot_identity.try_borrow().map_err(|_| refused())?;
        if let Some((view, cut)) = action_cut {
            boot.borrowed_current17_with_action_cut_data(boot_identity, view, cut)?;
            self.authenticate_settled_capture17_current_action_cut_data(view)?;
        } else {
            boot.borrowed_current17_data(boot_identity)?;
        }

        let mut observer = MetadataObserver::recording_with_aliases(records, aliases);
        observe_current_graph17_source_data(
            self,
            &prelude,
            &service,
            boot_identity,
            action_cut,
            &mut observer,
        )?;
        let ordinary_bytes_formatter = observer.ordinary_bytes_formatter_data();
        let facts = observer.finish();
        Ok(NativeCurrentGraph17Borrowed {
            endpoint: self,
            prelude,
            service,
            boot_identity,
            boot,
            records,
            aliases,
            facts,
            ordinary_bytes_formatter,
            action_cut,
        })
    }
}

impl NativeCurrentGraph17Borrowed<'_> {
    /// Borrows the completed exhaustive source census as DATA only.
    pub(in crate::reference_packet) fn metadata_facts_data(
        &self,
    ) -> &RetainedProtocolMetadataFacts {
        &self.facts
    }
}

struct GraphBody17<'a, 'owner>(&'a NativeCurrentGraph17Borrowed<'owner>);

impl Serialize for NativeCurrentGraph17Borrowed<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some((view, cut)) = self.action_cut {
            self.boot
                .borrowed_current17_with_action_cut_data(self.boot_identity, view, cut)
                .map_err(serde::ser::Error::custom)?;
            self.endpoint
                .authenticate_settled_capture17_current_action_cut_data(view)
                .map_err(serde::ser::Error::custom)?;
        }
        let mut fields = serializer.serialize_tuple(4)?;
        fields.serialize_element(CURRENT_PROTOCOL17_FORMAT)?;
        fields.serialize_element(&GraphBody17(self))?;
        fields.serialize_element(self.records.rows())?;
        fields.serialize_element(self.aliases)?;
        fields.end()
    }
}

impl Serialize for GraphBody17<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let source = self.0;
        let endpoint = source.endpoint;
        let mut fields = serializer.serialize_tuple(16)?;
        fields.serialize_element(CURRENT_GRAPH17_FORMAT)?;
        fields.serialize_element(&source.service.registrar_root17_data())?;
        fields.serialize_element(
            &source
                .prelude
                .actor_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_element(&source.service.supervisor_root17_data())?;
        fields.serialize_element(&source.prelude.codec_data())?;
        fields.serialize_element("current-native-control-identity")?;
        fields.serialize_element(
            &endpoint
                .native
                .borrowed_settled17_root_hold_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_element(&source.prelude.frames_data())?;
        fields.serialize_element(source.prelude.deadline_data())?;
        fields.serialize_element(
            &source
                .prelude
                .mapping_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_element(
            &endpoint
                .uploads
                .borrowed_owned11_protocol_view(&endpoint.authority)
                .map_err(serde::ser::Error::custom)?,
        )?;
        if let Some((view, cut)) = source.action_cut {
            fields.serialize_element(
                &source
                    .boot
                    .borrowed_current17_with_action_cut_data(source.boot_identity, view, cut)
                    .map_err(serde::ser::Error::custom)?,
            )?;
        } else {
            fields.serialize_element(
                &source
                    .boot
                    .borrowed_current17_data(source.boot_identity)
                    .map_err(serde::ser::Error::custom)?,
            )?;
        }
        fields.serialize_element(
            &source
                .prelude
                .connection_data()
                .borrowed_rooted_native17_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_element(
            &endpoint
                .borrowed_rooted_settled17_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_element(
            &endpoint
                .native
                .borrowed_rooted_current17_data()
                .map_err(serde::ser::Error::custom)?,
        )?;
        fields.serialize_element(&source.service.rooted_service17_data())?;
        fields.end()
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native17 whole graph parent or loan differs")
}

/// Retains exact source parents and their current census for a private action.
///
/// This loan holds no RefCell guard across debit. The caller's defining private
/// begin authenticates Source/current proof and independently derives prospective
/// storage. No row, digest or historical owner constructs this source plan.
pub(in crate::reference_packet) struct NativeCurrentGraph17ActionPlan<'a> {
    endpoint: &'a PacketEndpoint<DeadlineStream>,
    context: &'a OriginalNativeServiceCaptureContext<'a>,
    facts: RetainedProtocolMetadataFacts,
    ordinary_bytes_formatter: OrdinaryBytesFormatterDemandData,
}

impl PacketEndpoint<DeadlineStream> {
    /// Borrows actual action parents after an exhaustive allocation-free census.
    ///
    /// # Errors
    /// Refuses changed live roots, unsupported capability cuts, borrowed children
    /// or finite metadata limits. No output bank or native allowance is created.
    pub(in crate::reference_packet) fn borrowed_current_graph17_source_plan_data<'a>(
        &'a self,
        context: &'a OriginalNativeServiceCaptureContext<'a>,
    ) -> Result<NativeCurrentGraph17ActionPlan<'a>, ProviderError> {
        let (facts, ordinary_bytes_formatter) = self.current_graph17_census_data(context)?;
        Ok(NativeCurrentGraph17ActionPlan {
            endpoint: self,
            context,
            facts,
            ordinary_bytes_formatter,
        })
    }

    /// Borrows a genuine Capture-effect plan at the settled custody safe point.
    ///
    /// Auxiliary Chunk/Input plans keep their separate private source scopes.
    /// This constructor performs no cleanup, drain or native effect.
    ///
    /// # Errors
    /// Refuses unresolved upload/pin custody, active host transactions or the
    /// ordinary actual-parent/census checks of the source-plan constructor.
    pub(in crate::reference_packet) fn borrowed_settled_capture17_source_plan_data<'a>(
        &'a self,
        context: &'a OriginalNativeServiceCaptureContext<'a>,
    ) -> Result<NativeCurrentGraph17ActionPlan<'a>, ProviderError> {
        self.authenticate_settled_capture17_effect_cut_data()?;
        self.borrowed_current_graph17_source_plan_data(context)
    }

    fn authenticate_settled_capture17_effect_cut_data(&self) -> Result<(), ProviderError> {
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        connection.authenticate_native17_logical_capture_cut_data(
            crate::protocol_snapshot::ProtocolCaptureCut::NativeIncomingCapture,
        )?;
        self.authenticate_settled_capture17_custody_data()?;
        // Some is the normal retained completed-restore capsule. Its genuine
        // Released witness, rather than slot absence, authenticates completion.
        // None belongs to the separately authenticated original cohort; it
        // supplies no restoration witness or method permission here.
        let _released = self.authenticate_settled_capture_host_cut17_data()?;
        Ok(())
    }

    /// Records the actual graph before borrowing its parent-binding action plan.
    ///
    /// # Errors
    /// Refuses changed roots, nonempty banks or finite source metadata limits.
    pub(in crate::reference_packet) fn borrowed_current_graph17_action_plan_data<'a>(
        &'a self,
        context: &'a OriginalNativeServiceCaptureContext<'a>,
        records: &mut MetadataRecordBank,
        aliases: &mut MetadataAliasBank,
    ) -> Result<NativeCurrentGraph17ActionPlan<'a>, ProviderError> {
        let graph = self.borrowed_current_graph17_data(context, records, aliases)?;
        let facts = *graph.metadata_facts_data();
        let ordinary_bytes_formatter = graph.ordinary_bytes_formatter;
        drop(graph);
        Ok(NativeCurrentGraph17ActionPlan {
            endpoint: self,
            context,
            facts,
            ordinary_bytes_formatter,
        })
    }

    fn current_graph17_census_data(
        &self,
        context: &OriginalNativeServiceCaptureContext<'_>,
    ) -> Result<
        (
            RetainedProtocolMetadataFacts,
            OrdinaryBytesFormatterDemandData,
        ),
        ProviderError,
    > {
        self.borrowed_rooted_settled17_data()?;
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        let boot_identity = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        let prelude = connection.borrowed_native_prelude17_data()?;
        let service = context.borrowed_current_native17_service_data(
            connection,
            &self.uploads,
            boot_identity,
            &self.policy,
        )?;
        let boot = boot_identity.try_borrow().map_err(|_| refused())?;
        boot.borrowed_current17_data(boot_identity)?;
        let mut observer = MetadataObserver::new();
        observe_current_graph17_source_data(
            self,
            &prelude,
            &service,
            boot_identity,
            None,
            &mut observer,
        )?;
        let ordinary_bytes_formatter = observer.ordinary_bytes_formatter_data();
        Ok((observer.finish(), ordinary_bytes_formatter))
    }
}

impl NativeCurrentGraph17ActionPlan<'_> {
    /// Rechecks exact source parents and every census field before private debit.
    ///
    /// All temporary Boot/Mapping/frame/registrar guards end before this returns.
    /// The defining caller must still authenticate its current proof and derive
    /// a separately funded prospective quote, then drop the plan before dispatch.
    ///
    /// # Errors
    /// Refuses a different actual parent, changed origin or changed whole census.
    pub(in crate::reference_packet) fn authenticate_same_parents_data(
        &self,
        endpoint: &PacketEndpoint<DeadlineStream>,
        context: &OriginalNativeServiceCaptureContext<'_>,
        connection: &Connection<DeadlineStream>,
        control: &PacketControl,
        records: &[ExchangeRecord],
        boot: &Rc<RefCell<NativeAckBoot>>,
    ) -> Result<(), ProviderError> {
        let Some(Transport::Connected(actual_connection)) = self.endpoint.transport.as_ref() else {
            return Err(refused());
        };
        if !std::ptr::eq(endpoint, self.endpoint)
            || !std::ptr::eq(context, self.context)
            || !std::ptr::eq(connection, actual_connection)
            || !std::ptr::eq(control, &self.endpoint.native)
            || !std::ptr::eq(records, self.endpoint.records.as_slice())
            || self
                .endpoint
                .canonical_ack_boot
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(boot, actual))
            || self.endpoint.current_graph17_census_data(self.context)?
                != (self.facts, self.ordinary_bytes_formatter)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Rechecks supplied action parts against the privately retained full parents.
    ///
    /// # Errors
    /// Refuses changed actual parts, origins or any whole-source census field.
    pub(in crate::reference_packet) fn authenticate_action_parent_parts_data(
        &self,
        connection: &Connection<DeadlineStream>,
        control: &PacketControl,
        records: &[ExchangeRecord],
        boot: &Rc<RefCell<NativeAckBoot>>,
    ) -> Result<(), ProviderError> {
        self.authenticate_same_parents_data(
            self.endpoint,
            self.context,
            connection,
            control,
            records,
            boot,
        )
    }

    /// Rechecks the genuine Capture safe point immediately before private debit.
    ///
    /// The defining Capture begin must additionally authenticate its Source MAC,
    /// current proof and independently funded prospective row. Other private
    /// auxiliary/Input actions use their own exact custody scopes.
    ///
    /// # Errors
    /// Refuses changed actual parents/census or any unresolved upload, pin or
    /// active host transaction; no modeled queue is drained or cleared.
    pub(in crate::reference_packet) fn authenticate_settled_capture17_action_parent_parts_data(
        &self,
        connection: &Connection<DeadlineStream>,
        control: &PacketControl,
        records: &[ExchangeRecord],
        boot: &Rc<RefCell<NativeAckBoot>>,
    ) -> Result<(), ProviderError> {
        self.authenticate_action_parent_parts_data(connection, control, records, boot)?;
        self.endpoint
            .authenticate_settled_capture17_effect_cut_data()
    }

    /// Borrows the actual current Connection captured by this source loan.
    ///
    /// # Errors
    /// Refuses an unsupported transport, which cannot arise from its constructor.
    pub(in crate::reference_packet) fn connection_data(
        &self,
    ) -> Result<&Connection<DeadlineStream>, ProviderError> {
        let Some(Transport::Connected(connection)) = self.endpoint.transport.as_ref() else {
            return Err(refused());
        };
        Ok(connection)
    }

    /// Borrows the actual Control parent for a defining prospective phase plan.
    pub(in crate::reference_packet) fn control_data(&self) -> &PacketControl {
        &self.endpoint.native
    }

    /// Borrows the actual current exchange record bank without copying its rows.
    pub(in crate::reference_packet) fn records_data(&self) -> &[ExchangeRecord] {
        &self.endpoint.records
    }

    /// Borrows the same actual Endpoint receiver for defining auxiliary pricing.
    pub(in crate::reference_packet) fn uploads_data(&self) -> &crate::blob::BlobReceiver {
        &self.endpoint.uploads
    }

    /// Borrows a formatter bound from actual typed Bytes without allocating a bank.
    ///
    /// The defining action adds its checked temporary extent before generic
    /// counting. Compact-wrapped typed Bytes may make this conservative. Other
    /// serializer work and genuinely new future fields require independently
    /// derived rows; this is neither total work nor a native spending grant.
    pub(in crate::reference_packet) fn ordinary_bytes_formatter_data(
        &self,
    ) -> OrdinaryBytesFormatterDemandData {
        self.ordinary_bytes_formatter
    }

    /// Borrows the actual census without turning it into a storage allowance.
    pub(in crate::reference_packet) fn metadata_facts_data(
        &self,
    ) -> &RetainedProtocolMetadataFacts {
        &self.facts
    }
}

impl PacketEndpoint<DeadlineStream> {
    /// Rechecks the custody cut against the exact Boot-authenticated action loan.
    fn authenticate_settled_capture17_current_action_cut_data(
        &self,
        current: &NativeRestoredSettledActionCurrent17<'_>,
    ) -> Result<(), ProviderError> {
        let Some(Transport::Connected(connection)) = self.transport.as_ref() else {
            return Err(refused());
        };
        connection.authenticate_native17_current_action_cut_data(current)?;
        self.authenticate_settled_capture17_custody_data()?;
        let _released = self.authenticate_settled_capture_host_cut17_data()?;
        Ok(())
    }
}
