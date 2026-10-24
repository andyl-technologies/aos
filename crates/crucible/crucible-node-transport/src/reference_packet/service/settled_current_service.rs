//! Joins the actual selected17 service, registrar, private channel and supervisor.
//!
//! This borrows the current service under its real Connection admission. The
//! initial15 import is deliberately the only supported admission family here;
//! a settled17 reload needs its distinct installed Connection issuer. Historical
//! bootstrap/key data and serialized role labels cannot construct that issuer.

use super::*;
use serde::ser::SerializeStruct;

pub(in crate::reference_packet) struct CurrentServiceHistory17<'a> {
    context: &'a OriginalNativeServiceCaptureContext<'a>,
    bootstrap: ack_emitter::SettledBootstrapHistory17<'a>,
    boot: &'a Rc<RefCell<NativeAckBoot>>,
    policy: &'a Rc<dyn PacketEndpointPolicy>,
    supervisor: security::NativeSupervisorHistory<'a>,
    negotiation: crate::handshake::OriginalExtensionNegotiationOwned11<
        'a,
        server::complete::birth::EmptyBootExtensions,
    >,
    cut: crate::operational_time::OperationalDeadline,
}

impl OriginalNativeServiceCaptureContext<'_> {
    /// Borrows the genuine initial15-to-selected17 service graph.
    ///
    /// The complete protocol writer separately lends the same Boot, Policy,
    /// Endpoint and current Connection components. Only the actual original
    /// admission and inherited selected17 bootstrap can supply these roots.
    ///
    /// # Errors
    /// Refuses foreign live admission, another Boot/Policy/supervisor/deadline,
    /// absent selected registrar or a non-genuine closed private17 channel.
    pub(in crate::reference_packet) fn borrowed_current_native17_service_data<'a>(
        &'a self,
        connection: &'a Connection<DeadlineStream>,
        blobs: &BlobReceiver,
        boot: &'a Rc<RefCell<NativeAckBoot>>,
        policy: &'a Rc<dyn PacketEndpointPolicy>,
    ) -> Result<CurrentServiceHistory17<'a>, ProviderError> {
        // This is a live class15 admission, never a cast from a decoded17 owner.
        // The separate settled17 installed admission must replace this branch
        // explicitly before a recaptured archive can start another live route.
        let token = connection.original_native_owned11_admission()?;
        token.authenticate_current(connection)?;
        if !Rc::ptr_eq(boot, &token.boot)
            || !std::ptr::addr_eq(Rc::as_ptr(policy), Rc::as_ptr(&token.policy))
        {
            return Err(ProviderError::Correlation("current17 service roots differ"));
        }
        connection.authenticate_settled_history_supervisor_data(self.supervisor)?;
        blobs.authenticate_original_supervisor(self.supervisor)?;
        connection.authenticate_original_service_deadline(self.deadline)?;
        self.deadline.remaining()?;
        let bootstrap = ack_emitter::borrow_current_settled_bootstrap_data(
            self.bootstrap
                .ok_or(ProviderError::Correlation("current17 bootstrap absent"))?,
            boot,
        )?;
        let OriginalServiceHandshake::Selected {
            handshake,
            registry,
        } = self.handshake
        else {
            return Err(ProviderError::Correlation(
                "current17 selected registrar absent",
            ));
        };
        let supervisor = self.supervisor.borrowed_settled_history_data()?;
        // Acquired last: the actual registration view is held only across
        // bounded serialization, with no registration or socket callback.
        let negotiation =
            handshake.original_owned11_negotiation_view(&token.authority, registry)?;
        Ok(CurrentServiceHistory17 {
            context: self,
            bootstrap,
            boot,
            policy,
            supervisor,
            negotiation,
            cut: self.deadline.original_cut(),
        })
    }
}

impl OriginalNativeServiceCaptureContext<'_> {
    /// Preserves the established current-service loan spelling.
    ///
    /// # Errors
    /// Refuses the same changed original roots or unavailable selected capsule.
    pub(in crate::reference_packet) fn borrowed_restored_settled_current_service_data<'a>(
        &'a self,
        connection: &'a Connection<DeadlineStream>,
        blobs: &BlobReceiver,
        boot: &'a Rc<RefCell<NativeAckBoot>>,
        policy: &'a Rc<dyn PacketEndpointPolicy>,
    ) -> Result<CurrentServiceHistory17<'a>, ProviderError> {
        self.borrowed_current_native17_service_data(connection, blobs, boot, policy)
    }
}

impl Serialize for CurrentServiceHistory17<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.context
            .deadline
            .remaining()
            .map_err(serde::ser::Error::custom)?;
        if self.context.deadline.original_cut() != self.cut {
            return Err(serde::ser::Error::custom("current17 service cut changed"));
        }
        let mut fields = serializer.serialize_struct("NativeCurrentService17", 7)?;
        fields.serialize_field("schema", "source-private.native-current-service/17")?;
        fields.serialize_field("negotiation", &self.negotiation)?;
        fields.serialize_field("bootstrap", &self.bootstrap)?;
        fields.serialize_field("supervisor", &self.supervisor)?;
        fields.serialize_field("boot_role", "native-boot")?;
        fields.serialize_field("policy_role", "native-policy")?;
        fields.serialize_field("cut_role", "historical-operational-cut-no-renewal")?;
        fields.end()
    }
}

impl CurrentServiceHistory17<'_> {
    /// Borrows the complete actual supervisor before its role edges are emitted.
    pub(in crate::reference_packet) fn supervisor_root17_data(&self) -> impl Serialize + '_ {
        &self.supervisor
    }

    /// Defines the actual supervisor Rc and all retained incidents/quarantines.
    ///
    /// # Errors
    /// Refuses changed source currentness, borrowed payloads or finite banks.
    pub(in crate::reference_packet) fn observe_supervisor_root17_metadata(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_original_cut()?;
        observer.shared_original(
            MetadataSharedKind::NativeSupervisor,
            self.context.supervisor.as_ref(),
        )?;
        self.context
            .supervisor
            .observe_settled_history_metadata_data(observer)
    }

    /// Appends full registrar/bootstrap data and the actual repeated root edges.
    ///
    /// # Errors
    /// Refuses changed source currentness, unavailable original loans or banks.
    pub(in crate::reference_packet) fn observe_current_service17_metadata(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_original_cut()?;
        self.negotiation.observe_owned11_metadata(observer)?;
        self.bootstrap.observe_settled17_metadata(observer)?;
        observer.shared_original(
            MetadataSharedKind::NativeSupervisor,
            self.context.supervisor.as_ref(),
        )?;
        self.context
            .supervisor
            .observe_settled_history_metadata_data(observer)?;
        observer.shared_original(MetadataSharedKind::NativeBoot, self.boot.as_ref())?;
        observer.shared_original(MetadataSharedKind::NativePolicy, self.policy.as_ref())?;
        self.context.deadline.observe_owned11_metadata(observer)
    }

    fn ensure_original_cut(&self) -> Result<(), ProviderError> {
        self.context.deadline.remaining()?;
        if self.context.deadline.original_cut() != self.cut {
            return Err(ProviderError::Correlation("current17 service cut changed"));
        }
        Ok(())
    }
}

#[path = "settled_current_service/reader.rs"]
mod reader;
#[path = "settled_current_service/registrar.rs"]
mod registrar;
pub(crate) use registrar::{
    HistoricalNativeRegistrar17, NativeRegistrar17GroupIds,
    read_current_native17_registrar_root_data,
};

pub(crate) use reader::{
    CurrentNativeService17GroupIds, HistoricalCurrentNativeService17,
    read_current_native17_service_fields_data, read_rooted_current_native17_service_fields_data,
};

impl CurrentServiceHistory17<'_> {
    /// Borrows the complete actual registrar before descendant epoch/gate edges.
    pub(in crate::reference_packet) fn registrar_root17_data(&self) -> impl Serialize + '_ {
        &self.negotiation
    }

    /// Appends the genuine complete registrar using this same held live loan.
    ///
    /// # Errors
    /// Refuses changed currentness or finite metadata bank exhaustion.
    pub(in crate::reference_packet) fn observe_registrar_root17_metadata(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_original_cut()?;
        self.negotiation.observe_owned11_metadata(observer)
    }

    /// Borrows the distinct rooted schema with closed registrar/supervisor edges.
    pub(in crate::reference_packet) fn rooted_service17_data(&self) -> impl Serialize + '_ {
        RootedService17(self)
    }

    /// Appends all genuine source rows beneath the rooted service variant.
    ///
    /// # Errors
    /// Refuses changed currentness, unavailable state or finite metadata banks.
    pub(in crate::reference_packet) fn observe_rooted_service17_metadata(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_original_cut()?;
        self.negotiation.observe_owned11_metadata(observer)?;
        self.bootstrap.observe_settled17_metadata(observer)?;
        observer.shared_original(
            MetadataSharedKind::NativeSupervisor,
            self.context.supervisor.as_ref(),
        )?;
        observer.shared_original(MetadataSharedKind::NativeBoot, self.boot.as_ref())?;
        observer.shared_original(MetadataSharedKind::NativePolicy, self.policy.as_ref())?;
        self.context.deadline.observe_owned11_metadata(observer)
    }
}

struct RootedService17<'a, 'owner>(&'a CurrentServiceHistory17<'owner>);

impl Serialize for RootedService17<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .ensure_original_cut()
            .map_err(serde::ser::Error::custom)?;
        let mut fields = serializer.serialize_struct("NativeRootedService17", 7)?;
        fields.serialize_field("schema", "source-private.native-rooted-service/17")?;
        fields.serialize_field("negotiation", "native-registrar")?;
        fields.serialize_field("bootstrap", &self.0.bootstrap)?;
        fields.serialize_field("supervisor", "native-supervisor")?;
        fields.serialize_field("boot_role", "native-boot")?;
        fields.serialize_field("policy_role", "native-policy")?;
        fields.serialize_field("cut_role", "historical-operational-cut-no-renewal")?;
        fields.end()
    }
}

#[path = "settled_current_service/logical17.rs"]
mod logical17;
pub(crate) use logical17::{
    BorrowedCurrentNativeService17LineageData, borrow_current_native17_service_lineage_data,
};
