//! Lends genuine service roots to the native protocol encoder without new owners.
//!
//! Construction is confined to the actual service and endpoint. Every data loan
//! authenticates the current token, original endpoint roots, closed bootstrap,
//! selected registrar, supervisor aliases and exact original operational cut.

use super::*;
use crate::blob::BlobReceiver;
use crate::client::{DeadlineStream, ExchangeDeadline};
use crate::connection::{Connection, ProviderStream};
use crate::reference_packet::endpoint::PacketEndpointPolicy;
use crate::retained_metadata::{MetadataObserver, aliases::MetadataSharedKind};
use ack_emitter::{NativeAckBoot, OriginalNativeBootstrapOwned11};
use serde::{Serialize, Serializer};
use std::cell::RefCell;

#[path = "settled_current_service.rs"]
mod settled_current;

pub(crate) struct OriginalNativeServiceCaptureContext<'a> {
    handshake: &'a OriginalServiceHandshake,
    bootstrap: Option<&'a dyn std::any::Any>,
    supervisor: &'a Rc<security::Supervisor>,
    deadline: &'a ExchangeDeadline,
}

impl<'a> OriginalNativeServiceCaptureContext<'a> {
    pub(super) fn new(
        handshake: &'a OriginalServiceHandshake,
        bootstrap: Option<&'a dyn std::any::Any>,
        supervisor: &'a Rc<security::Supervisor>,
        deadline: &'a ExchangeDeadline,
    ) -> Self {
        Self {
            handshake,
            bootstrap,
            supervisor,
            deadline,
        }
    }

    pub(in crate::reference_packet) fn with_original_endpoint_roots<'b>(
        &'b self,
        boot: &'b Rc<RefCell<NativeAckBoot>>,
        policy: &'b Rc<dyn PacketEndpointPolicy>,
    ) -> OriginalNativeCaptureContext<'b> {
        OriginalNativeCaptureContext {
            service: self,
            boot,
            policy,
        }
    }
}

pub(crate) struct OriginalNativeCaptureContext<'a> {
    service: &'a OriginalNativeServiceCaptureContext<'a>,
    boot: &'a Rc<RefCell<NativeAckBoot>>,
    policy: &'a Rc<dyn PacketEndpointPolicy>,
}

impl OriginalNativeCaptureContext<'_> {
    /// Reports the fixed startup loan and codec counter layouts.
    ///
    /// This excludes compiler/recursive traversal frames, allocator overhead,
    /// preowned record/alias banks, unique identity rosters and retained payloads. It is requested
    /// storage data and supplies no allocation or original startup authority.
    pub(crate) fn startup_protocol_counter_scratch_data() -> usize {
        [
            std::mem::size_of::<OriginalNativeServiceOwned11<'static>>(),
            NativeAckBoot::startup_protocol_counter_scratch_data(),
            crate::connection::original_native_startup_protocol_counter_scratch_data(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .unwrap_or(usize::MAX)
    }

    pub(crate) fn invocation_additional_counter_scratch_data() -> usize {
        NativeAckBoot::invocation_wire_counter_scratch_data()
            .saturating_add(OriginalNativeBootstrapOwned11::invocation_wire_counter_scratch_data())
    }

    pub(crate) fn authenticate_original<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        blobs: &BlobReceiver,
    ) -> Result<(), ProviderError> {
        let token = connection.original_native_owned11_admission()?;
        token.authenticate_current(connection)?;
        if !Rc::ptr_eq(self.boot, &token.boot)
            || !std::ptr::addr_eq(Rc::as_ptr(self.policy), Rc::as_ptr(&token.policy))
        {
            return Err(ProviderError::Correlation(
                "native whole11 endpoint issuer roots differ",
            ));
        }
        connection.authenticate_original_supervisor(self.service.supervisor)?;
        blobs.authenticate_original_supervisor(self.service.supervisor)?;
        self.service.deadline.remaining()?;
        Ok(())
    }

    pub(crate) fn borrow_original<'a>(
        &'a self,
        connection: &'a Connection<DeadlineStream>,
        blobs: &BlobReceiver,
    ) -> Result<OriginalNativeServiceOwned11<'a>, ProviderError> {
        self.borrow_at_edition(connection, blobs, false, false)
    }

    pub(crate) fn requires_original_native_startup_codec<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        blobs: &BlobReceiver,
    ) -> Result<bool, ProviderError> {
        self.authenticate_original(connection, blobs)?;
        connection
            .original_native_owned11_admission()?
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native startup boot borrowed"))?
            .requires_startup_codec_data()
    }

    pub(crate) fn borrow_original_startup<'a>(
        &'a self,
        connection: &'a Connection<DeadlineStream>,
        blobs: &BlobReceiver,
    ) -> Result<OriginalNativeServiceOwned11<'a>, ProviderError> {
        self.borrow_at_edition(connection, blobs, true, false)
    }

    pub(crate) fn borrow_current_original_protocol_data<'a>(
        &'a self,
        connection: &'a Connection<DeadlineStream>,
        blobs: &BlobReceiver,
    ) -> Result<OriginalNativeServiceOwned11<'a>, ProviderError> {
        let startup = self.requires_original_native_startup_codec(connection, blobs)?;
        let invocation = connection
            .original_native_owned11_admission()?
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("invocation boot borrowed"))?
            .requires_invocation_codec_data()?;
        self.borrow_at_edition(connection, blobs, startup, invocation)
    }

    fn borrow_at_edition<'a>(
        &'a self,
        connection: &'a Connection<DeadlineStream>,
        blobs: &BlobReceiver,
        startup: bool,
        invocation: bool,
    ) -> Result<OriginalNativeServiceOwned11<'a>, ProviderError> {
        self.authenticate_original(connection, blobs)?;
        if self.requires_original_native_startup_codec(connection, blobs)? != startup {
            return Err(ProviderError::Correlation(
                "native service codec edition differs",
            ));
        }
        connection.authenticate_original_service_deadline(self.service.deadline)?;
        let token = connection.original_native_owned11_admission()?;
        let retained = self.service.bootstrap.ok_or(ProviderError::Correlation(
            "native original bootstrap absent",
        ))?;
        let bootstrap = if invocation {
            OriginalNativeBootstrapOwned11::borrow_original_invocation(retained, token, connection)?
        } else if startup {
            OriginalNativeBootstrapOwned11::borrow_original_startup(retained, token, connection)?
        } else {
            OriginalNativeBootstrapOwned11::borrow_original(retained, token, connection)?
        };
        // The primitive birth cut remains historical data after transfer.
        // The service's same deadline owner may reset for later operations;
        // its current cut is authenticated independently against Connection.
        let OriginalServiceHandshake::Selected {
            handshake,
            registry,
        } = self.service.handshake
        else {
            return Err(ProviderError::Correlation(
                "native whole11 selected original registrar absent",
            ));
        };
        let supervisor = self.service.supervisor.borrow_empty_owned11()?;
        // Acquire the original registration lock after source/current checks;
        // no registration callbacks may run while this data loan is held.
        let negotiation =
            handshake.original_owned11_negotiation_view(&token.authority, registry)?;
        Ok(OriginalNativeServiceOwned11 {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            startup,
            invocation,
            roots: self,
            bootstrap,
            supervisor,
            negotiation,
            cut: self.service.deadline.original_cut(),
        })
    }
}

pub(crate) struct OriginalNativeServiceOwned11<'a> {
    startup: bool,
    invocation: bool,
    creator: u32,
    thread: std::thread::ThreadId,
    roots: &'a OriginalNativeCaptureContext<'a>,
    bootstrap: OriginalNativeBootstrapOwned11<'a>,
    supervisor: security::OriginalNativeSupervisorOwned11<'a>,
    negotiation: crate::handshake::OriginalExtensionNegotiationOwned11<
        'a,
        server::complete::birth::EmptyBootExtensions,
    >,
    cut: crate::operational_time::OperationalDeadline,
}

impl OriginalNativeServiceOwned11<'_> {
    pub(crate) const fn current_protocol_format_data(&self) -> &'static str {
        if self.invocation {
            "source-private.native-state/15"
        } else if self.startup {
            "source-private.native-state/13"
        } else {
            "source-private.native-state/11"
        }
    }

    pub(crate) fn observe_current_protocol_metadata_data(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.observe_metadata_at_edition(observer)
    }

    pub(crate) fn observe_startup_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        if !self.startup || self.invocation {
            return Err(ProviderError::Correlation(
                "native startup service edition absent",
            ));
        }
        self.observe_metadata_at_edition(observer)
    }

    fn ensure_origin_and_cut(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation(
                "native whole11 service loan foreign origin",
            ));
        }
        self.roots.service.deadline.remaining()?;
        if self.roots.service.deadline.original_cut() != self.cut {
            return Err(ProviderError::Correlation(
                "native whole11 original service cut changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn original_cut(&self) -> crate::operational_time::OperationalDeadline {
        self.cut
    }

    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        if self.startup {
            return Err(ProviderError::Correlation(
                "native service startup edition requires explicit observer",
            ));
        }
        self.observe_metadata_at_edition(observer)
    }

    fn observe_metadata_at_edition(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.ensure_origin_and_cut()?;
        self.negotiation.observe_owned11_metadata(observer)?;
        if self.invocation {
            self.bootstrap.observe_invocation_metadata(observer)?;
        } else if self.startup {
            self.bootstrap.observe_startup_metadata(observer)?;
        } else {
            self.bootstrap.observe_owned11_metadata(observer)?;
        }
        observer.shared_original(
            MetadataSharedKind::NativeSupervisor,
            self.roots.service.supervisor.as_ref(),
        )?;
        self.supervisor.observe_owned11_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::NativeBoot, self.roots.boot.as_ref())?;
        {
            let boot = self
                .roots
                .boot
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("native endpoint boot borrowed"))?;
            if self.invocation {
                boot.observe_invocation_metadata(observer)?;
            } else if self.startup {
                boot.observe_startup_metadata(observer)?;
            } else {
                boot.observe_owned11_metadata(observer)?;
            }
        }
        observer.shared_original(MetadataSharedKind::NativePolicy, self.roots.policy.as_ref())?;
        let boot = self
            .roots
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native endpoint boot borrowed"))?;
        boot.policy
            .as_ref()
            .ok_or(ProviderError::Correlation("native endpoint policy absent"))?
            .observe_owned11_metadata(observer)?;
        self.roots
            .service
            .deadline
            .observe_owned11_metadata(observer)
    }
}

impl Serialize for OriginalNativeServiceOwned11<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.ensure_origin_and_cut()
            .map_err(serde::ser::Error::custom)?;
        let boot = self
            .roots
            .boot
            .try_borrow()
            .map_err(|_| serde::ser::Error::custom("native endpoint boot borrowed"))?;
        if self.invocation {
            let boot_view = boot
                .borrowed_invocation_protocol_view()
                .map_err(serde::ser::Error::custom)?;
            let policy = boot
                .policy
                .as_ref()
                .ok_or_else(|| serde::ser::Error::custom("invocation policy absent"))?;
            return (
                "source-private.native-service/15",
                &self.negotiation,
                &self.bootstrap,
                "source-private.native-supervisor-owner/11",
                &self.supervisor,
                boot_view,
                policy.borrowed_owned11_protocol_view(),
                "opaque-original-service-cut",
            )
                .serialize(serializer);
        }
        if self.startup {
            let boot_view = boot
                .borrowed_startup_protocol_view()
                .map_err(serde::ser::Error::custom)?;
            let policy = boot
                .policy
                .as_ref()
                .ok_or_else(|| serde::ser::Error::custom("native endpoint policy absent"))?;
            return (
                "source-private.native-service/14",
                &self.negotiation,
                &self.bootstrap,
                "source-private.native-supervisor-owner/11",
                &self.supervisor,
                boot_view,
                policy.borrowed_owned11_protocol_view(),
                "opaque-original-service-cut",
            )
                .serialize(serializer);
        }
        let boot_view = boot
            .borrowed_owned11_protocol_view()
            .map_err(serde::ser::Error::custom)?;
        let policy = boot
            .policy
            .as_ref()
            .ok_or_else(|| serde::ser::Error::custom("native endpoint policy absent"))?;
        (
            "source-private.native-service/11",
            &self.negotiation,
            &self.bootstrap,
            "source-private.native-supervisor-owner/11",
            &self.supervisor,
            boot_view,
            policy.borrowed_owned11_protocol_view(),
            "opaque-original-service-cut",
        )
            .serialize(serializer)
    }
}

/// Retains a measured service scope for one private restore preparation.
///
/// Construction requires the successful original bootstrap/registrar/supervisor
/// loan. The facts are requested-layout data; only the independent authenticated
/// restore request and checked aggregate can admit input allocation.
pub(crate) struct NativeRestoreServiceAllocationQuote {
    creator: u32,
    thread: std::thread::ThreadId,
    boot: Rc<RefCell<NativeAckBoot>>,
    policy: Rc<crate::reference_packet::Native5Policy>,
    cut: crate::operational_time::OperationalDeadline,
    facts: crate::retained_metadata::RetainedProtocolMetadataFacts,
}

impl OriginalNativeCaptureContext<'_> {
    pub(crate) fn quote_original_restore_service_allocation(
        &self,
        connection: &Connection<DeadlineStream>,
        blobs: &BlobReceiver,
    ) -> Result<NativeRestoreServiceAllocationQuote, ProviderError> {
        // Complete current Connection and Blob roots are measured before the
        // registrar/service loan is held. No callback or nested bank loan runs
        // under the original negotiation guard.
        let mut observer = MetadataObserver::new();
        connection.observe_original_restore_connection_metadata(&mut observer)?;
        // The retained native token reauthenticates the same actor, sealed
        // policy and registrar before lending its existing authority. This
        // readonly data walk neither clones authority nor invokes containment.
        let token = connection.original_native_owned11_admission()?;
        blobs
            .borrowed_owned11_protocol_view(&token.authority)?
            .observe_owned11_metadata(&mut observer)?;
        let loan = self.borrow_original(connection, blobs)?;
        loan.observe_owned11_metadata(&mut observer)?;
        // Account the actual new quote's strong edges as additional retained
        // views, without inferring allocator identity from serialized labels.
        observer.shared_original(MetadataSharedKind::NativeBoot, token.boot.as_ref())?;
        token
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("restore quote boot borrowed"))?
            .observe_owned11_metadata(&mut observer)?;
        observer.shared_original(MetadataSharedKind::NativePolicy, token.policy.as_ref())?;
        token.policy.observe_owned11_metadata(&mut observer)?;
        let quote = NativeRestoreServiceAllocationQuote {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            boot: Rc::clone(&token.boot),
            policy: Rc::clone(&token.policy),
            cut: loan.original_cut(),
            facts: observer.finish(),
        };
        quote.authenticate_original(connection, &token.boot, &token.policy)?;
        Ok(quote)
    }
}

impl NativeRestoreServiceAllocationQuote {
    pub(crate) fn authenticate_original<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        boot: &Rc<RefCell<NativeAckBoot>>,
        policy: &Rc<crate::reference_packet::Native5Policy>,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || self.cut.remaining().is_none()
        {
            return Err(ProviderError::Correlation(
                "restore service quote origin/cut",
            ));
        }
        let token = connection.original_native_owned11_admission()?;
        token.authenticate_current(connection)?;
        if !Rc::ptr_eq(&self.boot, boot)
            || !Rc::ptr_eq(&self.boot, &token.boot)
            || !Rc::ptr_eq(&self.policy, policy)
            || !Rc::ptr_eq(&self.policy, &token.policy)
        {
            return Err(ProviderError::Correlation(
                "restore service quote actual roots",
            ));
        }
        Ok(())
    }

    pub(crate) fn retained_facts(&self) -> crate::retained_metadata::RetainedProtocolMetadataFacts {
        self.facts
    }
}

impl OriginalNativeServiceOwned11<'_> {
    pub(crate) fn observe_unique_capture_metadata(
        &self,
        roots: &mut crate::retained_metadata::NativeCaptureMetadataRoots,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.ensure_origin_and_cut()?;
        self.negotiation
            .observe_unique_capture_metadata(roots, observer)?;
        self.bootstrap
            .observe_unique_capture_metadata(roots, observer)?;
        if roots.observe_shared(
            observer,
            MetadataSharedKind::NativeSupervisor,
            self.roots.service.supervisor.as_ref(),
        )? {
            self.supervisor.observe_owned11_metadata(observer)?;
        }
        if roots.observe_shared(
            observer,
            MetadataSharedKind::NativeBoot,
            self.roots.boot.as_ref(),
        )? {
            self.roots
                .boot
                .try_borrow()
                .map_err(|_| ProviderError::Conflict("native Capture endpoint boot borrowed"))?
                .observe_unique_capture_metadata(roots, observer)?;
        }
        if roots.observe_shared(
            observer,
            MetadataSharedKind::NativePolicy,
            self.roots.policy.as_ref(),
        )? {
            let boot =
                self.roots.boot.try_borrow().map_err(|_| {
                    ProviderError::Conflict("native Capture endpoint boot borrowed")
                })?;
            boot.policy
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "native Capture endpoint policy absent",
                ))?
                .observe_unique_capture_metadata(roots, observer)?;
        }
        self.roots
            .service
            .deadline
            .observe_unique_capture_metadata(roots, observer)?;
        self.ensure_origin_and_cut()
    }
}

#[path = "restore_allocation.rs"]
mod restore_allocation;

mod settled_quote17;
pub(in crate::reference_packet) use settled_current::CurrentServiceHistory17;
pub(crate) use settled_current::{
    CurrentNativeService17GroupIds, HistoricalCurrentNativeService17, HistoricalNativeRegistrar17,
    NativeRegistrar17GroupIds, read_current_native17_registrar_root_data,
    read_current_native17_service_fields_data, read_rooted_current_native17_service_fields_data,
};

pub(crate) use settled_current::{
    BorrowedCurrentNativeService17LineageData, borrow_current_native17_service_lineage_data,
};
