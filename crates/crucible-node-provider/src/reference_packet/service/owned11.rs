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
        self.authenticate_original(connection, blobs)?;
        connection.authenticate_original_service_deadline(self.service.deadline)?;
        let token = connection.original_native_owned11_admission()?;
        let bootstrap = OriginalNativeBootstrapOwned11::borrow_original(
            self.service.bootstrap.ok_or(ProviderError::Correlation(
                "native original bootstrap absent",
            ))?,
            token,
            connection,
        )?;
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
            roots: self,
            bootstrap,
            supervisor,
            negotiation,
            cut: self.service.deadline.original_cut(),
        })
    }
}

pub(crate) struct OriginalNativeServiceOwned11<'a> {
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
        self.ensure_origin_and_cut()?;
        self.negotiation.observe_owned11_metadata(observer)?;
        self.bootstrap.observe_owned11_metadata(observer)?;
        observer.shared_original(
            MetadataSharedKind::NativeSupervisor,
            self.roots.service.supervisor.as_ref(),
        )?;
        self.supervisor.observe_owned11_metadata(observer)?;
        observer.shared_original(MetadataSharedKind::NativeBoot, self.roots.boot.as_ref())?;
        self.roots
            .boot
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("native endpoint boot borrowed"))?
            .observe_owned11_metadata(observer)?;
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
