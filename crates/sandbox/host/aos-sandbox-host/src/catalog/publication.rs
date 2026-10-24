//! Retains authenticated HostCatalog17 input and the shared native publisher.
//!
//! Only the real Host broker constructs this original after its same Control
//! operation paid the complete header, native, model and post destinations.

use std::error::Error;
use std::mem::size_of;
use std::os::fd::OwnedFd;

use aos_sandbox_model::{ObjectDigest, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::immutable_file::SealedMemfdReadOriginalV2;
use aos_sandbox_protocol::host_catalog::ValidatedHostCatalogPublication;
use sha2::{Digest as _, Sha256};

use super::launch::NamedCatalogRootOriginalV2;
use super::publication_native::{self, PublicationNativeOriginal, Receiving};
use super::{FileHostCatalogPublisher, HostCatalogPublicationOutcome, HostCatalogSnapshot};
use crate::plan::CatalogClockOriginalV2;
use crate::plan::HostCatalogReceivingV2;
use crate::{HostError, Result};

/// Carries only one actual completed native publication and its exact input.
///
/// The constructor is private to the real paid Host broker. The snapshot is
/// historical DATA for protected response/recovery custody, never admission.
#[doc(hidden)]
pub struct HostCatalogPublicationCompletedV2 {
    pub(crate) outcome: HostCatalogPublicationOutcome,
    pub(crate) snapshot: Option<HostCatalogSnapshot>,
}

impl HostCatalogPublicationCompletedV2 {
    /// Returns the actual complete native publication outcome.
    #[must_use]
    pub const fn outcome_v2(&self) -> HostCatalogPublicationOutcome {
        self.outcome
    }

    /// Moves the already-paid snapshot once while retaining this completion.
    #[must_use]
    pub fn take_snapshot_v2(&mut self) -> Option<HostCatalogSnapshot> {
        self.snapshot.take()
    }
}

#[derive(Clone, Copy)]
pub(crate) enum PublicationFailureV2 {
    BeforeControl,
    BeforeClock,
    SessionCurrentness,
    Input,
    Decode,
    Native,
    BodyClock,
    BodyControl,
    RootAfter,
    AfterControl,
    FinalClock,
    Disposal,
    DisposalControl,
    DisposalClock,
}

pub(crate) struct HostCatalogPublicationOriginalV2 {
    pub(crate) clock: CatalogClockOriginalV2,
    pub(crate) payload: PublicationPayloadV2,
}

pub(crate) struct PublicationPayloadV2 {
    root_before: NamedCatalogRootOriginalV2,
    root_after: NamedCatalogRootOriginalV2,
    duplicate: Option<rustix::io::Result<OwnedFd>>,
    mapping: SealedMemfdReadOriginalV2,
    mapping_result: Option<Result<()>>,
    snapshot: Option<Result<HostCatalogSnapshot>>,
    native: PublicationNativeOriginal,
    pub(crate) before: Option<Result<()>>,
    currentness: Option<Result<()>>,
    pub(crate) body: Option<Result<HostCatalogPublicationOutcome>>,
    pub(crate) root_post: Option<Result<()>>,
    pub(crate) after: Option<Result<()>>,
    pub(crate) final_clock: Option<Result<()>>,
    pub(crate) disposed: Option<Result<()>>,
    pub(crate) first: Option<PublicationFailureV2>,
    pub(crate) completed: bool,
}

impl HostCatalogPublicationOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            clock: CatalogClockOriginalV2::new(),
            payload: PublicationPayloadV2::new(),
        }
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.payload.failure_v2(&self.clock)
    }
}

impl PublicationPayloadV2 {
    fn new() -> Self {
        Self {
            root_before: NamedCatalogRootOriginalV2::default(),
            root_after: NamedCatalogRootOriginalV2::default(),
            duplicate: None,
            mapping: SealedMemfdReadOriginalV2::new(),
            mapping_result: None,
            snapshot: None,
            native: PublicationNativeOriginal::default(),
            before: None,
            currentness: None,
            body: None,
            root_post: None,
            after: None,
            final_clock: None,
            disposed: None,
            first: None,
            completed: false,
        }
    }

    pub(crate) fn fixed_demand_v2(
        publication: &ValidatedHostCatalogPublication,
    ) -> Result<ResourceVector> {
        let input = usize::try_from(publication.catalog_bytes())
            .map_err(|_| HostError::ResourceExhausted)?;
        let carriers = size_of::<HostCatalogPublicationOriginalV2>()
            .checked_mul(2)
            .and_then(|bytes| {
                bytes
                    .checked_add(size_of::<Box<HostCatalogPublicationOriginalV2>>().checked_mul(2)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(SealedMemfdReadOriginalV2::receiving_memory_bytes_v2()?)
            })
            .and_then(|bytes| bytes.checked_add(4 * 8 * 4097))
            .and_then(|bytes| bytes.checked_add(3 * size_of::<HostCatalogReceivingV2<'_, '_>>()))
            .ok_or(HostError::ResourceExhausted)?;
        let (read_bytes, _) =
            aos_sandbox_linux::path::BeneathRegularFileReadOriginalV2::fixed_receiving_demand_v2(
                super::CATALOG_FILE.len(),
            )
            .ok_or(HostError::ResourceExhausted)?;
        let response = u64::from(publication.header().maximum_response_bytes());
        let carriers = u64::try_from(
            carriers
                .checked_add(
                    read_bytes
                        .checked_mul(2)
                        .ok_or(HostError::ResourceExhausted)?,
                )
                .ok_or(HostError::ResourceExhausted)?,
        )
        .map_err(|_| HostError::ResourceExhausted)?
        .checked_add(
            response
                .checked_mul(3)
                .ok_or(HostError::ResourceExhausted)?,
        )
        .ok_or(HostError::ResourceExhausted)?;
        publication_native::model_demand(input)?
            .checked_add(CatalogClockOriginalV2::demand_v2()?)
            .and_then(|demand| {
                demand.checked_add(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, carriers)
                        .with(D::OpenFiles, 16)
                        .with(D::MetadataEntries, 10)
                        .with(D::StorageBytes, publication.catalog_bytes())
                        .with(D::PublicationStagingBytes, publication.catalog_bytes())
                        .with(D::OutputBytes, response),
                )
            })
            .map_err(|_| HostError::ResourceExhausted)
    }

    pub(crate) fn publish_body_v2(
        &mut self,
        publisher: &FileHostCatalogPublisher,
        descriptor: &OwnedFd,
        publication: &ValidatedHostCatalogPublication,
        receiving: &mut HostCatalogReceivingV2<'_, '_>,
    ) -> Result<HostCatalogPublicationOutcome> {
        self.root_before.observe_once(&publisher.root)?;
        self.duplicate = Some(rustix::io::dup(descriptor));
        let duplicate = match self.duplicate.take() {
            Some(Ok(descriptor)) => descriptor,
            failure => {
                self.duplicate = failure;
                self.first = Some(PublicationFailureV2::Input);
                return Err(publication_native::closed());
            }
        };
        self.mapping_result = Some(
            self.mapping
                .prepare_once(
                    duplicate,
                    publication.catalog_bytes(),
                    super::MAXIMUM_HOST_CATALOG_BYTES as u64,
                )
                .map_err(|_| publication_native::closed()),
        );
        if !matches!(self.mapping_result, Some(Ok(()))) {
            self.first = Some(PublicationFailureV2::Input);
            return Err(publication_native::closed());
        }
        self.snapshot = Some(
            self.mapping
                .with_bytes(|bytes, _identity| {
                    let digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
                    if digest != publication.catalog_digest() {
                        return Err(HostError::Catalog(
                            "sealed host catalog digest does not match request".to_owned(),
                        ));
                    }
                    let snapshot = HostCatalogSnapshot::decode_canonical(bytes)?;
                    if snapshot.generation() != publication.catalog_generation() {
                        return Err(HostError::Catalog(
                            "sealed host catalog generation does not match request".to_owned(),
                        ));
                    }
                    Ok(snapshot)
                })
                .map_err(|_| publication_native::closed())?,
        );
        let snapshot = match self.snapshot.as_ref().and_then(|value| value.as_ref().ok()) {
            Some(snapshot) => snapshot,
            None => {
                self.first = Some(PublicationFailureV2::Decode);
                return Err(publication_native::closed());
            }
        };
        let result = self.native.publish(
            &publisher.root,
            snapshot,
            &mut Receiving::Original(receiving),
        );
        if result.is_err() {
            self.first = Some(if receiving.clock_failure_v2().is_some() {
                PublicationFailureV2::BodyClock
            } else if receiving.financial_refusal_v2() {
                PublicationFailureV2::BodyControl
            } else {
                PublicationFailureV2::Native
            });
        }
        result
    }

    pub(crate) fn root_after_owed_v2(
        &mut self,
        publisher: &FileHostCatalogPublisher,
    ) -> Result<()> {
        self.root_after.observe_once(&publisher.root)
    }

    pub(crate) fn take_completed_v2(&mut self) -> Result<HostCatalogPublicationCompletedV2> {
        if !self.completed || self.first.is_some() {
            return Err(publication_native::closed());
        }
        let outcome = self
            .body
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or_else(publication_native::closed)?;
        let snapshot = self
            .snapshot
            .take()
            .and_then(std::result::Result::ok)
            .ok_or_else(publication_native::closed)?;
        Ok(HostCatalogPublicationCompletedV2 {
            outcome,
            snapshot: Some(snapshot),
        })
    }

    pub(crate) fn retire_positive_input_v2(&mut self) -> Result<()> {
        self.mapping
            .retire_positive_mapping_v2()
            .map_err(|_| publication_native::closed())?;
        self.native.retire_positive_files()
    }

    fn failure_v2<'cause>(
        &'cause self,
        clock: &'cause CatalogClockOriginalV2,
    ) -> Option<&'cause (dyn Error + 'static)> {
        match self.first? {
            PublicationFailureV2::BeforeClock
            | PublicationFailureV2::BodyClock
            | PublicationFailureV2::FinalClock
            | PublicationFailureV2::DisposalClock => clock.failure_v2(),
            PublicationFailureV2::Input => self
                .duplicate
                .as_ref()
                .and_then(|value| value.as_ref().err())
                .map(|cause| cause as _)
                .or_else(|| self.mapping.failure())
                .or_else(|| cause(&self.mapping_result)),
            PublicationFailureV2::Decode => self
                .snapshot
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            PublicationFailureV2::Native => self
                .root_before
                .failure()
                .or_else(|| self.native.failure())
                .or_else(|| cause(&self.body)),
            PublicationFailureV2::RootAfter => {
                self.root_after.failure().or_else(|| cause(&self.root_post))
            }
            PublicationFailureV2::BeforeControl => cause(&self.before),
            PublicationFailureV2::SessionCurrentness => cause(&self.currentness),
            PublicationFailureV2::BodyControl => cause(&self.body),
            PublicationFailureV2::DisposalControl => cause(&self.disposed),
            PublicationFailureV2::AfterControl => cause(&self.after),
            PublicationFailureV2::Disposal => clock
                .failure_v2()
                .or_else(|| self.mapping.failure())
                .or_else(|| cause(&self.disposed)),
        }
    }
}

fn cause<T>(value: &Option<Result<T>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1;
use std::sync::{Arc, Mutex};

/// Borrows only the actual broker slot and admitted component Control owner.
///
/// No public constructor accepts a file, budget, deadline, or publication
/// result. The sealed Host composition lends this only from its live broker.
#[doc(hidden)]
pub struct HostCatalogPublicationCallsiteV2<'broker> {
    slot: &'broker mut Option<Box<HostCatalogPublicationOriginalV2>>,
    control: &'broker Arc<Mutex<crate::plan::HostComponentControlStartupV2>>,
    state_healthy: &'broker mut bool,
}

impl<'broker> HostCatalogPublicationCallsiteV2<'broker> {
    pub(crate) fn from_original_v2(
        slot: &'broker mut Option<Box<HostCatalogPublicationOriginalV2>>,
        control: &'broker Arc<Mutex<crate::plan::HostComponentControlStartupV2>>,
        state_healthy: &'broker mut bool,
    ) -> Self {
        Self {
            slot,
            control,
            state_healthy,
        }
    }

    /// Publishes under the actual request and keeps every native post on failure.
    ///
    /// # Errors
    /// Refuses foreign requests, exhausted Control, changed Root/Host custody,
    /// malformed sealed content, expired original time, native IO or posts.
    /// An entered refusal quarantines this broker; no recovery budget is minted.
    pub async fn publish_once_v2(
        &mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        publisher: &FileHostCatalogPublisher,
        descriptor: &OwnedFd,
        pending_guard: &mut dyn FnMut() -> Result<()>,
    ) -> Result<HostCatalogPublicationCompletedV2> {
        if !*self.state_healthy
            || self
                .slot
                .as_ref()
                .is_some_and(|owner| !owner.payload.completed)
        {
            return Err(publication_native::closed());
        }
        let publication = request
            .host_catalog_publication_data_v2()
            .ok_or_else(publication_native::closed)?;
        let demand = PublicationPayloadV2::fixed_demand_v2(publication)?;
        let mut control = self
            .control
            .lock()
            .map_err(|_| HostError::Fence("Host catalog original Control is poisoned"))?;
        // Finance precedes the actual Box, sealed duplicate/map, canonical
        // input and every pathname operation. Prior spent debt is unchanged.
        let preparation = match control.begin_catalog_preparation_v2(request, demand) {
            Ok(preparation) => preparation,
            Err(cause) => {
                *self.state_healthy = false;
                return Err(cause);
            }
        };
        *self.slot = Some(Box::new(HostCatalogPublicationOriginalV2::new()));
        let original = self.slot.as_mut().ok_or_else(publication_native::closed)?;
        let HostCatalogPublicationOriginalV2 { clock, payload } = original.as_mut();
        let mut loan =
            match HostCatalogReceivingV2::new_v2(preparation, clock, publication.header()) {
                Ok(loan) => loan,
                Err(cause) => {
                    payload.before = Some(Err(cause));
                    payload.first = Some(PublicationFailureV2::BeforeControl);
                    *self.state_healthy = false;
                    return Err(publication_native::closed());
                }
            };
        payload.before = Some(loan.observe_before_v2().await);
        if !matches!(payload.before, Some(Ok(()))) {
            payload.first = Some(if loan.clock_failure_v2().is_some() {
                PublicationFailureV2::BeforeClock
            } else {
                PublicationFailureV2::BeforeControl
            });
        }
        if payload.first.is_none() {
            // Security retains the actual Session currentness Result; this
            // supplement cannot replace the intrinsic Host/Root/time checks.
            payload.currentness = Some(pending_guard());
            if !matches!(payload.currentness, Some(Ok(()))) {
                payload.first = Some(PublicationFailureV2::SessionCurrentness);
            }
        }
        if payload.first.is_none() {
            payload.body =
                Some(payload.publish_body_v2(publisher, descriptor, publication, &mut loan));
            if !matches!(payload.body, Some(Ok(_))) {
                payload.first.get_or_insert(PublicationFailureV2::Native);
            }
        }
        // Each negative destination is independently owed once preparation
        // succeeded. None calls healthy admission or buys replacement time.
        payload.root_post = Some(payload.root_after_owed_v2(publisher));
        if !matches!(payload.root_post, Some(Ok(()))) {
            payload.first.get_or_insert(PublicationFailureV2::RootAfter);
        }
        payload.after = Some(loan.observe_after_owed_v2().await);
        if !matches!(payload.after, Some(Ok(()))) {
            payload
                .first
                .get_or_insert(PublicationFailureV2::AfterControl);
        }
        if payload.first.is_none() {
            payload.disposed = Some(payload.retire_positive_input_v2());
            if !matches!(payload.disposed, Some(Ok(()))) {
                payload.first = Some(PublicationFailureV2::Disposal);
            }
        }
        payload.final_clock = Some(loan.final_clock_after_owed_v2());
        if !matches!(payload.final_clock, Some(Ok(()))) {
            payload
                .first
                .get_or_insert(PublicationFailureV2::FinalClock);
        }
        if payload.first.is_none() {
            let wrote = matches!(
                payload.body,
                Some(Ok(HostCatalogPublicationOutcome::Published))
            );
            payload.disposed = Some(loan.dispose_positive_v2(wrote));
            if !matches!(payload.disposed, Some(Ok(()))) {
                payload.first = Some(if loan.clock_failure_v2().is_some() {
                    PublicationFailureV2::DisposalClock
                } else {
                    PublicationFailureV2::DisposalControl
                });
            }
        }
        if payload.first.is_some() {
            loan.fence_refusal_v2();
            *self.state_healthy = false;
            return Err(publication_native::closed());
        }
        payload.completed = true;
        payload.take_completed_v2()
    }
}

/// Formats the selected actual native cause while its broker keeps custody.
///
/// The view only borrows existing originals; it performs no IO or admission.
#[doc(hidden)]
pub struct HostCatalogPublicationFailureViewV2<'broker> {
    pub(crate) original: Option<&'broker HostCatalogPublicationOriginalV2>,
    pub(crate) control: Option<&'broker Arc<Mutex<crate::plan::HostComponentControlStartupV2>>>,
}

impl std::fmt::Display for HostCatalogPublicationFailureViewV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let selected_control = self.original.is_none()
            || self.original.is_some_and(|owner| {
                owner.payload.completed
                    || matches!(
                        owner.payload.first,
                        Some(
                            PublicationFailureV2::BeforeControl
                                | PublicationFailureV2::AfterControl
                                | PublicationFailureV2::BodyControl
                                | PublicationFailureV2::DisposalControl
                        )
                    )
            });
        if selected_control {
            if let Some(control) = self.control {
                if let Ok(control) = control.lock() {
                    return std::fmt::Display::fmt(control.failure(), formatter);
                }
            }
        }
        if let Some(cause) = self.original.and_then(|owner| owner.failure_v2()) {
            return std::fmt::Display::fmt(cause, formatter);
        }
        formatter.write_str("Host catalog native original is incomplete")
    }
}
