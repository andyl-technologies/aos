//! Fixed SourceProvider activation and original service orchestration.
//!
//! This concrete owner retains genuine startup, listener and Provider custody
//! through the unchanged catalog, handshake, request and completion crossings.
//! Shared fixed-path catalog observations remain nonauthorizing native DATA.

use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

use aos_sandbox_linux::inherited_fd::claim_systemd_activation_descriptor_range;
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketError};
use aos_sandbox_linux::seqpacket::{
    RetainedSeqpacketAdmissionErrorV1, descriptor_subject::DescriptorSubjectSocket,
};
use aos_sandbox::source_provider_startup::{
    OriginalSourceStartupV1, SourceStartupEndedV1, SourceStartupFailureRefV1,
};
use aos_sandbox_source_provider::{
    FixedProviderCatalogProgressV1, FixedProviderIngressProgressV1, FixedProviderOpenReportV1,
    FixedProviderOwnerStatusV1, FixedProviderOwnerV1,
    FixedProviderOriginalStorageOfferProgressV5, FixedProviderOriginalCompletionProgressV5,
    ProviderLedgerError,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};

use aos_sandbox_broker_session_security::ProductionBrokerSessionActivationErrorV1;
use aos_sandbox_broker_session_security::activation_envelope::{
    activation_names, remaining_duration, validate_activation_process,
};
use aos_sandbox_broker_session_security::source_catalog_readback::{
    CatalogReadFailureRefV1, SelectedCatalogPairV1,
    read_current_catalog_manifest_data_v1,
};
pub use aos_sandbox_broker_session_security::ProductionSourceProviderIngressErrorV1;

const LISTENER_NAME: &str = "aos-source-provider";
const LISTENER_PATH: &str = "/run/aos/source-provider/control.sock";

mod selected;
pub use selected::{
    ProductionSelectedSourceProviderFailureRefV1, ProductionSelectedSourceProviderOriginalV1,
};

/// Owns the exact source-provider listener after single-threaded FD adoption.
///
/// Accepted channels are only candidates. The returned fixed owner must
/// complete its protected peer handshake and catalog/journal verification;
/// this type never grants backend or source-effect response authority.
///
/// Deployment supplies one systemd listener named `aos-source-provider` at
/// `/run/aos/source-provider/control.sock` and a root-owned, mode-0700 state
/// directory at `/var/lib/aos/source-provider`. The 520-byte
/// `current-catalog-publication` file and content-addressed row manifest there
/// must be root-owned, mode-0600, regular, and singly linked. The signed
/// publication must match the protected provider journal; pathnames alone do
/// not authorize a session or selected resource.
#[must_use = "retain the fixed listener while admitting provider sessions"]
pub struct ProductionSourceProviderIngressV1 {
    listener: SourceListenerV1,
    selected_accept: Option<Result<DescriptorSubjectSocket, RetainedSeqpacketAdmissionErrorV1>>,
    selected_original: Option<ProductionSelectedSourceProviderOriginalV1>,
    selected_poll: Option<rustix::io::Result<usize>>,
    selected_failure: Option<ProductionSourceProviderIngressErrorV1>,
}

enum SourceListenerV1 {
    Legacy(RecordSubjectListener),
    Selected(OriginalSourceStartupV1),
}

struct SelectedIngressBoundaryV1<'owner> {
    ingress: &'owner mut ProductionSourceProviderIngressV1,
    completed: bool,
}

impl Drop for SelectedIngressBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.ingress.end_selected_initial();
        }
    }
}

impl ProductionSourceProviderIngressV1 {
    /// Creates the inert resident destination for the selected Source INITIAL recipe.
    #[must_use]
    pub fn new_selected_initial() -> Self {
        Self {
            listener: SourceListenerV1::Selected(OriginalSourceStartupV1::new()),
            selected_accept: None,
            selected_original: None,
            selected_poll: None,
            selected_failure: None,
        }
    }

    /// Captures and admits the selected original before runtime, files or threads.
    ///
    /// # Safety
    ///
    /// Requires the exclusive single-threaded original-entry contract of
    /// Core's INITIAL capture, before FD3 adoption or any other descriptor owner.
    ///
    /// # Errors
    ///
    /// Permanently refuses wrong disposition, inventory, kernel/image or listener
    /// admission. The actual typed failure stays in the SAME resident Core owner.
    pub unsafe fn capture_selected_initial_once(&mut self) -> Result<(), SourceStartupEndedV1> {
        let mut boundary = SelectedIngressBoundaryV1 { ingress: self, completed: false };
        let SourceListenerV1::Selected(startup) = &mut boundary.ingress.listener else {
            return Err(SourceStartupEndedV1);
        };
        // SAFETY: forwarding the caller's single-threaded original-entry
        // contract into the SAME Core/Linux capture before any other effects.
        unsafe { startup.capture_initial_once()? };
        startup.admit_listener_once()?;
        boundary.completed = true;
        Ok(())
    }

    /// Lends the actual startup cause without observation, copying or extraction.
    #[must_use]
    pub fn selected_startup_failure(&self) -> Option<SourceStartupFailureRefV1<'_>> {
        match &self.listener {
            SourceListenerV1::Legacy(_) => None,
            SourceListenerV1::Selected(startup) => startup.failure(),
        }
    }

    /// Lends actual retained acceptance custody and its separate shutdown debt.
    #[must_use]
    pub fn selected_accept_failure(&self) -> Option<&RetainedSeqpacketAdmissionErrorV1> {
        self.selected_accept.as_ref().and_then(|result| result.as_ref().err())
    }

    /// Borrows the first actual outer deadline/listener/currentness error.
    #[must_use]
    pub fn selected_failure(&self) -> Option<&ProductionSourceProviderIngressErrorV1> {
        self.selected_failure.as_ref()
    }

    /// Borrows the native readiness outcome independently of its outer refusal.
    #[must_use]
    pub fn selected_poll_outcome(&self) -> Option<&rustix::io::Result<usize>> {
        self.selected_poll.as_ref()
    }

    /// Borrows one-shot listener shutdown debt without implying settlement or Drain.
    #[must_use]
    pub fn selected_listener_shutdown_outcome(&self) -> Option<&rustix::io::Result<()>> {
        match &self.listener {
            SourceListenerV1::Legacy(_) => None,
            SourceListenerV1::Selected(startup) => startup.listener_shutdown_outcome(),
        }
    }

    /// Borrows the original/fresh/pending native image shutdown outcomes.
    #[must_use]
    pub fn selected_image_shutdown_outcomes(&self)
        -> [(Option<&std::io::Result<()>>, Option<&std::io::Result<()>>); 3]
    {
        match &self.listener {
            SourceListenerV1::Legacy(_) => [(None, None); 3],
            SourceListenerV1::Selected(startup) => startup.image_shutdown_outcomes(),
        }
    }

    /// Permanently ends selected startup and every parked accepted original.
    pub fn end_selected_initial(&mut self) {
        if let SourceListenerV1::Selected(startup) = &mut self.listener {
            startup.end();
        }
        if let Some(Ok(socket)) = &mut self.selected_accept {
            socket.close();
        }
        if let Some(original) = &mut self.selected_original {
            original.end_original();
        }
    }

    /// Claims the sole named systemd listener before other descriptors are opened.
    ///
    /// # Safety
    ///
    /// The caller must be the single-threaded startup owner of FD 3. No other
    /// owner, thread, signal handler, or concurrent operation may open, close,
    /// duplicate, or replace it until this call returns.
    ///
    /// # Errors
    ///
    /// Rejects a wrong PID, descriptor count or name, socket type, identity
    /// option, or bound pathname. The claimed descriptor closes on rejection.
    pub unsafe fn adopt_systemd() -> Result<Self, ProductionSourceProviderIngressErrorV1> {
        validate_activation_process(1)?;
        let names = activation_names(1)?;
        validate_listener_names(&names)?;

        // SAFETY: forwarded from the public startup contract after validating
        // the complete one-descriptor activation envelope.
        let descriptors = unsafe { claim_systemd_activation_descriptor_range(0, 1) }
            .map_err(|_| ProductionBrokerSessionActivationErrorV1::Kernel)?
            .into_descriptors();
        let descriptor = descriptors.into_iter().next().ok_or(
            ProductionBrokerSessionActivationErrorV1::Activation(
                "SourceProvider listener descriptor is absent",
            ),
        )?;
        Self::from_owned_listener(descriptor)
    }

    /// Accepts a candidate and opens fixed provider custody and journal state.
    ///
    /// The 520-byte catalog file is a protected locator, not independent
    /// authority. [`FixedProviderOwnerV1::advance_handshake`] verifies its
    /// signature and exact journal head after the peer handshake completes.
    ///
    /// # Errors
    ///
    /// Rejects an expired deadline, changed listener, invalid child identity
    /// options, missing protected catalog file, or fixed-owner admission error.
    pub fn accept_pending_owner(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<
        (FixedProviderOwnerV1, FixedProviderOpenReportV1),
        ProductionSourceProviderIngressErrorV1,
    > {
        self.legacy_listener()?;
        let socket = self.accept_fixed_candidate(deadline_boottime_nanoseconds)?;
        let catalog = read_protected_catalog_publication()?;
        FixedProviderOwnerV1::open_fixed(socket, &catalog).map_err(Into::into)
    }

    /// Parks one genuine fixed-listener candidate in the selected opening.
    ///
    /// No protected catalog or authority file is read here. The selected
    /// opening first validates its actual retained local task role.
    ///
    /// # Errors
    ///
    /// Rejects an expired deadline, changed listener or lower acceptance error.
    /// A lower call that never returns a socket remains a custody exclusion.
    pub fn accept_selected_pending_owner(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<ProductionSelectedSourceProviderOriginalV1, ProductionSourceProviderIngressErrorV1> {
        if matches!(&self.listener, SourceListenerV1::Legacy(_)) {
            let socket = self.accept_fixed_candidate(deadline_boottime_nanoseconds)?;
            return Ok(ProductionSelectedSourceProviderOriginalV1::new(socket, deadline_boottime_nanoseconds));
        }
        let mut boundary = SelectedIngressBoundaryV1 { ingress: self, completed: false };
        if boundary.ingress.selected_failure.is_some() || boundary.ingress.selected_accept.is_some()
            || boundary.ingress.selected_original.is_some()
        {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("selected accept is ended"));
        }
        loop {
            boundary.ingress.check_selected_boundary(deadline_boottime_nanoseconds)?;
            if let Err(cause) = boundary.ingress.wait_until_ready(deadline_boottime_nanoseconds) {
                boundary.ingress.selected_failure = Some(cause);
                return Err(ProductionSourceProviderIngressErrorV1::Catalog("selected wait failed"));
            }
            boundary.ingress.check_selected_boundary(deadline_boottime_nanoseconds)?;
            let SourceListenerV1::Selected(startup) = &mut boundary.ingress.listener else {
                return Err(ProductionSourceProviderIngressErrorV1::Catalog("selected listener association"));
            };
            let listener = startup.listener_mut()
                .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("selected listener is ended"))?;
            // The lower SAME acceptance/admission recipe retains its actual
            // returned socket or failure before any subsequent startup check.
            boundary.ingress.selected_accept = Some(listener.accept_descriptor_subject_retaining());
            if let Some(Ok(socket)) = &mut boundary.ingress.selected_accept {
                socket.begin_original_retention_v1();
            }
            let retry = boundary.ingress.selected_accept.as_ref().is_some_and(|result| {
                result.as_ref().err().is_some_and(|failure| {
                    !failure.retains_descriptor()
                        && matches!(failure.cause(), SeqpacketError::WouldBlock | SeqpacketError::Interrupted)
                })
            });
            if !retry && !matches!(boundary.ingress.selected_accept.as_ref(), Some(Ok(_))) {
                // The actual acceptance cause precedes later shutdown debt.
                // Do not run a fresh observer after a terminal native failure.
                return Err(ProductionSourceProviderIngressErrorV1::Catalog("selected acceptance failed"));
            }
            boundary.ingress.check_selected_boundary(deadline_boottime_nanoseconds)?;
            if retry {
                // Only a nonconsuming no-descriptor result may be superseded.
                boundary.ingress.selected_accept = None;
                continue;
            }
            break;
        }
        // Slot association was checked before taking. The existing opening
        // constructor has an Arc allocation/funding exclusion; there is no IO
        // or fallible postcheck before its returned whole owner is parked.
        match boundary.ingress.selected_accept.take() {
            Some(Ok(socket)) => boundary.ingress.selected_original = Some(
                ProductionSelectedSourceProviderOriginalV1::new(socket, deadline_boottime_nanoseconds),
            ),
            other => {
                boundary.ingress.selected_accept = other;
                return Err(ProductionSourceProviderIngressErrorV1::Catalog("selected socket association"));
            }
        }
        boundary.ingress.check_selected_boundary(deadline_boottime_nanoseconds)?;
        if boundary.ingress.selected_original.is_none() {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("selected original association"));
        }
        match boundary.ingress.selected_original.take() {
            Some(original) => {
                boundary.completed = true;
                Ok(original)
            }
            None => Err(ProductionSourceProviderIngressErrorV1::Catalog("selected original association")),
        }
    }

    fn accept_fixed_candidate(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket, ProductionSourceProviderIngressErrorV1> {
        loop {
            self.wait_until_ready(deadline_boottime_nanoseconds)?;
            let SourceListenerV1::Legacy(listener) = &mut self.listener else {
                return Err(ProductionSourceProviderIngressErrorV1::Catalog("ordinary acceptance requires Legacy"));
            };
            listener.validate_current()?;
            match listener.accept_descriptor_subject() {
                Ok(socket) => return Ok(socket),
                Err(SeqpacketError::WouldBlock | SeqpacketError::Interrupted) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Completes peer authentication and fixed-journal admission by a deadline.
    ///
    /// The security owner keeps the carrier private. A bounded pause between
    /// nonblocking handshake steps avoids exporting a raw socket descriptor to
    /// a poller. Unsupported legacy graphs remain closed.
    ///
    /// # Errors
    ///
    /// Returns an error on deadline expiry, peer or custody failure, catalog
    /// mismatch, journal failure, or unsupported legacy state.
    pub fn accept_authenticated_owner(
        &mut self,
        deadline_boottime_nanoseconds: u64,
    ) -> Result<
        (FixedProviderOwnerV1, FixedProviderOpenReportV1),
        ProductionSourceProviderIngressErrorV1,
    > {
        let (mut owner, report) = self.accept_pending_owner(deadline_boottime_nanoseconds)?;
        loop {
            let remaining = remaining_duration(deadline_boottime_nanoseconds)?;
            match owner.advance_handshake()? {
                FixedProviderOwnerStatusV1::Ready => return Ok((owner, report)),
                FixedProviderOwnerStatusV1::HandshakePending => {
                    std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000)));
                }
                FixedProviderOwnerStatusV1::HeldReadOnly => {
                    return Err(ProviderLedgerError::InvalidTransition(
                        "held profile cannot serve authenticated effects",
                    )
                    .into());
                }
            }
        }
    }

    /// Advances only the catalog-currentness control path on a retained owner.
    ///
    /// The publication is freshly read through the protected fixed path for
    /// each step. The owner verifies its signature and current journal head
    /// before signing or sending a response; effect requests remain rejected.
    ///
    /// # Errors
    ///
    /// Rejects publication drift, stale custody or journal, malformed or
    /// replayed control, peer death, and carrier failure.
    pub fn advance_catalog_currentness(
        &self,
        owner: &mut FixedProviderOwnerV1,
    ) -> Result<FixedProviderCatalogProgressV1, ProductionSourceProviderIngressErrorV1> {
        self.legacy_listener()?.validate_current()?;
        let publication = read_protected_catalog_publication()?;
        owner
            .advance_catalog_currentness(&publication)
            .map_err(Into::into)
    }

    /// Advances catalog control or receives one Acquire or Inventory request.
    ///
    /// The fixed owner brands a source request only after the retained
    /// authenticated carrier receives its exact descriptor-free packet.
    ///
    /// # Errors
    ///
    /// Rejects a retired listener, changed publication, invalid query or
    /// source frame, or lost protected session custody.
    pub fn advance_authenticated_ingress(
        &self,
        owner: &mut FixedProviderOwnerV1,
    ) -> Result<FixedProviderIngressProgressV1, ProductionSourceProviderIngressErrorV1> {
        if owner.original_native_ingress_closed() {
            return Err(
                ProviderLedgerError::InvalidTransition("original ingress is closed").into(),
            );
        }
        let result = (|| {
            self.legacy_listener()?.validate_current()?;
            if owner.original_native_pair_pending() {
                let (publication, rows) = self.read_current_catalog_manifest()?;
                owner
                    .advance_original_native_pair(&publication, &rows)
                    .map_err(Into::into)
            } else {
                let publication = read_protected_catalog_publication()?;
                owner
                    .advance_authenticated_ingress(&publication)
                    .map_err(Into::into)
            }
        })();
        if result.is_err() {
            owner.close_original_native_ingress_after_failure();
        }
        result
    }

    /// Advances the same retained original pair through StoragePrepared only.
    ///
    /// The protected locator and rows are comparison DATA. Only the genuine
    /// owner's retained pair, first clock, selected owner and original writer
    /// can admit this lane. It does not complete, deliver SourceRoot or relay.
    ///
    /// # Errors
    ///
    /// Rejects listener/catalog drift. The caller must retain the returned
    /// first cause with the permanently closed original owner.
    pub fn advance_original_storage_offer(
        &self,
        owner: &mut FixedProviderOwnerV1,
    ) -> Result<FixedProviderOriginalStorageOfferProgressV5, ProductionSourceProviderIngressErrorV1> {
        let result = (|| {
            self.legacy_listener()?.validate_current()?;
            let (publication, rows) = self.read_current_catalog_manifest()?;
            let progress = owner.advance_original_storage_offer_v5(&publication, &rows);
            self.legacy_listener()?.validate_current()?;
            Ok(progress)
        })();
        if result.is_err() {
            owner.close_original_storage_offer_after_failure_v5();
        }
        result
    }

    /// Advances the SAME original pair through local Held and Complete transmission.
    ///
    /// Local transmission is not Root acceptance, relay, settlement or drain.
    /// The original owner and the first outer cause remain resident.
    ///
    /// # Errors
    ///
    /// Rejects listener/catalog drift and closes the original writer before
    /// returning its actual cause. No replacement Session or retry is admitted.
    pub fn advance_original_native_completion(
        &self,
        owner: &mut FixedProviderOwnerV1,
    ) -> Result<FixedProviderOriginalCompletionProgressV5, ProductionSourceProviderIngressErrorV1> {
        let result = (|| {
            self.legacy_listener()?.validate_current()?;
            let (publication, rows) = self.read_current_catalog_manifest()?;
            let progress = owner.advance_original_native_delivery_v5(&publication, &rows);
            self.legacy_listener()?.validate_current()?;
            Ok(progress)
        })();
        if result.is_err() {
            owner.close_original_storage_offer_after_failure_v5();
        }
        result
    }

    /// Reads the content-addressed row catalog under the protected fixed root.
    ///
    /// The returned bytes are nonauthorizing. The fixed owner must compare the
    /// canonical digest and row against its signed publication and journal
    /// snapshot before constructing any Provider-to-Storage plan.
    ///
    /// # Errors
    ///
    /// Rejects missing, replaced, public, malformed, or forked catalog rows.
    pub fn read_current_catalog_manifest(
        &self,
    ) -> Result<(Vec<u8>, Vec<u8>), ProductionSourceProviderIngressErrorV1> {
        self.legacy_listener()?.validate_current()?;
        read_current_catalog_manifest_data_v1()
    }

    fn from_owned_listener(
        descriptor: OwnedFd,
    ) -> Result<Self, ProductionSourceProviderIngressErrorV1> {
        let listener = RecordSubjectListener::from_owned(descriptor)?;
        listener.require_local_filesystem_path(Path::new(LISTENER_PATH))?;
        Ok(Self {
            listener: SourceListenerV1::Legacy(listener),
            selected_accept: None,
            selected_original: None,
            selected_poll: None,
            selected_failure: None,
        })
    }

    fn wait_until_ready(
        &mut self,
        deadline: u64,
    ) -> Result<(), ProductionSourceProviderIngressErrorV1> {
        let remaining = remaining_duration(deadline)?;
        let timeout = Timespec {
            tv_sec: i64::try_from(remaining / 1_000_000_000)
                .map_err(|_| ProductionBrokerSessionActivationErrorV1::Deadline)?,
            tv_nsec: i64::try_from(remaining % 1_000_000_000)
                .map_err(|_| ProductionBrokerSessionActivationErrorV1::Deadline)?,
        };
        let selected = matches!(&self.listener, SourceListenerV1::Selected(_));
        let listener = match &mut self.listener {
            SourceListenerV1::Legacy(listener) => listener,
            SourceListenerV1::Selected(startup) => startup.listener_mut()
                .map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog("selected listener is ended"))?,
        };
        let mut poll_fd = [PollFd::from_borrowed_fd(listener.as_fd(), PollFlags::IN)];
        if selected {
            self.selected_poll = Some(poll(&mut poll_fd, Some(&timeout)));
            return match self.selected_poll.as_ref() {
                Some(Ok(0)) => Err(ProductionBrokerSessionActivationErrorV1::Deadline.into()),
                Some(Ok(_)) | Some(Err(rustix::io::Errno::INTR)) => Ok(()),
                _ => Err(ProductionBrokerSessionActivationErrorV1::Kernel.into()),
            };
        }
        match poll(&mut poll_fd, Some(&timeout)) {
            Ok(0) => Err(ProductionBrokerSessionActivationErrorV1::Deadline.into()),
            Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
            Err(_) => Err(ProductionBrokerSessionActivationErrorV1::Kernel.into()),
        }
    }

    fn legacy_listener(&self) -> Result<&RecordSubjectListener, ProductionSourceProviderIngressErrorV1> {
        match &self.listener {
            SourceListenerV1::Legacy(listener) => Ok(listener),
            SourceListenerV1::Selected(startup) => {
                // Shared negative access can end this !Sync owner, but cannot
                // observe, recover, lend a FD or execute a selected effect.
                startup.end();
                Err(ProductionSourceProviderIngressErrorV1::Catalog(
                    "ordinary route cannot borrow selected INITIAL custody",
                ))
            }
        }
    }

    pub(super) fn check_selected_boundary(&mut self, deadline: u64)
        -> Result<(), ProductionSourceProviderIngressErrorV1>
    {
        if let SourceListenerV1::Legacy(listener) = &self.listener {
            remaining_duration(deadline)?;
            listener.validate_current()?;
            return Ok(());
        }
        if self.selected_failure.is_some() {
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("selected ingress is ended"));
        }
        let result = (|| {
            remaining_duration(deadline)?;
            match &mut self.listener {
                SourceListenerV1::Legacy(listener) => listener.validate_current()?,
                SourceListenerV1::Selected(startup) => {
                    startup.recheck().map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog(
                        "selected INITIAL bookend failed",
                    ))?;
                    // Slow image observation consumes the SAME original D.
                    remaining_duration(deadline)?;
                    startup.listener_mut().map_err(|_| ProductionSourceProviderIngressErrorV1::Catalog(
                        "selected listener is ended",
                    ))?.validate_current()?;
                    remaining_duration(deadline)?;
                }
            }
            Ok(())
        })();
        if let Err(cause) = result {
            self.selected_failure = Some(cause);
            self.end_selected_initial();
            return Err(ProductionSourceProviderIngressErrorV1::Catalog("selected boundary failed"));
        }
        Ok(())
    }

    pub(super) fn check_initial_only(&mut self, deadline: u64)
        -> Result<(), ProductionSourceProviderIngressErrorV1>
    {
        if matches!(&self.listener, SourceListenerV1::Selected(_)) {
            self.check_selected_boundary(deadline)?;
        }
        Ok(())
    }
}

impl Drop for ProductionSourceProviderIngressV1 {
    fn drop(&mut self) {
        self.end_selected_initial();
    }
}

fn validate_listener_names(
    names: &[String],
) -> Result<(), ProductionBrokerSessionActivationErrorV1> {
    if names.len() != 1 || names[0] != LISTENER_NAME {
        return Err(ProductionBrokerSessionActivationErrorV1::Activation(
            "SourceProvider descriptor name differs from the fixed listener",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_name_rejects_substitution_and_extra_descriptors() {
        assert!(validate_listener_names(&[LISTENER_NAME.to_owned()]).is_ok());
        assert!(validate_listener_names(&["aos-sandbox-mount".to_owned()]).is_err());
        assert!(validate_listener_names(&[]).is_err());
        assert!(
            validate_listener_names(&[LISTENER_NAME.to_owned(), LISTENER_NAME.to_owned()]).is_err()
        );
    }

    #[test]
    fn foreign_listener_path_is_rejected_before_owner_admission() {
        let temporary = tempfile::tempdir().expect("temporary socket directory");
        let path = temporary.path().join("source-provider.sock");
        let listener = RecordSubjectListener::bind(&path, 1).expect("configured listener");
        assert!(
            listener
                .require_local_filesystem_path(Path::new(LISTENER_PATH))
                .is_err()
        );
    }

}
