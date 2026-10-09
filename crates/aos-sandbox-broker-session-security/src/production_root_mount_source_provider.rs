//! Fixed RootMount connection to the separate SourceProvider service.
//!
//! This connector retains the configured sequenced-packet carrier inside the
//! protected RootMount session owner. Establishing a session grants no source
//! operation or backend authority; the Mount source graph remains a separate
//! admission boundary.

use std::path::Path;
use std::time::Duration;

use aos_sandbox::MountSourceConsumptionJournalAuthorityV1;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_linux::seqpacket::descriptor_subject::DescriptorSubjectSocket;
use aos_sandbox_mount::MountError;
use aos_sandbox_mount::broker::MountBroker;
use aos_sandbox_mount::worker::MountWorker;
use aos_sandbox_source_provider_protocol::SourceProviderMethod;
use aos_sandbox_source_provider_security::{
    AuthenticatedRootMountRecoveryObservationV2, RootMountSourceProviderHandshakeStatusV1,
    RootMountSourceProviderOwnerV1, SourceProviderSecurityError,
    SelectedRootMountSourceProviderOwnerV1, SelectedSourceProviderFailureRefV1,
};

use crate::ProductionBrokerSessionActivationErrorV1;
use crate::production_activation::remaining_duration;

const FIXED_PROVIDER_SOCKET: &str = "/run/aos/source-provider/control.sock";

/// Retains fixed selected RootMount connection, opening and HELLO custody.
///
/// The genuine selected self/custody checks run before protected file reads.
/// PID1 establishment and the signed Source SCM task stay distinct. This owner
/// cannot supply the still-missing Core/Linux initial-table image bridge; it
/// preserves the actual refusal instead of falling back to the ordinary role.
pub struct ProductionSelectedRootMountSourceProviderV1 {
    socket: Option<Result<DescriptorSubjectSocket, SeqpacketError>>,
    owner: Option<SelectedRootMountSourceProviderOwnerV1>,
    deadline: u64,
    attempted: bool,
    ended: bool,
    first_deadline_failure: Option<ProductionBrokerSessionActivationErrorV1>,
    first_stage: Option<SelectedRootOpeningStageV1>,
    catalog: crate::production_source_provider_catalog::SelectedMountCatalogCredentialsV1,
    shutdown_failure: Option<std::io::Error>,
    release_effect: Option<Result<(), MountError>>,
}

#[derive(Clone, Copy)]
enum SelectedRootOpeningStageV1 {
    Socket,
    Security,
    Deadline,
    Catalog,
    ReleaseEffect,
}

impl std::fmt::Debug for ProductionSelectedRootMountSourceProviderV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProductionSelectedRootMountSourceProviderV1([original opening])")
    }
}

/// Lends an actual selected connection, opening or deadline refusal.
pub enum ProductionSelectedRootMountSourceProviderFailureV1<'owner> {
    /// The returned native connection error remains resident.
    Socket(&'owner SeqpacketError),
    /// The selected opening retains its original typed cause and prefixes.
    Security(SelectedSourceProviderFailureRefV1<'owner>),
    /// The original absolute boot-time deadline failed.
    Deadline(&'owner ProductionBrokerSessionActivationErrorV1),
    /// The fixed delivered catalog reader retains its original native cause.
    Catalog(crate::production_source_provider_catalog::SelectedSourceProviderCatalogFailureRefV1<'owner>),
    /// The genuine Release effect loan retains its returned currentness cause.
    ReleaseEffect(&'owner MountError),
    /// The opening ended without a returned cause, including unwind.
    Ended,
}

impl std::fmt::Debug for ProductionSelectedRootMountSourceProviderFailureV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Socket(_) => "ProductionSelectedRootMountSourceProviderFailureV1::Socket",
            Self::Security(_) => "ProductionSelectedRootMountSourceProviderFailureV1::Security",
            Self::Deadline(_) => "ProductionSelectedRootMountSourceProviderFailureV1::Deadline",
            Self::Catalog(_) => "ProductionSelectedRootMountSourceProviderFailureV1::Catalog",
            Self::ReleaseEffect(_) => "ProductionSelectedRootMountSourceProviderFailureV1::ReleaseEffect",
            Self::Ended => "ProductionSelectedRootMountSourceProviderFailureV1::Ended",
        })
    }
}

struct SelectedRootOpeningBoundaryV1<'owner> {
    owner: &'owner mut ProductionSelectedRootMountSourceProviderV1,
    completed: bool,
}

impl Drop for SelectedRootOpeningBoundaryV1<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.end();
        }
    }
}

impl ProductionSelectedRootMountSourceProviderV1 {
    /// Creates an inert, fixed selected opening with its original deadline.
    #[must_use]
    pub fn new(deadline_boottime_nanoseconds: u64) -> Self {
        Self {
            socket: None,
            owner: None,
            deadline: deadline_boottime_nanoseconds,
            attempted: false,
            ended: false,
            first_deadline_failure: None,
            first_stage: None,
            catalog: Default::default(),
            shutdown_failure: None,
            release_effect: None,
        }
    }

    /// Connects and opens once, retaining every returned owner before checks.
    ///
    /// # Errors
    ///
    /// Lends the actual first socket, selected-custody, transcript or deadline
    /// refusal. It never reconnects, renews or switches to ordinary custody.
    pub fn connect_once(
        &mut self,
    ) -> Result<(), ProductionSelectedRootMountSourceProviderFailureV1<'_>> {
        if self.attempted || self.ended {
            self.end();
            return Err(self.failure_or_ended());
        }
        self.attempted = true;

        let succeeded = {
            let mut boundary = SelectedRootOpeningBoundaryV1 {
                owner: self,
                completed: false,
            };
            let succeeded = boundary.owner.connect_inner();
            boundary.completed = succeeded;
            succeeded
        };
        if succeeded {
            Ok(())
        } else {
            Err(self.failure_or_ended())
        }
    }

    fn check_deadline(&mut self) -> bool {
        match remaining_duration(self.deadline) {
            Ok(_) => true,
            Err(cause) => {
                if self.first_deadline_failure.is_none() {
                    self.first_deadline_failure = Some(cause);
                }
                self.note_failure(SelectedRootOpeningStageV1::Deadline);
                self.end();
                false
            }
        }
    }

    fn note_failure(&mut self, stage: SelectedRootOpeningStageV1) {
        if self.first_stage.is_none() {
            self.first_stage = Some(stage);
        }
    }

    fn connect_inner(&mut self) -> bool {
        if !self.check_deadline() {
            return false;
        }
        self.socket = Some(DescriptorSubjectSocket::connect(Path::new(FIXED_PROVIDER_SOCKET)));
        if !matches!(self.socket, Some(Ok(_))) {
            self.note_failure(SelectedRootOpeningStageV1::Socket);
            return false;
        }
        if !self.check_deadline() {
            return false;
        }

        // All slots are checked before the original is moved. Construction
        // parks that same socket immediately; its Arc funding boundary remains
        // explicit, as do lower connect prefixes that never returned here.
        if self.owner.is_some() {
            return false;
        }
        match self.socket.take() {
            Some(Ok(socket)) => {
                self.owner = Some(RootMountSourceProviderOwnerV1::begin_fixed_selected_mount_source(socket));
            }
            other => {
                self.socket = other;
                return false;
            }
        }
        let Some(owner) = self.owner.as_mut() else {
            return false;
        };
        if owner.open_once().is_err() {
            self.note_failure(SelectedRootOpeningStageV1::Security);
            return false;
        }

        loop {
            if !self.check_deadline() {
                return false;
            }
            let progress = match self.owner.as_mut() {
                Some(owner) => owner.advance_handshake(),
                None => return false,
            };
            let current = match progress {
                Ok(RootMountSourceProviderHandshakeStatusV1::Current) => true,
                Ok(RootMountSourceProviderHandshakeStatusV1::Pending) => false,
                Err(_) => {
                    self.note_failure(SelectedRootOpeningStageV1::Security);
                    return false;
                }
            };
            if !self.check_deadline() {
                return false;
            }
            if current {
                return true;
            }
            // This is the existing bounded fixed handshake backpressure wait,
            // not a renewed timeout or a second receive/supervisor engine.
            std::thread::sleep(Duration::from_nanos(2_000_000));
        }
    }

    /// Lends only the genuine current Session while retaining its whole owner.
    pub(crate) fn borrow_current_session(
        &mut self,
    ) -> Option<&mut aos_sandbox_source_provider_security::CurrentRootMountSourceProviderSessionV1> {
        if self.ended || !self.check_deadline() {
            return None;
        }
        let owner = self.owner.as_mut()?;
        match owner.borrow_current_session() {
            Ok(Some(session)) => Some(session),
            _ => {
                self.first_stage.get_or_insert(SelectedRootOpeningStageV1::Security);
                None
            }
        }
    }

    pub(crate) fn read_catalog_once(&mut self) -> bool {
        let mut boundary = SelectedRootOpeningBoundaryV1 { owner: self, completed: false };
        let succeeded = if !boundary.owner.current_session_is_present() {
            false
        } else if !boundary.owner.catalog.read_once() {
            boundary.owner.note_failure(SelectedRootOpeningStageV1::Catalog);
            false
        } else {
            boundary.owner.current_session_is_present()
        };
        boundary.completed = succeeded;
        succeeded
    }

    pub(crate) fn recheck_catalog(&mut self) -> bool {
        let mut boundary = SelectedRootOpeningBoundaryV1 { owner: self, completed: false };
        let succeeded = if !boundary.owner.current_session_is_present() {
            false
        } else if !boundary.owner.catalog.recheck() {
            boundary.owner.note_failure(SelectedRootOpeningStageV1::Catalog);
            false
        } else {
            boundary.owner.current_session_is_present()
        };
        boundary.completed = succeeded;
        succeeded
    }

    fn current_session_is_present(&mut self) -> bool {
        if self.ended || !self.check_deadline() {
            return false;
        }
        if matches!(self.owner.as_mut().map(|owner| owner.borrow_current_session()), Some(Ok(Some(_)))) {
            true
        } else {
            self.note_failure(SelectedRootOpeningStageV1::Security);
            false
        }
    }

    /// Rechecks the genuine catalog and Session under the fixed intake cut.
    pub(crate) fn recheck_catalog_for_original_release_intake(&mut self, cut: u64) -> bool {
        if self.ended || self.first_stage.is_some() {
            return false;
        }
        let mut boundary = SelectedRootOpeningBoundaryV1 { owner: self, completed: false };
        let before = boundary.owner.release_session_is_present();
        let catalog = boundary.owner.catalog.recheck();
        if !catalog {
            boundary.owner.note_failure(SelectedRootOpeningStageV1::Catalog);
        }
        let after = boundary.owner.release_session_is_present();
        let clock = match remaining_duration(cut) {
            Ok(_) => true,
            Err(cause) => {
                if boundary.owner.first_deadline_failure.is_none() {
                    boundary.owner.first_deadline_failure = Some(cause);
                }
                boundary.owner.note_failure(SelectedRootOpeningStageV1::Deadline);
                false
            }
        };
        boundary.completed = before && catalog && after && clock;
        boundary.completed
    }

    /// Rechecks the same catalog and owner under the newly admitted Release.
    ///
    /// The historical opening cutoff remains unchanged. Only this closed
    /// purpose uses the actual committed Release effect's current clock.
    pub(crate) fn recheck_catalog_for_original_release(
        &mut self,
        effect: &mut aos_sandbox_mount::broker::OriginalMountReleaseEffectLoanV1<'_>,
    ) -> bool {
        if self.ended || self.first_stage.is_some() {
            return false;
        }
        let mut boundary = SelectedRootOpeningBoundaryV1 { owner: self, completed: false };
        if !boundary.owner.check_release_effect(effect)
            || !boundary.owner.release_session_is_present()
        {
            return false;
        }
        if !boundary.owner.catalog.recheck() {
            boundary.owner.note_failure(SelectedRootOpeningStageV1::Catalog);
            return false;
        }
        let current = boundary.owner.release_session_is_present();
        let clock = boundary.owner.check_release_effect(effect);
        boundary.completed = current && clock;
        boundary.completed
    }

    /// Lends the genuine Session only after the short Release-effect bookend.
    pub(crate) fn borrow_current_session_for_original_release(
        &mut self,
        effect: &mut aos_sandbox_mount::broker::OriginalMountReleaseEffectLoanV1<'_>,
    ) -> Option<&mut aos_sandbox_source_provider_security::CurrentRootMountSourceProviderSessionV1> {
        if self.ended || self.first_stage.is_some()
            || !self.check_release_effect(effect)
            || !self.release_session_is_present()
            || !self.check_release_effect(effect)
        {
            self.end();
            return None;
        }
        if !self.catalog.recheck() {
            self.note_failure(SelectedRootOpeningStageV1::Catalog);
            self.end();
            return None;
        }
        if !self.release_session_is_present() || !self.check_release_effect(effect) {
            self.end();
            return None;
        }
        let first_stage = &mut self.first_stage;
        let ended = &mut self.ended;
        let owner = self.owner.as_mut()?;
        match owner.borrow_current_session() {
            Ok(Some(session)) => Some(session),
            Ok(None) | Err(_) => {
                // The lower owner retains and closes on its actual refusal.
                // Do not erase that cause behind the outer ended fallback.
                if first_stage.is_none() {
                    *first_stage = Some(SelectedRootOpeningStageV1::Security);
                }
                *ended = true;
                None
            }
        }
    }

    fn check_release_effect(
        &mut self,
        effect: &mut aos_sandbox_mount::broker::OriginalMountReleaseEffectLoanV1<'_>,
    ) -> bool {
        self.release_effect = Some(effect.check_before_release_effect());
        if matches!(self.release_effect, Some(Ok(()))) {
            true
        } else {
            self.note_failure(SelectedRootOpeningStageV1::ReleaseEffect);
            false
        }
    }

    fn release_session_is_present(&mut self) -> bool {
        if matches!(self.owner.as_mut().map(|owner| owner.borrow_current_session()), Some(Ok(Some(_)))) {
            true
        } else {
            self.note_failure(SelectedRootOpeningStageV1::Security);
            false
        }
    }

    pub(crate) fn catalog_pair(&self) -> Option<(&[u8], &[u8])> {
        if self.ended { None } else { self.catalog.pair() }
    }

    /// Lends the first failure without I/O or recovery.
    #[must_use]
    pub fn failure(&self) -> Option<ProductionSelectedRootMountSourceProviderFailureV1<'_>> {
        let failure = match self.first_stage {
            Some(SelectedRootOpeningStageV1::Socket) => self.socket.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(ProductionSelectedRootMountSourceProviderFailureV1::Socket),
            Some(SelectedRootOpeningStageV1::Security) => self.owner.as_ref()
                .and_then(SelectedRootMountSourceProviderOwnerV1::failure)
                .map(ProductionSelectedRootMountSourceProviderFailureV1::Security),
            Some(SelectedRootOpeningStageV1::Deadline) => self.first_deadline_failure.as_ref()
                .map(ProductionSelectedRootMountSourceProviderFailureV1::Deadline),
            Some(SelectedRootOpeningStageV1::Catalog) => self.catalog.failure()
                .map(ProductionSelectedRootMountSourceProviderFailureV1::Catalog),
            Some(SelectedRootOpeningStageV1::ReleaseEffect) => self.release_effect.as_ref()
                .and_then(|result| result.as_ref().err())
                .map(ProductionSelectedRootMountSourceProviderFailureV1::ReleaseEffect),
            None => None,
        };
        failure.or_else(|| self.ended.then_some(ProductionSelectedRootMountSourceProviderFailureV1::Ended))
    }

    fn failure_or_ended(&self) -> ProductionSelectedRootMountSourceProviderFailureV1<'_> {
        self.failure().unwrap_or(ProductionSelectedRootMountSourceProviderFailureV1::Ended)
    }

    /// Permanently closes the selected original queue before prefixes drop.
    pub fn end(&mut self) {
        self.ended = true;
        if let Some(owner) = self.owner.as_mut() {
            owner.end();
        }
        if let Some(Ok(socket)) = self.socket.as_ref() {
            if let Ok(original) = socket.as_fd() {
                if let Err(cause) = rustix::net::shutdown(original, rustix::net::Shutdown::Both) {
                    if self.shutdown_failure.is_none() { self.shutdown_failure = Some(cause.into()); }
                }
            }
        }
    }

    /// Lends failed native shutdown separately from original admission failure.
    /// This is debt only, never transport or descendant-drain evidence.
    #[must_use]
    pub fn shutdown_failure(&self) -> Option<&std::io::Error> {
        self.shutdown_failure.as_ref()
    }
}

impl Drop for ProductionSelectedRootMountSourceProviderV1 {
    fn drop(&mut self) {
        self.end();
    }
}

/// Reports failure before RootMount can retain an authenticated provider session.
#[derive(Debug, thiserror::Error)]
pub enum ProductionRootMountSourceProviderErrorV1 {
    /// The exact configured provider socket was unavailable or invalid.
    #[error("RootMount SourceProvider socket failed: {0}")]
    Socket(#[from] SeqpacketError),
    /// Fixed RootMount custody, peer, or handshake authentication failed.
    #[error("RootMount SourceProvider authentication failed: {0}")]
    Security(#[from] SourceProviderSecurityError),
    /// The configured handshake deadline elapsed or the kernel clock was invalid.
    #[error("RootMount SourceProvider handshake deadline failed: {0}")]
    Deadline(#[from] ProductionBrokerSessionActivationErrorV1),
    /// The sole protected Mount journal could not be lent or verified.
    #[error("RootMount SourceProvider recovery failed: {0}")]
    Mount(#[from] MountError),
}

/// Connects RootMount to the fixed SourceProvider socket and authenticates it.
///
/// The returned owner alone retains the carrier and current session. The
/// service's protected execution identity and signed hello are checked by the
/// owner; a successful filesystem connection is never treated as authority.
///
/// # Errors
///
/// Returns an error for an invalid fixed socket, missing protected custody,
/// peer or signed transcript mismatch, or an expired boot-time deadline.
pub fn connect_authenticated_fixed_source_provider(
    deadline_boottime_nanoseconds: u64,
) -> Result<RootMountSourceProviderOwnerV1, ProductionRootMountSourceProviderErrorV1> {
    let socket = DescriptorSubjectSocket::connect(Path::new(FIXED_PROVIDER_SOCKET))?;
    let mut owner = RootMountSourceProviderOwnerV1::open_fixed(socket)?;

    loop {
        let remaining = remaining_duration(deadline_boottime_nanoseconds)?;
        match owner.advance_handshake()? {
            RootMountSourceProviderHandshakeStatusV1::Current => {
                remaining_duration(deadline_boottime_nanoseconds)?;
                return Ok(owner);
            }
            RootMountSourceProviderHandshakeStatusV1::Pending => {
                std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000)));
            }
        }
    }
}

/// Advances the original pending Acquire query under Mount's sole journal claim.
///
/// The returned observation is descriptor-free. LocalLive remains pending;
/// native terminal evidence requires a separate protected Mount settlement.
/// `Ok(None)` means the handshake or nonblocking exchange is still pending.
///
/// # Errors
///
/// Rejects a stale journal, changed original attempt, retired peer, or
/// malformed/downgraded Provider answer.
pub fn advance_authenticated_pending_acquire_recovery(
    owner: &mut RootMountSourceProviderOwnerV1,
    journal: &MountSourceConsumptionJournalAuthorityV1<'_>,
    acquisition_id: ObjectDigest,
) -> Result<Option<AuthenticatedRootMountRecoveryObservationV2>, SourceProviderSecurityError> {
    match owner.with_current_session(|session| {
        session.advance_pending_acquire_recovery_v1(journal, acquisition_id)
    })? {
        Some(progress) => progress,
        None => Ok(None),
    }
}

/// Observes every original pending Acquire after a Mount broker restart.
///
/// The broker lends its sole protected journal for the entire scan and each
/// AOSSPR01 exchange. Only an exact native no-dispatch terminal proof may
/// settle the old attempt under a second protected Mount journal claim.
/// The authenticated session remains owned by `owner` after this function.
///
/// # Errors
///
/// Fails closed for a changed protected graph, retired peer, invalid signed
/// answer, or expired boot-time deadline. The caller should restart rather
/// than create a successor attempt or serve a source through this state.
pub fn observe_original_pending_acquires<W: MountWorker>(
    owner: &mut RootMountSourceProviderOwnerV1,
    broker: &mut MountBroker<W>,
    deadline_boottime_nanoseconds: u64,
) -> Result<usize, ProductionRootMountSourceProviderErrorV1> {
    let observed = broker.with_fixed_source_acquisition_owner(|source| {
        let pending = source
            .with_consumption_authority(|table, _| Ok(table.original_pending_acquire_ids()))?;
        for acquisition_id in &pending {
            loop {
                let remaining = remaining_duration(deadline_boottime_nanoseconds)
                    .map_err(|error| MountError::State(error.to_string()))?;
                let observation = source.with_consumption_authority(|_, journal| {
                    advance_authenticated_pending_acquire_recovery(
                        owner,
                        journal,
                        ObjectDigest::from_bytes(*acquisition_id),
                    )
                    .map_err(|error| MountError::State(error.to_string()))
                })?;
                match observation {
                    Some(AuthenticatedRootMountRecoveryObservationV2::NativeNoDispatch(proof)) => {
                        source.with_source_acquisition_authority(|table, journal| {
                            journal.with_authority(|protected| {
                                table.settle_native_no_dispatch_recovery_v2(
                                    protected,
                                    ObjectDigest::from_bytes(*acquisition_id),
                                    proof,
                                )
                            })
                        })?;
                        break;
                    }
                    Some(AuthenticatedRootMountRecoveryObservationV2::LocalLive(_)) => {
                        if source.with_consumption_authority(|table, _| {
                            Ok(table.original_superseded_acquire_v2(*acquisition_id))
                        })? {
                            return Err(MountError::State(
                                "superseded Acquire requires exact terminal Provider settlement"
                                    .to_owned(),
                            ));
                        }
                        break;
                    }
                    None => std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000))),
                }
            }
        }
        Ok(pending.len())
    })?;
    Ok(observed)
}

/// Obtains one fresh Mount source inventory through the separate provider daemon.
///
/// The fixed Mount journal reserves the signed request before it reaches the
/// authenticated carrier. Only a descriptor-free, exact signed Inventory
/// reply can advance the source graph. An unanswered send leaves a Reserved
/// attempt for explicit cold recovery; it never authorizes retransmission as
/// a new request or a terminal inventory response.
///
/// # Errors
///
/// Rejects an unresolved source graph, stale session or journal, invalid
/// descriptor or signature, and any unanswered or ambiguous request at the
/// absolute boot-time deadline.
pub fn observe_remote_source_inventory<W: MountWorker>(
    owner: &mut RootMountSourceProviderOwnerV1,
    broker: &mut MountBroker<W>,
    deadline_boottime_nanoseconds: u64,
) -> Result<Vec<u8>, ProductionRootMountSourceProviderErrorV1> {
    let response = broker.with_fixed_source_acquisition_owner(|source| {
        if let Err(error) = source.prepare_and_send_remote_inventory(owner) {
            if !source.has_pending_provider_send() {
                return Err(error);
            }
        }
        while source.has_pending_provider_send() {
            let remaining = remaining_duration(deadline_boottime_nanoseconds)
                .map_err(|error| MountError::State(error.to_string()))?;
            match source.retry_pending_provider_send(owner) {
                Ok(()) => break,
                Err(_) => std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000))),
            }
        }
        loop {
            let remaining = remaining_duration(deadline_boottime_nanoseconds)
                .map_err(|error| MountError::State(error.to_string()))?;
            match source.advance_remote_inventory(owner)? {
                true => {
                    let inventory = source.encode_current_inventory()?;
                    remaining_duration(deadline_boottime_nanoseconds)
                        .map_err(|error| MountError::State(error.to_string()))?;
                    return Ok(inventory);
                }
                false => std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000))),
            }
        }
    })?;
    Ok(response)
}

/// Recovers one old Reserved Inventory from Provider's protected journal.
///
/// This is a non-effect recovery operation. It never resends the old signed
/// request, authorizes Acquire or Release, or activates source-method dispatch.
///
/// # Errors
///
/// Rejects signed Unavailable, changed protected history, ambiguous commit,
/// or a response not completed before the absolute boot-time deadline.
pub fn observe_remote_cold_source_inventory<W: MountWorker>(
    owner: &mut RootMountSourceProviderOwnerV1,
    broker: &mut MountBroker<W>,
    deadline_boottime_nanoseconds: u64,
) -> Result<Vec<u8>, ProductionRootMountSourceProviderErrorV1> {
    let response = broker.with_fixed_source_acquisition_owner(|source| {
        loop {
            let remaining = remaining_duration(deadline_boottime_nanoseconds)
                .map_err(|error| MountError::State(error.to_string()))?;
            match source.advance_remote_cold_inventory_readback(owner)? {
                true => {
                    let inventory = source.encode_current_inventory()?;
                    remaining_duration(deadline_boottime_nanoseconds)
                        .map_err(|error| MountError::State(error.to_string()))?;
                    return Ok(inventory);
                }
                false => std::thread::sleep(Duration::from_nanos(remaining.min(2_000_000))),
            }
        }
    })?;
    Ok(response)
}

/// Recovers consecutive old Reserved Inventory barriers before Mount serves requests.
///
/// The oldest protected attempt selects each readback. A different method or
/// already-consumed disposition remains blocked for its own explicit recovery
/// path; this dispatcher never sends a new Inventory or invokes Apply.
///
/// # Errors
///
/// Rejects an unsupported cold barrier, unauthenticated readback, ambiguous
/// Mount commit, or expired absolute boot-time deadline.
pub fn recover_reserved_remote_inventories<W: MountWorker>(
    owner: &mut RootMountSourceProviderOwnerV1,
    broker: &mut MountBroker<W>,
    deadline_boottime_nanoseconds: u64,
) -> Result<usize, ProductionRootMountSourceProviderErrorV1> {
    broker.with_fixed_source_acquisition_owner(|source| {
        source.qualify_inventory_only_cold_recovery().map(|_| ())
    })?;

    let mut recovered = 0usize;
    loop {
        let reserved_inventory = broker.with_fixed_source_acquisition_owner(|source| {
            if !source.has_cold_provider_recovery() {
                return Ok(false);
            }
            let signed = source.cold_reserved_provider_request()?;
            if signed.method() != SourceProviderMethod::Inventory {
                return Err(MountError::State(
                    "oldest cold SourceProvider attempt needs method-specific recovery".to_owned(),
                ));
            }
            Ok(true)
        })?;
        if !reserved_inventory {
            return Ok(recovered);
        }

        observe_remote_cold_source_inventory(owner, broker, deadline_boottime_nanoseconds)?;
        recovered += 1;
    }
}
