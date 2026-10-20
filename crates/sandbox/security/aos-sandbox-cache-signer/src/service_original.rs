//! Owns Cache's private monotone stages under its genuine fixed-service F.
//!
//! The shared receiver alone captures the actual Cache two-entry PID1 original,
//! role3 Parent subdivision and installed finite containment. Only this private
//! owner derives its purpose's complete geometry before native entry. No public
//! budget, account, key, descriptor or role factory exists in this module.

mod challenge;
mod current_clock;
mod current_journals;
mod current_models;
mod current_objects;
mod current_proof;
mod journal_prefix;
mod journal_semantic;
mod lifetime;
mod object_view;
mod physical_manifest;
mod reply;
mod request;
mod root_interval;

use std::error::Error;
use std::mem::size_of;
use std::os::fd::OwnedFd;

use aos_sandbox_broker::receiving::{
    FixedServiceCurrentnessSampleV1, FixedServiceReceivingCaptureV1, FixedSignerListenerClosedV1,
    FixedSignerListenerOriginalV1, RepresentationDemandDebitV1 as _, RootPeerImageObservationsV1,
    RootPeerImagesClosedV1, RootProfileOriginalCaptureV1,
};
use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};

use crate::cache_signer_credential::{CacheSignerCredentialCaptureV1, CacheSignerCredentialV2};

#[derive(Clone, Copy, Debug, Default, thiserror::Error)]
#[error("the original private Cache signer stage is unavailable")]
pub(crate) struct CacheSignerReceivingClosedV1;

const CLOSED: CacheSignerReceivingClosedV1 = CacheSignerReceivingClosedV1;
type Common = FixedServiceReceivingCaptureV1<CacheSignerReceivingClosedV1>;
type Sample = FixedServiceCurrentnessSampleV1<CacheSignerReceivingClosedV1>;

#[derive(Clone, Copy)]
enum First {
    HeaderFunding,
    HeaderBefore,
    HeaderClock,
    HeaderReadiness,
    HeaderDeadline,
    Header,
    HeaderAfter,
    HeaderAfterDeadline,
    RootPurposeFunding,
    RootChallenge,
    RootPurposeBefore,
    RootPeerBefore,
    RootBinding,
    JoinFunding,
    JoinBefore,
    ControllerRequest,
    JoinBinding,
    JoinAfter,
    JoinLate,
    CurrentClockFunding,
    CurrentClockBefore,
    CurrentClock,
    CurrentClockAfter,
    CurrentObjects,
    CurrentJournals,
    CurrentModels,
    CurrentProof,
    ControllerRequestAfter,
    RootRequestAfter,
    RootPeerAfter,
    RootPurposeAfter,
    RootPurposeLate,
    RootSettlement,
    Closed,
}

#[derive(Clone, Copy)]
enum StartupFirst {
    Common,
    CredentialFunding,
    CredentialBefore,
    Credentials,
    CredentialAfter,
    CredentialRetirement,
    ProfileFunding,
    ProfileBefore,
    Profile,
    ProfileAfter,
    Configuration,
    ImagesFunding,
    ImagesBefore,
    Images,
    ImagesAfter,
    ListenerFunding,
    ListenerBefore,
    Listener,
    ListenerAfter,
    Closed,
}

#[derive(Default)]
struct StageOriginals {
    demand: Option<Result<ResourceVector, AccountingError>>,
    physical: Option<Result<(), AccountingError>>,
    debit: Option<Result<(), CacheSignerReceivingClosedV1>>,
    before: Sample,
    before_result: Option<Result<(), CacheSignerReceivingClosedV1>>,
    after: Sample,
    after_result: Option<Result<(), CacheSignerReceivingClosedV1>>,
    native_retired: bool,
}

impl StageOriginals {
    fn admitted(&self) -> bool {
        matches!(self.demand, Some(Ok(_)))
            && matches!(self.physical, Some(Ok(())))
            && matches!(self.debit, Some(Ok(())))
    }

    fn complete(&self) -> bool {
        self.admitted()
            && matches!(self.before_result, Some(Ok(())))
            && matches!(self.after_result, Some(Ok(())))
            && self.before.failure().is_none()
            && self.after.failure().is_none()
    }

    fn can_retire_positive_samples(&self) -> bool {
        !self.native_retired && self.complete()
    }

    // Called only after this owner's actual whole before/body/after recipe.
    // Compact positive results remain; actual native samples are really gone
    // before another stage can reuse their finite physical peak.
    fn retire_positive_samples(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if !self.can_retire_positive_samples() {
            return Err(CLOSED);
        }
        drop(std::mem::take(&mut self.before));
        drop(std::mem::take(&mut self.after));
        self.native_retired = true;
        Ok(())
    }

    fn funding_failure<'cause>(
        &'cause self,
        common: &'cause Common,
    ) -> Option<&'cause (dyn Error + 'static)> {
        cause(&self.demand)
            .or_else(|| cause(&self.physical))
            .or_else(|| {
                if matches!(self.debit, Some(Err(_))) {
                    common
                        .representation
                        .as_ref()
                        .and_then(|ledger| ledger.failure())
                        .map(|cause| cause as _)
                        .or_else(|| cause(&self.debit))
                } else {
                    None
                }
            })
            .or_else(|| common.failure())
    }
}

struct CacheSignerStartupOriginalV1 {
    common: Common,
    first: Option<StartupFirst>,
    credentials: CacheSignerCredentialCaptureV1,
    credential_stage: StageOriginals,
    credential_result:
        Option<Result<(), crate::cache_signer_credential::CacheSignerCredentialErrorV2>>,
    credential_retirement:
        Option<Result<(), crate::cache_signer_credential::CacheSignerCredentialErrorV2>>,
    profile: RootProfileOriginalCaptureV1,
    profile_slot: Option<OwnedFd>,
    profile_stage: StageOriginals,
    profile_result: Option<Result<(), aos_sandbox_broker::receiving::RootObservationErrorV1>>,
    configuration: Option<Result<(), CacheSignerReceivingClosedV1>>,
    images: RootPeerImageObservationsV1,
    image_stage: StageOriginals,
    image_result: Option<Result<(), RootPeerImagesClosedV1>>,
    listener: Option<FixedSignerListenerOriginalV1>,
    listener_stage: StageOriginals,
    listener_result: Option<Result<(), FixedSignerListenerClosedV1>>,
    closed: bool,
}

struct CacheCurrentPurposeOriginalV1 {
    first: Option<First>,
    root_request: Option<request::CacheCurrentRequestOriginalV1>,
    header_stage: StageOriginals,
    header_clock: Option<rustix::time::Timespec>,
    header_cutoff: Option<Result<u64, CacheSignerReceivingClosedV1>>,
    header_timeout: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    header_poll: Option<rustix::io::Result<(usize, rustix::event::PollFlags)>>,
    header_poll_clock: Option<rustix::time::Timespec>,
    header_poll_deadline: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    header_result: Option<Result<(), CacheSignerReceivingClosedV1>>,
    header_after_clock: Option<rustix::time::Timespec>,
    header_after_deadline: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    root_challenge: challenge::CacheCurrentChallengeOriginalV1,
    root_interval: Option<root_interval::CacheRootIntervalOriginalV1>,
    purpose_stage: StageOriginals,
    root_begin: Option<Result<(), CacheSignerReceivingClosedV1>>,
    root_binding: Option<Result<(), CacheSignerReceivingClosedV1>>,
    root_finish: Option<Result<(), CacheSignerReceivingClosedV1>>,
    root_settlement: Option<Result<(), CacheSignerReceivingClosedV1>>,
    root_request_finish: Option<Result<(), CacheSignerReceivingClosedV1>>,
    controller_request: Option<request::CacheCurrentRequestOriginalV1>,
    join_stage: StageOriginals,
    controller_request_result: Option<Result<(), CacheSignerReceivingClosedV1>>,
    join_binding: Option<Result<(), CacheSignerReceivingClosedV1>>,
    join_clock: Option<rustix::time::Timespec>,
    join_deadline: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    controller_request_finish: Option<Result<(), CacheSignerReceivingClosedV1>>,
    current_clock_stage: StageOriginals,
    current_clock: Option<current_clock::CacheCurrentClockOriginalV1>,
    current_clock_before: Option<Result<(), CacheSignerReceivingClosedV1>>,
    current_clock_after: Option<Result<(), CacheSignerReceivingClosedV1>>,
    current_objects: Option<current_objects::CacheCurrentObjectsOriginalV1>,
    current_journals: Option<current_journals::CacheCurrentJournalsOriginalV1>,
    current_models: Option<current_models::CacheCurrentModelsOriginalV1>,
    current_proof: Option<current_proof::CacheCurrentProofOriginalV1>,
    purpose_after_clock: Option<rustix::time::Timespec>,
    purpose_after_deadline: Option<
        Result<
            rustix::time::Timespec,
            aos_sandbox_broker::cache_signer_connection::CacheSignerConnectionClosedV1,
        >,
    >,
    retired_request: Option<[u8; aos_sandbox_broker::cache_current_signer_exchange::CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1]>,
    retirement: Option<Result<(), CacheSignerReceivingClosedV1>>,
 }

struct CachePurposeReceivingV1<'original> {
    startup: &'original mut CacheSignerStartupOriginalV1,
    original: &'original mut CacheCurrentPurposeOriginalV1,
    previous_request: Option<&'original [u8; aos_sandbox_broker::cache_current_signer_exchange::CACHE_CURRENT_SIGNER_CHALLENGE_BYTES_V1]>,
    previous_cutoff: Option<u64>,
}

#[derive(Clone, Copy)]
enum ServiceFailure {
    Startup,
    Purpose(usize),
    Lifetime,
    Order,
}

pub(crate) struct CacheSignerServiceOriginalV1 {
    startup: CacheSignerStartupOriginalV1,
    purposes: [Option<CacheCurrentPurposeOriginalV1>; 2],
    purpose_results: [Option<Result<(), CacheSignerReceivingClosedV1>>; 2],
    lifetime: lifetime::CacheSignerLifetimeOriginalV1,
    first: Option<ServiceFailure>,
}

impl CacheSignerStartupOriginalV1 {
    fn new(upper_inline_bytes: usize) -> Self {
        Self {
            common: Common::new_cache(upper_inline_bytes),
            first: None,
            credentials: Default::default(),
            credential_stage: Default::default(),
            credential_result: None,
            credential_retirement: None,
            profile: Default::default(),
            profile_slot: None,
            profile_stage: Default::default(),
            profile_result: None,
            configuration: None,
            images: RootPeerImageObservationsV1::new(),
            image_stage: Default::default(),
            image_result: None,
            listener: None,
            listener_stage: Default::default(),
            listener_result: None,
            closed: false,
        }
    }

    pub(crate) fn capture_once(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.first.is_some() || self.closed {
            return Err(self.fail(StartupFirst::Closed));
        }
        if self.common.capture_once().is_err() {
            return Err(self.fail(StartupFirst::Common));
        }
        Ok(())
    }

    pub(crate) fn capture_credentials_once(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.first.is_some()
            || self.credential_stage.demand.is_some()
            || !matches!(self.common.final_binding, Some(Ok(())))
        {
            return Err(self.fail(StartupFirst::Closed));
        }
        self.credential_stage.demand = Some(credential_demand());
        if admit_stage(&mut self.common, &mut self.credential_stage, 0).is_err() {
            return Err(self.fail(StartupFirst::CredentialFunding));
        }
        self.credential_stage.before_result = Some(observe_original(
            &mut self.common,
            &mut self.credential_stage.before,
        ));
        if !matches!(self.credential_stage.before_result, Some(Ok(()))) {
            self.fail(StartupFirst::CredentialBefore);
        }
        if self.first.is_none() {
            self.credential_result = Some(self.credentials.capture_once());
            if !matches!(self.credential_result, Some(Ok(()))) {
                self.fail(StartupFirst::Credentials);
            }
        }
        // Independent already-paid after: never reborrow a healthy ledger to
        // decide whether an entered failed before/body deserves its post.
        self.credential_stage.after_result = Some(observe_original(
            &mut self.common,
            &mut self.credential_stage.after,
        ));
        if !matches!(self.credential_stage.after_result, Some(Ok(()))) {
            self.fail(StartupFirst::CredentialAfter);
        }
        if self.first.is_none()
            && self.credential_stage.complete()
            && matches!(self.credential_result, Some(Ok(())))
        {
            self.credential_retirement = Some(self.credentials.retire_completed_native_once());
            if !matches!(self.credential_retirement, Some(Ok(()))) {
                self.fail(StartupFirst::CredentialRetirement);
            } else if self.credential_stage.retire_positive_samples().is_err() {
                self.fail(StartupFirst::CredentialRetirement);
            }
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }

    pub(crate) fn capture_root_profile_once(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.first.is_some()
            || self.profile_stage.demand.is_some()
            || !self.credential_stage.complete()
            || !matches!(self.credential_retirement, Some(Ok(())))
        {
            return Err(self.fail(StartupFirst::Closed));
        }
        self.profile_stage.demand = Some(profile_demand());
        if admit_stage(&mut self.common, &mut self.profile_stage, 0).is_err() {
            return Err(self.fail(StartupFirst::ProfileFunding));
        }
        self.profile_stage.before_result = Some(observe_original(
            &mut self.common,
            &mut self.profile_stage.before,
        ));
        if !matches!(self.profile_stage.before_result, Some(Ok(()))) {
            self.fail(StartupFirst::ProfileBefore);
        }
        if self.first.is_none() {
            self.profile_slot = self.common.root_profile.take().map(OwnedFd::from);
            self.profile_result = Some(self.profile.receive_original_once(&mut self.profile_slot));
            if !matches!(self.profile_result, Some(Ok(()))) {
                self.fail(StartupFirst::Profile);
            }
        }
        self.profile_stage.after_result = Some(observe_original(
            &mut self.common,
            &mut self.profile_stage.after,
        ));
        if !matches!(self.profile_stage.after_result, Some(Ok(()))) {
            self.fail(StartupFirst::ProfileAfter);
        }
        if self.first.is_none()
            && self.profile_stage.complete()
            && self.profile_stage.retire_positive_samples().is_err()
        {
            self.fail(StartupFirst::ProfileAfter);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }

    pub(crate) fn require_configuration_once(
        &mut self,
        controller_uid: u32,
        controller_gid: u32,
        cache_uid: u32,
        cache_gid: u32,
    ) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.first.is_some() || self.configuration.is_some() || !self.profile_stage.complete() {
            return Err(self.fail(StartupFirst::Closed));
        }
        self.configuration = Some((|| {
            let profile = self.profile.profile().ok_or(CLOSED)?;
            let membership = self
                .common
                .membership
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CLOSED)?;
            let credentials = membership.credentials().ok_or(CLOSED)?;
            if profile.identities[0] != controller_uid
                || profile.identities[1] != controller_gid
                || profile.identities[2] != cache_uid
                || profile.cache_signer_gid != cache_gid
                || controller_uid == 0
                || controller_gid == 0
                || cache_uid == 0
                || cache_gid == 0
                || controller_uid == cache_uid
                || credentials.real_user_id() != cache_uid
                || credentials.effective_user_id() != cache_uid
                || credentials.saved_user_id() != cache_uid
                || credentials.filesystem_user_id() != cache_uid
                || credentials.real_group_id() != cache_gid
                || credentials.effective_group_id() != cache_gid
                || credentials.saved_group_id() != cache_gid
                || credentials.filesystem_group_id() != cache_gid
            {
                return Err(CLOSED);
            }
            Ok(())
        })());
        if matches!(self.configuration, Some(Ok(()))) {
            Ok(())
        } else {
            Err(self.fail(StartupFirst::Configuration))
        }
    }

    pub(crate) fn capture_root_images_once(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.first.is_some()
            || self.image_stage.demand.is_some()
            || !matches!(self.configuration, Some(Ok(())))
            || !self.profile_stage.native_retired
        {
            return Err(self.fail(StartupFirst::Closed));
        }
        self.image_stage.demand = Some((|| {
            let profile = self
                .profile
                .profile()
                .ok_or(AccountingError::ArithmeticOverflow {
                    dimension: D::MemoryBytes,
                })?;
            let native = RootPeerImageObservationsV1::receiving_demand_v1(profile).ok_or(
                AccountingError::ArithmeticOverflow {
                    dimension: D::MemoryBytes,
                },
            )?;
            native.checked_add(sample_pair_demand()?)
        })());
        // The prior Root companion remains physically resident. Its original
        // fixed allowance is conservatively retained after its sample leaves.
        let resident = RootProfileOriginalCaptureV1::fixed_demand()
            .ok_or(CLOSED)?
            .get(D::OpenFiles);
        if admit_stage(&mut self.common, &mut self.image_stage, resident).is_err() {
            return Err(self.fail(StartupFirst::ImagesFunding));
        }
        self.image_stage.before_result = Some(observe_original(
            &mut self.common,
            &mut self.image_stage.before,
        ));
        if !matches!(self.image_stage.before_result, Some(Ok(()))) {
            self.fail(StartupFirst::ImagesBefore);
        }
        if self.first.is_none() {
            let profile = self.profile.profile().ok_or(CLOSED)?;
            self.image_result = Some(self.images.observe_once(profile));
            if !matches!(self.image_result, Some(Ok(()))) {
                self.fail(StartupFirst::Images);
            }
        }
        self.image_stage.after_result = Some(observe_original(
            &mut self.common,
            &mut self.image_stage.after,
        ));
        if !matches!(self.image_stage.after_result, Some(Ok(()))) {
            self.fail(StartupFirst::ImagesAfter);
        }
        if self.first.is_none()
            && self.image_stage.complete()
            && self.images.is_complete()
            && self.image_stage.retire_positive_samples().is_err()
        {
            self.fail(StartupFirst::ImagesAfter);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }

    pub(crate) fn capture_listener_once(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.first.is_some()
            || self.listener_stage.demand.is_some()
            || !self.image_stage.native_retired
            || !self.images.is_complete()
        {
            return Err(self.fail(StartupFirst::Closed));
        }
        self.listener_stage.demand = Some((|| {
            let native = FixedSignerListenerOriginalV1::receiving_demand_v1().ok_or(
                AccountingError::ArithmeticOverflow {
                    dimension: D::MemoryBytes,
                },
            )?;
            native.checked_add(sample_pair_demand()?)
        })());
        let profile = self.profile.profile().ok_or(CLOSED)?;
        let cache_uid = profile.identities[2];
        let socket_gid = profile.identities[1];
        let resident = RootProfileOriginalCaptureV1::fixed_demand()
            .ok_or(CLOSED)?
            .checked_add(RootPeerImageObservationsV1::receiving_demand_v1(profile).ok_or(CLOSED)?)
            .map_err(|_| CLOSED)?
            .get(D::OpenFiles);
        if admit_stage(&mut self.common, &mut self.listener_stage, resident).is_err() {
            return Err(self.fail(StartupFirst::ListenerFunding));
        }
        self.listener_stage.before_result = Some(observe_original(
            &mut self.common,
            &mut self.listener_stage.before,
        ));
        if !matches!(self.listener_stage.before_result, Some(Ok(()))) {
            self.fail(StartupFirst::ListenerBefore);
        }
        if self.first.is_none() {
            // Construct this actual fd0 owner only after the complete same-F
            // shape is paid. No CLI path or descriptor can select its recipe.
            self.listener = Some(FixedSignerListenerOriginalV1::cache(cache_uid, socket_gid));
            self.listener_result = Some(self.listener.as_mut().ok_or(CLOSED)?.observe_once());
            if !matches!(self.listener_result, Some(Ok(()))) {
                self.fail(StartupFirst::Listener);
            }
        }
        self.listener_stage.after_result = Some(observe_original(
            &mut self.common,
            &mut self.listener_stage.after,
        ));
        if !matches!(self.listener_stage.after_result, Some(Ok(()))) {
            self.fail(StartupFirst::ListenerAfter);
        }
        if self.first.is_none()
            && self.listener_stage.complete()
            && self
                .listener
                .as_ref()
                .is_some_and(FixedSignerListenerOriginalV1::complete)
            && self.listener_stage.retire_positive_samples().is_err()
        {
            self.fail(StartupFirst::ListenerAfter);
        }
        if self.first.is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }

    pub(crate) fn capture_startup_once(
        &mut self,
        controller_uid: u32,
        controller_gid: u32,
        cache_uid: u32,
        cache_gid: u32,
    ) -> Result<(), CacheSignerReceivingClosedV1> {
        self.capture_once()?;
        self.capture_credentials_once()?;
        self.capture_root_profile_once()?;
        self.require_configuration_once(controller_uid, controller_gid, cache_uid, cache_gid)?;
        self.capture_root_images_once()?;
        self.capture_listener_once()
    }

    pub(crate) fn credential(
        &self,
    ) -> Result<&CacheSignerCredentialV2, CacheSignerReceivingClosedV1> {
        if self.first.is_some()
            || self.closed
            || !matches!(self.configuration, Some(Ok(())))
            || !self.credential_stage.complete()
            || !self.profile_stage.complete()
            || !matches!(self.credential_retirement, Some(Ok(())))
            || !self.image_stage.complete()
            || !self.images.is_complete()
            || !self.listener_stage.native_retired
            || !self
                .listener
                .as_ref()
                .is_some_and(FixedSignerListenerOriginalV1::complete)
        {
            return Err(CLOSED);
        }
        self.credentials.credential().map_err(|_| CLOSED)
    }

    fn fail(&mut self, stage: StartupFirst) -> CacheSignerReceivingClosedV1 {
        self.first.get_or_insert(stage);
        CLOSED
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            StartupFirst::Common => self.common.failure(),
            StartupFirst::CredentialFunding => self.credential_stage.funding_failure(&self.common),
            StartupFirst::CredentialBefore => self
                .credential_stage
                .before
                .failure()
                .or_else(|| cause(&self.credential_stage.before_result)),
            StartupFirst::Credentials => self
                .credentials
                .failure()
                .or_else(|| cause(&self.credential_result)),
            StartupFirst::CredentialAfter => self
                .credential_stage
                .after
                .failure()
                .or_else(|| cause(&self.credential_stage.after_result)),
            StartupFirst::CredentialRetirement => cause(&self.credential_retirement),
            StartupFirst::ProfileFunding => self.profile_stage.funding_failure(&self.common),
            StartupFirst::ProfileBefore => self
                .profile_stage
                .before
                .failure()
                .or_else(|| cause(&self.profile_stage.before_result)),
            StartupFirst::Profile => self
                .profile
                .source_failure()
                .or_else(|| cause(&self.profile_result)),
            StartupFirst::ProfileAfter => self
                .profile_stage
                .after
                .failure()
                .or_else(|| cause(&self.profile_stage.after_result)),
            StartupFirst::Configuration => cause(&self.configuration),
            StartupFirst::ImagesFunding => self.image_stage.funding_failure(&self.common),
            StartupFirst::ImagesBefore => self
                .image_stage
                .before
                .failure()
                .or_else(|| cause(&self.image_stage.before_result)),
            StartupFirst::Images => self.images.failure().or_else(|| cause(&self.image_result)),
            StartupFirst::ImagesAfter => self
                .image_stage
                .after
                .failure()
                .or_else(|| cause(&self.image_stage.after_result)),
            StartupFirst::ListenerFunding => self.listener_stage.funding_failure(&self.common),
            StartupFirst::ListenerBefore => self
                .listener_stage
                .before
                .failure()
                .or_else(|| cause(&self.listener_stage.before_result)),
            StartupFirst::Listener => self
                .listener
                .as_ref()
                .and_then(FixedSignerListenerOriginalV1::failure)
                .or_else(|| cause(&self.listener_result)),
            StartupFirst::ListenerAfter => self
                .listener_stage
                .after
                .failure()
                .or_else(|| cause(&self.listener_stage.after_result)),
            StartupFirst::Closed => Some(&CLOSED),
        }
    }
}

impl CacheCurrentPurposeOriginalV1 {
    fn new() -> Self {
        Self {
            first: None,
            root_request: None,
            header_stage: Default::default(),
            header_clock: None,
            header_cutoff: None,
            header_timeout: None,
            header_poll: None,
            header_poll_clock: None,
            header_poll_deadline: None,
            header_result: None,
            header_after_clock: None,
            header_after_deadline: None,
            root_challenge: Default::default(),
            root_interval: None,
            purpose_stage: Default::default(),
            root_begin: None,
            root_binding: None,
            root_finish: None,
            root_settlement: None,
            root_request_finish: None,
            controller_request: None,
            join_stage: Default::default(),
            controller_request_result: None,
            join_binding: None,
            join_clock: None,
            join_deadline: None,
            controller_request_finish: None,
            current_clock_stage: Default::default(),
            current_clock: None,
            current_clock_before: None,
            current_clock_after: None,
            current_objects: None,
            current_journals: None,
            current_models: None,
            current_proof: None,
            purpose_after_clock: None,
            purpose_after_deadline: None,
            retired_request: None,
            retirement: None,
        }
    }

    fn failure<'cause>(
        &'cause self,
        startup: &'cause CacheSignerStartupOriginalV1,
    ) -> Option<&'cause (dyn Error + 'static)> {
        match self.first? {
            First::HeaderFunding => self.header_stage.funding_failure(&startup.common),
            First::HeaderBefore => self
                .header_stage
                .before
                .failure()
                .or_else(|| cause(&self.header_stage.before_result)),
            First::HeaderClock => cause(&self.header_cutoff),
            First::HeaderReadiness => cause(&self.header_timeout)
                .or_else(|| cause(&self.header_poll))
                .or(Some(&CLOSED)),
            First::HeaderDeadline => cause(&self.header_poll_deadline),
            First::Header => self
                .root_request
                .as_ref()
                .and_then(request::CacheCurrentRequestOriginalV1::failure)
                .or_else(|| cause(&self.header_result)),
            First::HeaderAfter => self
                .header_stage
                .after
                .failure()
                .or_else(|| cause(&self.header_stage.after_result)),
            First::HeaderAfterDeadline => cause(&self.header_after_deadline),
            First::RootPurposeFunding => self.purpose_stage.funding_failure(&startup.common),
            First::RootChallenge => self.root_challenge.failure(),
            First::RootPurposeBefore => self
                .purpose_stage
                .before
                .failure()
                .or_else(|| cause(&self.purpose_stage.before_result)),
            First::RootPeerBefore => self
                .root_interval
                .as_ref()
                .and_then(|interval| interval.failure(&startup.images))
                .or_else(|| cause(&self.root_begin)),
            First::RootBinding => cause(&self.root_binding),
            First::JoinFunding => self.join_stage.funding_failure(&startup.common),
            First::JoinBefore => self
                .join_stage
                .before
                .failure()
                .or_else(|| cause(&self.join_stage.before_result)),
            First::ControllerRequest => self
                .controller_request
                .as_ref()
                .and_then(request::CacheCurrentRequestOriginalV1::failure)
                .or_else(|| cause(&self.controller_request_result)),
            First::JoinBinding => cause(&self.join_binding),
            First::JoinAfter => self
                .join_stage
                .after
                .failure()
                .or_else(|| cause(&self.join_stage.after_result)),
            First::JoinLate => cause(&self.join_deadline),
            First::CurrentClockFunding => self.current_clock_stage.funding_failure(&startup.common),
            First::CurrentClockBefore => self
                .current_clock_stage
                .before
                .failure()
                .or_else(|| cause(&self.current_clock_stage.before_result)),
            First::CurrentClock => self
                .current_clock
                .as_ref()
                .and_then(current_clock::CacheCurrentClockOriginalV1::failure)
                .or_else(|| cause(&self.current_clock_before)),
            First::CurrentClockAfter => self
                .current_clock
                .as_ref()
                .and_then(current_clock::CacheCurrentClockOriginalV1::failure)
                .or_else(|| cause(&self.current_clock_after))
                .or_else(|| self.current_clock_stage.after.failure())
                .or_else(|| cause(&self.current_clock_stage.after_result)),
            First::CurrentObjects => self
                .current_objects
                .as_ref()
                .and_then(|objects| objects.failure(&startup.common)),
            First::CurrentJournals => self
                .current_journals
                .as_ref()
                .and_then(|journals| journals.failure(&startup.common)),
            First::CurrentModels => self
                .current_models
                .as_ref()
                .and_then(|models| models.failure(&startup.common)),
            First::CurrentProof => self
                .current_proof
                .as_ref()
                .and_then(|proof| proof.failure(&startup.common)),
            First::ControllerRequestAfter => self
                .controller_request
                .as_ref()
                .and_then(request::CacheCurrentRequestOriginalV1::failure)
                .or_else(|| cause(&self.controller_request_finish)),
            First::RootRequestAfter => self
                .root_request
                .as_ref()
                .and_then(request::CacheCurrentRequestOriginalV1::failure)
                .or_else(|| cause(&self.root_request_finish)),
            First::RootPeerAfter => self
                .root_interval
                .as_ref()
                .and_then(|interval| interval.failure(&startup.images))
                .or_else(|| cause(&self.root_finish)),
            First::RootPurposeAfter => self
                .purpose_stage
                .after
                .failure()
                .or_else(|| cause(&self.purpose_stage.after_result)),
            First::RootPurposeLate => cause(&self.purpose_after_deadline),
            First::RootSettlement => self
                .root_interval
                .as_ref()
                .and_then(|interval| interval.failure(&startup.images))
                .or_else(|| cause(&self.root_settlement)),
            First::Closed => Some(&CLOSED),
        }
    }

    pub(crate) fn root_property_failure_view(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::RootPeerBefore | First::RootPeerAfter | First::RootSettlement => {
                self.root_interval.as_ref()?.property_failure_view()
            }
            _ => None,
        }
    }

    // Only this owner's actual whole result can select native retirement.
    fn retire_after_complete_once(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.retirement.is_some()
            || self.first.is_some()
            || !self.purpose_stage.can_retire_positive_samples()
            || !self.current_clock_stage.can_retire_positive_samples()
            || !self
                .current_journals
                .as_ref()
                .is_some_and(|owner| owner.can_retire_positive_samples_v1())
            || !matches!(self.root_finish, Some(Ok(())))
            || !matches!(self.root_settlement, Some(Ok(())))
            || !matches!(self.root_request_finish, Some(Ok(())))
            || !matches!(self.controller_request_finish, Some(Ok(())))
            || !matches!(self.purpose_after_deadline, Some(Ok(_)))
            || !self
                .current_proof
                .as_ref()
                .is_some_and(|proof| proof.can_retire_positive_native_v1())
        {
            return Err(CLOSED);
        }
        let request = self.root_request.as_ref().ok_or(CLOSED)?.bytes()?;
        let saved = *request;
        self.retired_request = Some(saved);
        // Every fallible retirement predicate was checked above against these
        // same exclusively held owners. Retire their positive samples before
        // releasing the complete request/native intervals; no future credit is
        // used by the next purpose.
        self.purpose_stage.retire_positive_samples()?;
        self.current_clock_stage.retire_positive_samples()?;
        self.current_journals
            .as_mut()
            .ok_or(CLOSED)?
            .retire_positive_samples_once_v1()?;
        self.current_proof
            .as_mut()
            .ok_or(CLOSED)?
            .retire_positive_native_once_v1()?;
        // Packet, complete models, whole results and immutable Root challenge
        // stay resident. Their own positive native intervals have ended.
        drop(self.root_request.take());
        drop(self.controller_request.take());
        drop(self.root_interval.take());
        drop(self.current_objects.take());
        drop(self.current_clock.take());
        self.retirement = Some(Ok(()));
        Ok(())
    }
}

impl CachePurposeReceivingV1<'_> {
    fn fail(&mut self, stage: First) -> CacheSignerReceivingClosedV1 {
        self.original.first.get_or_insert(stage);
        CLOSED
    }

    fn credential(&self) -> Result<&CacheSignerCredentialV2, CacheSignerReceivingClosedV1> {
        if self.original.first.is_some() {
            return Err(CLOSED);
        }
        self.startup.credential()
    }

    pub(crate) fn capture_root_request_once(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.original.first.is_some()
            || self.original.header_stage.demand.is_some()
            || self.credential().is_err()
        {
            return Err(self.fail(First::Closed));
        }
        self.original.header_stage.demand = Some((|| {
            let request = request::CacheCurrentRequestOriginalV1::receiving_demand_v1().ok_or(
                AccountingError::ArithmeticOverflow {
                    dimension: D::MemoryBytes,
                },
            )?;
            request.checked_add(sample_pair_demand()?)
        })());
        let profile = self.startup.profile.profile().ok_or(CLOSED)?;
        let root_group = profile.identities[1];
        let resident = RootProfileOriginalCaptureV1::fixed_demand()
            .ok_or(CLOSED)?
            .checked_add(RootPeerImageObservationsV1::receiving_demand_v1(profile).ok_or(CLOSED)?)
            .and_then(|demand| {
                demand.checked_add(FixedSignerListenerOriginalV1::receiving_demand_v1().ok_or(
                    AccountingError::ArithmeticOverflow {
                        dimension: D::MemoryBytes,
                    },
                )?)
            })
            .map_err(|_| CLOSED)?
            .get(D::OpenFiles);
        if admit_stage(
            &mut self.startup.common,
            &mut self.original.header_stage,
            resident,
        )
        .is_err()
        {
            return Err(self.fail(First::HeaderFunding));
        }
        self.original.header_stage.before_result = Some(observe_original(
            &mut self.startup.common,
            &mut self.original.header_stage.before,
        ));
        if !matches!(self.original.header_stage.before_result, Some(Ok(()))) {
            self.fail(First::HeaderBefore);
        }
        if self.original.first.is_none() {
            let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            self.original.header_clock = Some(now);
            self.original.header_cutoff = Some(if let Some(cutoff) = self.previous_cutoff {
                Ok(cutoff)
            } else {
                (|| {
                    let seconds = u64::try_from(now.tv_sec).map_err(|_| CLOSED)?;
                    let nanos = u64::try_from(now.tv_nsec).map_err(|_| CLOSED)?;
                    if nanos >= 1_000_000_000 {
                        return Err(CLOSED);
                    }
                    seconds
                        .checked_mul(1_000_000_000)
                        .and_then(|value| value.checked_add(nanos))
                        .and_then(|value| {
                            value.checked_add(
                                u64::try_from(std::time::Duration::from_secs(5).as_nanos()).ok()?,
                            )
                        })
                        .ok_or(CLOSED)
                })()
            });
            if !matches!(self.original.header_cutoff, Some(Ok(_))) {
                self.fail(First::HeaderClock);
            }
        }
        if self.original.first.is_none() {
            let cutoff = self
                .original
                .header_cutoff
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or(CLOSED)?;
            let now = self.original.header_clock.ok_or(CLOSED)?;
            self.original.header_timeout =
                Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
            if let Some(Ok(timeout)) = self.original.header_timeout.as_ref() {
                self.original.header_poll = Some(
                    self.startup
                        .listener
                        .as_ref()
                        .ok_or(CLOSED)?
                        .poll_once(timeout),
                );
            }
            if !matches!(self.original.header_poll, Some(Ok((count, flags))) if count != 0
                && flags.contains(rustix::event::PollFlags::IN)
                && !flags.contains(rustix::event::PollFlags::NVAL))
            {
                self.fail(First::HeaderReadiness);
            }
            let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            self.original.header_poll_clock = Some(now);
            self.original.header_poll_deadline =
                Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
            if !matches!(self.original.header_poll_deadline, Some(Ok(_))) {
                self.fail(First::HeaderDeadline);
            }
        }
        if self.original.first.is_none() {
            let cutoff = self
                .original
                .header_cutoff
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or(CLOSED)?;
            self.original.root_request = Some(request::CacheCurrentRequestOriginalV1::new());
            self.original.header_result = Some(
                self.original
                    .root_request
                    .as_mut()
                    .ok_or(CLOSED)?
                    .accept_root_once(
                        self.startup.listener.as_ref().ok_or(CLOSED)?,
                        root_group,
                        cutoff,
                    ),
            );
            if !matches!(self.original.header_result, Some(Ok(()))) {
                self.fail(First::Header);
            }
        }
        // This already-paid Cache-native post is independent of the raw
        // preamble action. It cannot certify the later Root/signing interval.
        self.original.header_stage.after_result = Some(observe_original(
            &mut self.startup.common,
            &mut self.original.header_stage.after,
        ));
        if !matches!(self.original.header_stage.after_result, Some(Ok(()))) {
            self.fail(First::HeaderAfter);
        }
        if let Some(Ok(cutoff)) = self.original.header_cutoff {
            let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
            self.original.header_after_clock = Some(now);
            self.original.header_after_deadline =
                Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
            if !matches!(self.original.header_after_deadline, Some(Ok(_))) {
                self.fail(First::HeaderAfterDeadline);
            }
        }
        if self.original.first.is_none()
            && self.original.header_stage.complete()
            && self
                .original
                .header_stage
                .retire_positive_samples()
                .is_err()
        {
            self.fail(First::HeaderAfter);
        }
        if self.original.first.is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }

    fn begin_current_root_purpose_once(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.original.first.is_some()
            || !self.original.header_stage.native_retired
            || self.original.purpose_stage.demand.is_some()
        {
            return Err(self.fail(First::Closed));
        }
        self.original.purpose_stage.demand = Some((|| {
            let overflow = AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            };
            root_interval::CacheRootIntervalOriginalV1::receiving_demand_v1()
                .ok_or(overflow)?
                .checked_add(sample_pair_demand()?)
        })());
        let profile = self.startup.profile.profile().ok_or(CLOSED)?;
        let resident = RootProfileOriginalCaptureV1::fixed_demand()
            .ok_or(CLOSED)?
            .checked_add(RootPeerImageObservationsV1::receiving_demand_v1(profile).ok_or(CLOSED)?)
            .and_then(|value| {
                value.checked_add(FixedSignerListenerOriginalV1::receiving_demand_v1().ok_or(
                    AccountingError::ArithmeticOverflow {
                        dimension: D::OpenFiles,
                    },
                )?)
            })
            .and_then(|value| {
                value.checked_add(
                    request::CacheCurrentRequestOriginalV1::receiving_demand_v1().ok_or(
                        AccountingError::ArithmeticOverflow {
                            dimension: D::OpenFiles,
                        },
                    )?,
                )
            })
            .map_err(|_| CLOSED)?
            .get(D::OpenFiles);
        if admit_stage(
            &mut self.startup.common,
            &mut self.original.purpose_stage,
            resident,
        )
        .is_err()
        {
            return Err(self.fail(First::RootPurposeFunding));
        }
        let request = self.original.root_request.as_ref().ok_or(CLOSED)?;
        if self.original.root_challenge.decode_once(request).is_err() {
            return Err(self.fail(First::RootChallenge));
        }
        if let Some(previous) = self.previous_request {
            let current = self.original.root_request.as_ref().ok_or(CLOSED)?.bytes()?;
            if current != previous.as_slice() {
                return Err(self.fail(First::RootChallenge));
            }
        }
        let cutoff = self.original.root_challenge.data()?.cutoff;
        self.original.purpose_stage.before_result = Some(observe_original(
            &mut self.startup.common,
            &mut self.original.purpose_stage.before,
        ));
        if !matches!(self.original.purpose_stage.before_result, Some(Ok(()))) {
            self.fail(First::RootPurposeBefore);
        }
        // The actual Root post is armed by construction before its before.
        // It stays resident until the complete service body and all posts.
        self.original.root_interval = Some(root_interval::CacheRootIntervalOriginalV1::new());
        if self.original.first.is_none() {
            self.original.root_begin = Some(
                self.original
                    .root_interval
                    .as_mut()
                    .ok_or(CLOSED)?
                    .begin_once(
                        &self.startup.profile,
                        &mut self.startup.images,
                        self.original
                            .root_request
                            .as_ref()
                            .ok_or(CLOSED)?
                            .stream()?,
                        cutoff,
                    ),
            );
            if !matches!(self.original.root_begin, Some(Ok(()))) {
                self.fail(First::RootPeerBefore);
            }
        }
        if self.original.first.is_none() {
            self.original.root_binding = Some((|| {
                let data = self.original.root_challenge.data()?;
                let (recipient, producer) = self
                    .original
                    .root_interval
                    .as_ref()
                    .and_then(|interval| interval.subjects())
                    .ok_or(CLOSED)?;
                let root = data.root;
                let stream = self
                    .original
                    .root_request
                    .as_ref()
                    .ok_or(CLOSED)?
                    .stream()?;
                let profile = self.startup.profile.profile().ok_or(CLOSED)?;
                if root.root_pid != stream.peer().credentials().pid().get()
                    || root.root_profile
                        != self
                            .startup
                            .profile
                            .measurement()
                            .map_err(|_| CLOSED)?
                            .measured_digest_v1()
                    || root.root_recipient != recipient
                    || root.root_producer != producer
                    || root.controller_uid != profile.identities[0]
                    || root.controller_gid != profile.identities[1]
                {
                    return Err(CLOSED);
                }
                Ok(())
            })());
            if !matches!(self.original.root_binding, Some(Ok(()))) {
                self.fail(First::RootBinding);
            }
        }
        if self.original.first.is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }

    fn join_current_controller_once(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.original.first.is_some()
            || !matches!(self.original.root_binding, Some(Ok(())))
            || self.original.join_stage.demand.is_some()
        {
            return Err(self.fail(First::Closed));
        }
        self.original.join_stage.demand = Some((|| {
            let overflow = AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            };
            request::CacheCurrentRequestOriginalV1::receiving_demand_v1()
                .ok_or(overflow)?
                .checked_add(sample_pair_demand()?)
        })());
        let profile = self.startup.profile.profile().ok_or(CLOSED)?;
        let controller_uid = profile.identities[0];
        let controller_gid = profile.identities[1];
        let resident = RootProfileOriginalCaptureV1::fixed_demand()
            .ok_or(CLOSED)?
            .checked_add(RootPeerImageObservationsV1::receiving_demand_v1(profile).ok_or(CLOSED)?)
            .and_then(|value| {
                value.checked_add(FixedSignerListenerOriginalV1::receiving_demand_v1().ok_or(
                    AccountingError::ArithmeticOverflow {
                        dimension: D::OpenFiles,
                    },
                )?)
            })
            .and_then(|value| {
                value.checked_add(
                    request::CacheCurrentRequestOriginalV1::receiving_demand_v1().ok_or(
                        AccountingError::ArithmeticOverflow {
                            dimension: D::OpenFiles,
                        },
                    )?,
                )
            })
            .and_then(|value| {
                value.checked_add(
                    root_interval::CacheRootIntervalOriginalV1::receiving_demand_v1().ok_or(
                        AccountingError::ArithmeticOverflow {
                            dimension: D::OpenFiles,
                        },
                    )?,
                )
            })
            // The whole Root purpose still owes its own after sample. Its
            // failed before/after can coexist with this stage's negative pair.
            .and_then(|value| value.checked_add(sample_pair_demand()?))
            .map_err(|_| CLOSED)?
            .get(D::OpenFiles);
        if admit_stage(
            &mut self.startup.common,
            &mut self.original.join_stage,
            resident,
        )
        .is_err()
        {
            return Err(self.fail(First::JoinFunding));
        }
        let cutoff = self.original.root_challenge.data()?.cutoff;
        self.original.join_stage.before_result = Some(observe_original(
            &mut self.startup.common,
            &mut self.original.join_stage.before,
        ));
        if !matches!(self.original.join_stage.before_result, Some(Ok(()))) {
            self.fail(First::JoinBefore);
        }
        if self.original.first.is_none() {
            self.original.controller_request = Some(request::CacheCurrentRequestOriginalV1::new());
            self.original.controller_request_result = Some(
                self.original
                    .controller_request
                    .as_mut()
                    .ok_or(CLOSED)?
                    .accept_controller_once(
                        self.startup.listener.as_ref().ok_or(CLOSED)?,
                        controller_uid,
                        controller_gid,
                        cutoff,
                    ),
            );
            if !matches!(self.original.controller_request_result, Some(Ok(()))) {
                self.fail(First::ControllerRequest);
            }
        }
        if self.original.first.is_none() {
            self.original.join_binding = Some((|| {
                let root = self.original.root_request.as_ref().ok_or(CLOSED)?;
                let controller = self.original.controller_request.as_ref().ok_or(CLOSED)?;
                // Both actual requests have independently checked fixed magics,
                // exact EOF, SCM subjects and original endpoint currentness.
                // Compare only the complete common Hello+Held challenge.
                if root.bytes()?[8..] != controller.bytes()?[8..]
                    || self.original.root_challenge.data()?.root.controller_pid
                        != controller.stream()?.peer().credentials().pid().get()
                {
                    return Err(CLOSED);
                }
                Ok(())
            })());
            if !matches!(self.original.join_binding, Some(Ok(()))) {
                self.fail(First::JoinBinding);
            }
        }
        self.original.join_stage.after_result = Some(observe_original(
            &mut self.startup.common,
            &mut self.original.join_stage.after,
        ));
        if !matches!(self.original.join_stage.after_result, Some(Ok(()))) {
            self.fail(First::JoinAfter);
        }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.original.join_clock = Some(now);
        self.original.join_deadline =
            Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
        if !matches!(self.original.join_deadline, Some(Ok(_))) {
            self.fail(First::JoinLate);
        }
        if self.original.first.is_none()
            && self.original.join_stage.retire_positive_samples().is_err()
        {
            self.fail(First::JoinAfter);
        }
        if self.original.first.is_none() {
            self.begin_current_clock_once()?;
            self.begin_current_journals_once()?;
            self.begin_current_models_once()?;
            self.begin_current_objects_once()?;
        }
        if self.original.first.is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }

    fn finish_current_root_purpose_once(&mut self) -> Result<(), CacheSignerReceivingClosedV1> {
        if !self.original.purpose_stage.admitted()
            || self.original.purpose_stage.before_result.is_none()
            || self.original.purpose_stage.after_result.is_some()
        {
            return Err(self.fail(First::Closed));
        }
        let cutoff = self.original.root_challenge.data()?.cutoff;
        if self
            .original
            .current_journals
            .as_ref()
            .is_some_and(|journals| journals.owes_after_v1())
        {
            let _ = self.finish_current_journals_once();
        }
        if self
            .original
            .current_objects
            .as_ref()
            .is_some_and(|objects| objects.owes_after_v1())
        {
            let _ = self.finish_current_objects_once();
        }
        if self.original.current_clock_stage.before_result.is_some()
            && self.original.current_clock_after.is_none()
        {
            // A failed body still owes the paired native post and its F post.
            // The private method preserves any earlier body cause.
            let _ = self.finish_current_clock_once();
        }
        if let Some(controller) = self.original.controller_request.as_mut() {
            self.original.controller_request_finish =
                Some(controller.finish_native_posts_once(cutoff));
            if !matches!(self.original.controller_request_finish, Some(Ok(()))) {
                self.fail(First::ControllerRequestAfter);
            }
        }
        if self.original.root_begin.is_some() {
            self.original.root_finish = Some(
                self.original
                    .root_interval
                    .as_mut()
                    .ok_or(CLOSED)?
                    .finish_once(
                        &self.startup.profile,
                        &mut self.startup.images,
                        self.original
                            .root_request
                            .as_ref()
                            .ok_or(CLOSED)?
                            .stream()?,
                        cutoff,
                    ),
            );
            if !matches!(self.original.root_finish, Some(Ok(()))) {
                self.fail(First::RootPeerAfter);
            }
        }
        if let Some(request) = self.original.root_request.as_mut() {
            self.original.root_request_finish = Some(request.finish_native_posts_once(cutoff));
            if !matches!(self.original.root_request_finish, Some(Ok(()))) {
                self.fail(First::RootRequestAfter);
            }
        }
        self.original.purpose_stage.after_result = Some(observe_original(
            &mut self.startup.common,
            &mut self.original.purpose_stage.after,
        ));
        if !matches!(self.original.purpose_stage.after_result, Some(Ok(()))) {
            self.fail(First::RootPurposeAfter);
        }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        self.original.purpose_after_clock = Some(now);
        self.original.purpose_after_deadline =
            Some(aos_sandbox_broker::cache_signer_connection::deadline_timeout_v1(now, cutoff));
        if !matches!(self.original.purpose_after_deadline, Some(Ok(_))) {
            self.fail(First::RootPurposeLate);
        }
        if self.original.first.is_none() {
            Ok(())
        } else {
            Err(CLOSED)
        }
    }
}

impl CacheSignerServiceOriginalV1 {
    pub(crate) fn new() -> Self {
        // The returned owning error can move this entire resident carrier to a
        // Box. Include both construction locations and that allocation header
        // in the original fixed byte peak before native service stages enter.
        let upper_inline_bytes = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_sub(size_of::<Common>()))
            .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>()))
            .unwrap_or(usize::MAX);
        Self {
            startup: CacheSignerStartupOriginalV1::new(upper_inline_bytes),
            purposes: [None, None],
            purpose_results: [None, None],
            lifetime: Default::default(),
            first: None,
        }
    }

    pub(crate) fn capture_startup_once(
        &mut self,
        controller_uid: u32,
        controller_gid: u32,
        cache_uid: u32,
        cache_gid: u32,
    ) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.first.is_some() {
            return Err(CLOSED);
        }
        let result =
            self.startup
                .capture_startup_once(controller_uid, controller_gid, cache_uid, cache_gid);
        if result.is_err() {
            self.first.get_or_insert(ServiceFailure::Startup);
        }
        result
    }

    pub(crate) fn serve_two_current_purposes_once(
        &mut self,
    ) -> Result<(), CacheSignerReceivingClosedV1> {
        if self.first.is_some()
            || self.purposes.iter().any(Option::is_some)
            || self.startup.credential().is_err()
        {
            self.first.get_or_insert(ServiceFailure::Order);
            return Err(CLOSED);
        }
        self.purposes[0] = Some(CacheCurrentPurposeOriginalV1::new());
        self.purpose_results[0] = Some(
            CachePurposeReceivingV1 {
                startup: &mut self.startup,
                original: self.purposes[0].as_mut().ok_or(CLOSED)?,
                previous_request: None,
                previous_cutoff: None,
            }
            .serve_current_purpose_once(),
        );
        if !matches!(self.purpose_results[0], Some(Ok(()))) {
            self.first.get_or_insert(ServiceFailure::Purpose(0));
            return Err(CLOSED);
        }
        // The same financial original/ledger/seed/profile/listener survives.
        // First purpose outputs remain resident; no fields or debt are reset.
        let (first, second) = self.purposes.split_at_mut(1);
        let first = first[0].as_mut().ok_or(CLOSED)?;
        let retired = first.retire_after_complete_once();
        if retired.is_err() {
            first.retirement = Some(retired);
            self.first.get_or_insert(ServiceFailure::Purpose(0));
            return Err(CLOSED);
        }
        let cutoff = first.root_challenge.data()?.cutoff;
        second[0] = Some(CacheCurrentPurposeOriginalV1::new());
        self.purpose_results[1] = Some(
            CachePurposeReceivingV1 {
                startup: &mut self.startup,
                original: second[0].as_mut().ok_or(CLOSED)?,
                previous_request: first.retired_request.as_ref(),
                previous_cutoff: Some(cutoff),
            }
            .serve_current_purpose_once(),
        );
        if !matches!(self.purpose_results[1], Some(Ok(()))) {
            self.first.get_or_insert(ServiceFailure::Purpose(1));
            return Err(CLOSED);
        }
        // Both callers still independently inspect this same live process
        // after receiving the packet. A half-close is not their completion:
        // keep the original process and all resident outputs until the same
        // immutable challenge cutoff, without accepting a third purpose.
        if self.lifetime.wait_until_cutoff_once(cutoff).is_err() {
            self.first.get_or_insert(ServiceFailure::Lifetime);
            return Err(CLOSED);
        }
        Ok(())
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            ServiceFailure::Startup => self.startup.failure(),
            ServiceFailure::Purpose(index) => self
                .purposes
                .get(index)?
                .as_ref()?
                .failure(&self.startup)
                .or_else(|| cause(&self.purposes.get(index)?.as_ref()?.retirement))
                .or_else(|| self.purpose_results.get(index).and_then(cause)),
            ServiceFailure::Lifetime => self.lifetime.failure(),
            ServiceFailure::Order => Some(&CLOSED),
        }
    }

    pub(crate) fn root_property_failure_view(
        &self,
    ) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        let ServiceFailure::Purpose(index) = self.first? else {
            return None;
        };
        self.purposes
            .get(index)?
            .as_ref()?
            .root_property_failure_view()
    }
}

fn credential_demand() -> Result<ResourceVector, AccountingError> {
    CacheSignerCredentialCaptureV1::receiving_demand_v1()?.checked_add(sample_pair_demand()?)
}

fn profile_demand() -> Result<ResourceVector, AccountingError> {
    let overflow = AccountingError::ArithmeticOverflow {
        dimension: D::MemoryBytes,
    };
    RootProfileOriginalCaptureV1::fixed_demand()
        .ok_or(overflow)?
        .checked_add(sample_pair_demand()?)
}

fn sample_pair_demand() -> Result<ResourceVector, AccountingError> {
    let sample = Sample::dynamic_demand()?;
    let overflow = AccountingError::ArithmeticOverflow {
        dimension: D::MemoryBytes,
    };
    let construction = size_of::<Sample>()
        .checked_mul(2)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(overflow)?;
    sample
        .checked_add(sample)?
        .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, construction))
}

// This private arithmetic port is called only by the two concrete capture
// fixed bodies above. It accepts no public vector or account and performs no IO.
fn admit_stage(
    common: &mut Common,
    stage: &mut StageOriginals,
    resident_files: u64,
) -> Result<(), CacheSignerReceivingClosedV1> {
    if !matches!(common.final_binding, Some(Ok(())))
        || stage.debit.is_some()
        || common.require_permanent_fd_coverage_v1().is_err()
    {
        return Err(CLOSED);
    }
    let additional = stage
        .demand
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .copied()
        .ok_or(CLOSED)?;
    stage.physical = Some((|| {
        let native = common.fixed_startup_demand()?;
        let attempted = native
            .checked_add(additional)?
            .get(D::OpenFiles)
            .checked_add(resident_files)
            .ok_or(AccountingError::ArithmeticOverflow {
                dimension: D::OpenFiles,
            })?;
        let limit =
            common
                .permanent_open_files()
                .map_err(|_| AccountingError::ArithmeticOverflow {
                    dimension: D::OpenFiles,
                })?;
        if attempted > limit {
            return Err(AccountingError::LimitExceeded {
                dimension: D::OpenFiles,
                limit,
                attempted,
            });
        }
        Ok(())
    })());
    if !matches!(stage.physical, Some(Ok(()))) {
        return Err(CLOSED);
    }
    let ledger = common.representation.as_mut().ok_or(CLOSED)?;
    stage.debit = Some(
        ledger
            .reserve(additional.with(D::OpenFiles, 0))
            .map_err(|_| CLOSED),
    );
    if matches!(stage.debit, Some(Ok(()))) {
        Ok(())
    } else {
        Err(CLOSED)
    }
}

fn observe_original(
    common: &mut Common,
    sample: &mut Sample,
) -> Result<(), CacheSignerReceivingClosedV1> {
    let anchor = common.cgroup.as_ref().ok_or(CLOSED)?;
    let identity = common
        .process_before
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .copied()
        .ok_or(CLOSED)?;
    let membership = common
        .membership
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .copied()
        .ok_or(CLOSED)?;
    sample.observe_once(
        &mut common.process,
        anchor,
        &common.limits,
        membership,
        identity,
        Some(aos_sandbox_broker::cache_signer_context::CACHE_SIGNER_TASK_CONTEXT_V1),
        true,
    )
}

fn cause<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value
        .as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|cause| cause as _)
}

struct CacheSignerServiceErrorV1 {
    original: CacheSignerServiceOriginalV1,
}

impl std::fmt::Display for CacheSignerServiceErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the original selected Cache signer service failed")?;
        // The actual worker Error borrows a MutexGuard. Format it while that
        // chronological original is locked; never return a dangling source.
        if let Some(view) = self.original.root_property_failure_view() {
            write!(formatter, ": {view:?}")
        } else if let Some(cause) = self.original.failure() {
            write!(formatter, ": {cause}")
        } else {
            Ok(())
        }
    }
}

impl std::fmt::Debug for CacheSignerServiceErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CacheSignerServiceErrorV1")
            .field("cause", &self.original.failure())
            .field("root_property", &self.original.root_property_failure_view())
            .finish_non_exhaustive()
    }
}

impl Error for CacheSignerServiceErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }
}

// Called only by the installed service's activation-selected entrance. Neither
// activation text nor these comparison IDs can create the actual F original.
/// Runs both fixed Current-proof purposes under the genuine original Cache F.
///
/// Captures the installed PID1 financial original, fixed companion/profile and
/// private credentials itself. No snapshot, key, payer, descriptor or completed
/// comparison can be supplied by the application coordinator.
///
/// # Errors
/// Returns the complete owning failure on native, original, financial, replay,
/// peer, signature, cutoff, or once-only lifecycle refusal. Never falls back to
/// ordinary service or resets the first purpose's original/debt.
pub fn run_selected_current_service_once(
    controller_uid: u32,
    controller_gid: u32,
    cache_uid: u32,
    cache_gid: u32,
) -> Result<(), Box<dyn Error>> {
    let mut original = CacheSignerServiceOriginalV1::new();
    let result = original
        .capture_startup_once(controller_uid, controller_gid, cache_uid, cache_gid)
        .and_then(|()| original.serve_two_current_purposes_once());
    if result.is_err() {
        // Move every reached native/error/model owner together; the returned
        // source borrows its original cause without cloning native IO errors.
        Err(Box::new(CacheSignerServiceErrorV1 { original }))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod service_lifecycle_tests {
    use super::*;

    #[test]
    fn missing_startup_original_cannot_mint_either_purpose_or_recapture_f() {
        use std::io::Write as _;
        use std::os::unix::process::ExitStatusExt as _;

        const CHILD: &str = "AOS_CACHE_MISSING_STARTUP_ORIGINAL_CHILD";
        const ASSERTIONS_REACHED: &str = "cache-missing-startup-original-assertions-reached";
        if std::env::var_os(CHILD).is_some() {
            let mut original = CacheSignerServiceOriginalV1::new();

            assert!(original.serve_two_current_purposes_once().is_err());
            assert!(original.serve_two_current_purposes_once().is_err());
            assert!(original.capture_startup_once(0, 0, 0, 0).is_err());

            assert!(!original.startup.common.entered);
            assert!(original.purposes.iter().all(Option::is_none));
            assert!(original.purpose_results.iter().all(Option::is_none));
            assert!(original.failure().is_some());

            println!("{ASSERTIONS_REACHED}");
            std::io::stdout().flush().unwrap();
            // The initial descriptor-table owner is armed at construction.
            // Its real Drop must abort even though service IO never entered.
            drop(original);
            panic!("dropping the original initial table unexpectedly returned");
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("service_original::service_lifecycle_tests::missing_startup_original_cannot_mint_either_purpose_or_recapture_f")
            .arg("--nocapture")
            .env(CHILD, "1")
            .output()
            .unwrap();

        assert!(String::from_utf8_lossy(&output.stdout).contains(ASSERTIONS_REACHED),
            "child did not reach all no-mint assertions: {}",
            String::from_utf8_lossy(&output.stderr));
        assert_eq!(output.status.signal(), Some(6),
            "the actual initial-table Drop must terminate with SIGABRT");
    }
}
