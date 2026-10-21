//! Shares the fixed Root peer's native observations without role authority.
//!
//! The role owner keeps its real financial interval, image bookends and PID1
//! archive. This owner receives the original property tables at their existing
//! read boundary and retains native errors through the independently owed post.
//! Ordinary and selected entries use the existing two- and four-role decoders.

use std::error::Error;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use aos_sandbox_linux::cgroup::{CgroupV2Root, ExactCgroupMembershipReadbackV1,
    ExactCgroupMembershipRefusalV1, RetainedCgroupAnchor, RootInitialCgroupReadbackV1};
use aos_linux_descriptors::pidfd::PidFdInfo;
use aos_sandbox_linux::selinux_policy::{PolicyReadbackError, RetainedLiveSelinuxPolicyReadbackV1};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1;
use sha2::{Digest, Sha256};

use crate::immutable_image::{ImmutableImageErrorV1, ImmutableFileAcquisitionOriginalV1};
use crate::profile_data::{delivery, root_peer_data, schema};
use crate::profile_data::delivery::ServiceObservationV1;
use crate::profile_data::property_values::PropertyPairV1;
use super::RootObservationErrorV1 as Refusal;

/// Bounds the existing fixed Root property-table decoder materialization.
///
/// This DATA ceiling does not admit an archive or supply a financial interval.
pub const ROOT_PEER_MATERIALIZED_PROPERTY_BYTES_V1: usize = 64 * 1024;

/// Names the fixed Root peer properties read by both role-owned archives.
pub const ROOT_PEER_PROPERTIES_V1: &[&str] = &[
    "ControlGroup", "OpenFile", "ExtraFileDescriptorNames", "FileDescriptorStoreMax",
    "NFileDescriptorStore", "SELinuxContext", "CapabilityBoundingSet",
    "AmbientCapabilities", "NoNewPrivileges", "ExecStart", "ExecStartPre", "ExecStartPost",
];

/// Compares already-observed Root credentials without constructing a role.
///
/// # Errors
/// Refuses another task, parent, user or configured Root group.
pub fn require_root_process_identity_v1(
    pid: NonZeroU32,
    gid: u32,
    info: &PidFdInfo,
) -> Result<(), Refusal> {
    let credentials = info.credentials().ok_or(Refusal::Service)?;
    if info.thread_group_id() != pid.get() || info.parent_pid() != 1
        || credentials.real_user_id() != 0 || credentials.effective_user_id() != 0
        || credentials.saved_user_id() != 0 || credentials.filesystem_user_id() != 0
        || credentials.real_group_id() != gid || credentials.effective_group_id() != gid
        || credentials.saved_group_id() != gid || credentials.filesystem_group_id() != gid
    {
        return Err(Refusal::Service);
    }
    Ok(())
}

/// Retains the fixed Root connection's anchor, fragment and comparison baseline.
pub struct RootPeerConnectionOriginalsV1 {
    capture: RootInitialCgroupReadbackV1,
    capture_result: Option<Result<(), aos_linux_descriptors::Error>>,
    anchor: Option<(CgroupV2Root, RetainedCgroupAnchor)>,
    fragment: ImmutableFileAcquisitionOriginalV1,
    baseline: Option<ServiceObservationV1>,
}

impl RootPeerConnectionOriginalsV1 {
    /// Creates an empty native DATA owner without observing or admitting a peer.
    pub fn new() -> Self {
        Self {
            capture: RootInitialCgroupReadbackV1::new(), capture_result: None,
            anchor: None, fragment: ImmutableFileAcquisitionOriginalV1::new(), baseline: None,
        }
    }

    /// Returns the actual fixed Root socket-context receiving geometry.
    ///
    /// # Errors
    /// Refuses checked native receiving geometry overflow.
    pub fn receive_geometry() -> Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError> {
        SubjectStreamReceiveGeometryV1::for_context_bytes(schema::CONTEXT.len())
    }

    fn capture_anchor_once(&mut self) -> Result<(), Refusal> {
        if self.capture_result.is_none() {
            self.capture_result = Some(self.capture.capture_once());
            if matches!(self.capture_result, Some(Ok(()))) {
                self.anchor = self.capture.take_validated_pair();
            }
        }
        if self.anchor.is_none() { return Err(Refusal::Service); }
        Ok(())
    }

    /// Returns the fixed fragment acquisition byte/native geometry.
    ///
    /// The role's whole peer envelope already names the same one fragment
    /// file. This helper supplies the additional retained initial-prefix bytes;
    /// its file count is not an additional independent open.
    pub fn fragment_acquisition_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(4096)
    }

    /// Borrows the actual captured anchor as comparison DATA only.
    pub fn anchor_data_v1(&self) -> Option<&RetainedCgroupAnchor> {
        self.anchor.as_ref().map(|(_, anchor)| anchor)
    }

    /// Borrows the earliest actual anchor or fragment native failure.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.capture.failure().or_else(|| self.fragment.failure())
    }
}

impl Default for RootPeerConnectionOriginalsV1 {
    fn default() -> Self { Self::new() }
}

#[derive(Clone, Copy)]
enum Delivery { Ordinary, Selected, SelectedProducer }

/// Owns one native Root peer interval while its role retains admission and payment.
pub struct RootPeerObservationOriginalsV1<E> {
    delivery: Delivery,
    entered: bool,
    stream_before: Option<Result<(), aos_linux_descriptors::Error>>,
    nomination: Option<Result<(), E>>,
    membership_before: ExactCgroupMembershipReadbackV1,
    membership_before_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    identity_before: Option<Result<(), E>>,
    properties_before: Option<Result<PropertyPairV1, E>>,
    canonical_before: Option<std::io::Result<PathBuf>>,
    observed_before: Option<Result<ServiceObservationV1, E>>,
    producer_before: Option<[u8; 16]>,
    fragment_before: Option<Result<(), ImmutableImageErrorV1>>,
    unit: Option<Result<Vec<u8>, E>>,
    unit_binding: Option<Result<(), E>>,
    policy_before: RetainedLiveSelinuxPolicyReadbackV1,
    policy_before_result: Option<Result<(), PolicyReadbackError>>,
    begin: Option<Result<(), E>>,
    stream_after: Option<Result<(), aos_linux_descriptors::Error>>,
    membership_after: ExactCgroupMembershipReadbackV1,
    membership_after_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    identity_after: Option<Result<(), E>>,
    properties_after: Option<Result<PropertyPairV1, E>>,
    canonical_after: Option<std::io::Result<PathBuf>>,
    observed_after: Option<Result<ServiceObservationV1, E>>,
    producer_after: Option<[u8; 16]>,
    property_binding: Option<Result<(), E>>,
    fragment_after: Option<Result<(), ImmutableImageErrorV1>>,
    policy_after: RetainedLiveSelinuxPolicyReadbackV1,
    policy_after_result: Option<Result<(), PolicyReadbackError>>,
    finish: Option<Result<(), E>>,
    closed: Option<E>,
}

impl<E> RootPeerObservationOriginalsV1<E>
where E: Error + From<Refusal> + 'static,
{
    /// Creates the existing ordinary two-delivery-role native observer.
    pub fn ordinary() -> Self { Self::new(Delivery::Ordinary) }

    /// Creates the selected four-delivery-role native observer.
    ///
    /// This selects comparison semantics only. The caller still owns its real
    /// fixed-role original, profile association, payment and operation interval.
    pub fn selected() -> Self { Self::new(Delivery::Selected) }

    /// Creates the selected four-role observer with the SAME PID1 producer.
    ///
    /// The role must pay the exact thirteen-property flight and retain its own
    /// admission. This entry supplies comparison DATA and creates no grant.
    pub fn selected_with_resource_producer_v1() -> Self {
        Self::new(Delivery::SelectedProducer)
    }

    /// Borrows recipient and producer from this original successful before.
    ///
    /// This readonly DATA does not complete the interval or authenticate Hello.
    pub fn selected_resource_subjects_v1(&self) -> Option<([u8; 16], [u8; 16])> {
        if !matches!(self.delivery, Delivery::SelectedProducer)
            || !matches!(self.begin, Some(Ok(())))
        {
            return None;
        }
        let observed = self.observed_before.as_ref()?.as_ref().ok()?;
        Some((observed.invocation, self.producer_before?))
    }

    fn new(delivery: Delivery) -> Self {
        Self {
            delivery, entered: false,
            stream_before: None, nomination: None,
            membership_before: ExactCgroupMembershipReadbackV1::new(), membership_before_result: None,
            identity_before: None, properties_before: None, canonical_before: None, observed_before: None, producer_before: None,
            fragment_before: None, unit: None, unit_binding: None,
            policy_before: RetainedLiveSelinuxPolicyReadbackV1::new(), policy_before_result: None, begin: None,
            stream_after: None,
            membership_after: ExactCgroupMembershipReadbackV1::new(), membership_after_result: None,
            identity_after: None, properties_after: None, canonical_after: None, observed_after: None, producer_after: None,
            property_binding: None, fragment_after: None,
            policy_after: RetainedLiveSelinuxPolicyReadbackV1::new(), policy_after_result: None,
            finish: None, closed: None,
        }
    }
    /// Returns the bounded native byte and descriptor envelope for this owner.
    ///
    /// Actual PID1 archive rows and the caller's image observations are paid
    /// separately before construction. Rust controls are not namespace entries.
    pub fn receiving_demand_v1() -> Option<aos_sandbox_model::ResourceVector> {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        let policy = RetainedLiveSelinuxPolicyReadbackV1::receiving_demand_v1();
        let membership = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(membership.checked_mul(2)?)?
            .checked_add(policy.memory_bytes.checked_mul(2)?)?
            .checked_add(8 * 65_536 + 32 * 4096)?
            .checked_add(usize::try_from(RootPeerConnectionOriginalsV1::fragment_acquisition_demand_v1()?
                .get(D::MemoryBytes)).ok()?)?;
        Some(ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
            .with(D::OpenFiles, 6 + 1 + 2 * 2 + 2 * policy.open_files as u64))
    }

    /// Runs native connection and membership checks before the property read.
    ///
    /// # Errors
    /// Refuses reentry or the original stream, nomination, anchor or identity.
    pub fn begin_before_properties_once(
        &mut self, profile: Result<&schema::NormalRootProfileV1, Refusal>,
        peer: &mut RootPeerConnectionOriginalsV1, stream: &RetainedUnixStream,
    ) -> Result<(), Refusal> {
        if self.entered { self.closed.get_or_insert(Refusal::Service.into()); return Err(Refusal::Service); }
        self.entered = true;
        let result: Result<(), Refusal> = (|| {
            self.stream_before = Some(stream.revalidate_original());
            positive(&self.stream_before)?;
            let profile = profile?;
            let credentials = stream.peer().credentials();
            self.nomination = Some((if credentials.uid() == 0 && credentials.gid() == profile.identities[1] {
                Ok(())
            } else { Err(Refusal::Service) }).map_err(E::from));
            positive(&self.nomination)?;
            peer.capture_anchor_once()?;
            let (_, anchor) = peer.anchor.as_ref().ok_or(Refusal::Service)?;
            self.membership_before_result = Some(self.membership_before.capture_once(anchor, stream.peer().pidfd()));
            self.identity_before = Some(self.membership_before.result()
                .and_then(|result| result.as_ref().ok()).ok_or(Refusal::Service)
                .and_then(|info| require_root_process_identity_v1(credentials.pid(), profile.identities[1], info)).map_err(E::from));
            positive(&self.identity_before)?;
            Ok(())
        })();
        if result.is_err() { self.begin = Some(result.map_err(E::from)); }
        result
    }

    /// Moves the actual archive output before the remaining native comparisons.
    ///
    /// # Errors
    /// Preserves property, unit, fragment and live-policy refusals in order.
    pub fn begin_after_properties_once(
        &mut self, profile: Result<&schema::NormalRootProfileV1, Refusal>,
        profile_path: Result<&Path, Refusal>,
        peer: &mut RootPeerConnectionOriginalsV1, stream: &RetainedUnixStream,
        properties: Result<PropertyPairV1, E>,
    ) -> Result<(), Refusal> {
        if !self.entered || self.begin.is_some() {
            self.closed.get_or_insert(Refusal::Service.into()); return Err(Refusal::Service);
        }
        self.properties_before = Some(properties);
        let credentials = stream.peer().credentials();
        let result: Result<(), Refusal> = (|| {
            self.observed_before = Some(decode_observation(
                profile?, profile_path, self.delivery, positive(&self.properties_before)?, credentials.pid().get(), &mut self.canonical_before, &mut self.producer_before,
            ).map_err(E::from));
            let observed = positive(&self.observed_before)?;
            let profile = profile?;
            if let Some(baseline) = &peer.baseline { delivery::require_same(baseline, observed).map_err(Refusal::from)?; }
            self.fragment_before = Some(if peer.fragment.completed_measurement().is_some() {
                peer.fragment.revalidate_completed()
            } else {
                peer.fragment.open_and_measure_once(observed.fragment.clone(), None, 64 * 1024, false)
            });
            positive(&self.fragment_before)?;
            // The original fragment stays on the connection. Reading and normalizing
            // it uses the SAME existing pure Root unit placeholder recipe.
            self.unit = Some((|| {
                peer.fragment.read_completed_bounded().map_err(|_| Refusal::Image)?;
                schema::normalized_unit(peer.fragment.bytes(), profile_path?.to_str().ok_or(Refusal::Profile)?).map_err(Refusal::from)
            })().map_err(E::from));
            self.unit_binding = Some((if <[u8; 32]>::from(Sha256::digest(positive(&self.unit)?)) == profile.unit_sha256 {
                Ok(())
            } else { Err(Refusal::Service) }).map_err(E::from));
            positive(&self.unit_binding)?;
            self.policy_before_result = Some(self.policy_before.verify_once(&profile.canonical_policy.path));
            positive(&self.policy_before_result)?;
            if self.policy_before.verified().map(|policy| policy.digest()) != Some(profile.canonical_policy.sha256) {
                return Err(Refusal::Confinement);
            }
            Ok(())
        })();
        self.begin = Some(result.map_err(E::from));
        result
    }

    /// Performs the independently owed connection and membership post.
    ///
    /// # Errors
    /// Refuses only repeated finish; reached native failures remain resident.
    pub fn finish_before_properties_once(
        &mut self, profile: Result<&schema::NormalRootProfileV1, Refusal>,
        peer: &mut RootPeerConnectionOriginalsV1, stream: &RetainedUnixStream,
    ) -> Result<(), Refusal> {
        if self.finish.is_some() || self.stream_after.is_some() {
            self.closed.get_or_insert(Refusal::Service.into()); return Err(Refusal::Service);
        }
        self.stream_after = Some(stream.revalidate_original());
        if let Some((_, anchor)) = &peer.anchor {
            self.membership_after_result = Some(self.membership_after.capture_once(anchor, stream.peer().pidfd()));
        }
        self.identity_after = Some((|| -> Result<(), Refusal> {
            let profile = profile?;
            let info = self.membership_after.result().and_then(|result| result.as_ref().ok()).ok_or(Refusal::Service)?;
            require_root_process_identity_v1(stream.peer().credentials().pid(), profile.identities[1], info)
        })().map_err(E::from));
        Ok(())
    }

    /// Moves the actual post table and performs independently owed native posts.
    ///
    /// # Errors
    /// Preserves before refusal ahead of property, fragment and policy posts.
    pub fn finish_after_properties_once(
        &mut self, profile: Result<&schema::NormalRootProfileV1, Refusal>,
        profile_path: Result<&Path, Refusal>,
        peer: &mut RootPeerConnectionOriginalsV1, stream: &RetainedUnixStream,
        properties: Option<Result<PropertyPairV1, E>>,
    ) -> Result<(), Refusal> {
        if self.finish.is_some() || self.stream_after.is_none() {
            self.closed.get_or_insert(Refusal::Service.into()); return Err(Refusal::Service);
        }
        self.properties_after = properties;
        if self.properties_after.is_some() {
            self.observed_after = Some((|| -> Result<ServiceObservationV1, Refusal> {
                decode_observation(profile?, profile_path, self.delivery,
                    positive(&self.properties_after)?, stream.peer().credentials().pid().get(),
                    &mut self.canonical_after, &mut self.producer_after)
            })().map_err(E::from));
        }
        self.property_binding = Some((|| -> Result<(), Refusal> {
            delivery::require_same(positive(&self.observed_before)?, positive(&self.observed_after)?).map_err(Refusal::from)?;
            if matches!(self.delivery, Delivery::SelectedProducer)
                && (self.producer_before.is_none() || self.producer_before != self.producer_after)
            {
                return Err(Refusal::Service);
            }
            Ok(())
        })().map_err(E::from));
        self.fragment_after = Some(peer.fragment.revalidate_completed());
        if let Ok(profile) = profile {
            self.policy_after_result = Some(self.policy_after.verify_once(&profile.canonical_policy.path));
        }
        let result: Result<(), Refusal> = (|| {
                positive(&self.begin)?;
                positive(&self.stream_after)?;
                positive(&self.identity_after)?;
                positive(&self.property_binding)?;
                positive(&self.fragment_after)?;
                positive(&self.policy_after_result)?;
                let profile = profile?;
                if self.policy_after.verified().map(|policy| policy.digest()) != Some(profile.canonical_policy.sha256) {
                    return Err(Refusal::Confinement);
                }
                Ok(())
        })();
        self.finish = Some(result.map_err(E::from));
        result
    }

    /// Moves the first complete comparison baseline after the caller's own posts.
    ///
    /// This moves DATA only and settles no role or financial stage.
    ///
    /// # Errors
    /// Refuses incomplete or closed native comparisons.
    pub fn retain_completed_baseline_once(&mut self, peer: &mut RootPeerConnectionOriginalsV1)
        -> Result<(), Refusal>
    {
        if !self.complete() { return Err(Refusal::Service); }
        if peer.baseline.is_none() {
            if let Some(Ok(observed)) = self.observed_before.take() { peer.baseline = Some(observed); }
        }
        Ok(())
    }

    /// Reports complete native comparisons without granting role admission.
    pub fn complete(&self) -> bool {
        self.closed.is_none() && matches!(self.finish, Some(Ok(())))
    }

    /// Borrows the earliest native failure before the caller's operation.
    pub fn before_failure<'a>(&'a self, peer: &'a RootPeerConnectionOriginalsV1)
        -> Option<&'a (dyn Error + 'static)>
    {
        failure(&self.stream_before).or_else(|| failure(&self.nomination))
            .or_else(|| peer.capture.failure())
            .or_else(|| self.membership_before.failure().map(|error| error as _))
            .or_else(|| failure(&self.identity_before)).or_else(|| failure(&self.properties_before))
            .or_else(|| self.canonical_before.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| failure(&self.observed_before))
            .or_else(|| if matches!(self.fragment_before, Some(Err(_))) {
                peer.fragment.failure().or_else(|| failure(&self.fragment_before))
            } else { None })
            .or_else(|| failure(&self.unit)).or_else(|| failure(&self.unit_binding))
            .or_else(|| self.policy_before.failure()).or_else(|| failure(&self.begin))
    }

    /// Borrows an independently owed post failure after the caller's bookend.
    pub fn after_failure<'a>(&'a self, peer: &'a RootPeerConnectionOriginalsV1)
        -> Option<&'a (dyn Error + 'static)>
    {
        failure(&self.stream_after)
            .or_else(|| self.membership_after.failure().map(|error| error as _))
            .or_else(|| failure(&self.identity_after)).or_else(|| failure(&self.properties_after))
            .or_else(|| self.canonical_after.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _))
            .or_else(|| failure(&self.observed_after)).or_else(|| failure(&self.property_binding))
            .or_else(|| if matches!(self.fragment_after, Some(Err(_))) {
                peer.fragment.failure().or_else(|| failure(&self.fragment_after))
            } else { None })
            .or_else(|| self.policy_after.failure())
            .or_else(|| failure(&self.finish))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

fn decode_observation(
    profile: &schema::NormalRootProfileV1,
    profile_path: Result<&Path, Refusal>, delivery: Delivery,
    properties: &PropertyPairV1, pid: u32,
    canonical: &mut Option<std::io::Result<PathBuf>>,
    producer: &mut Option<[u8; 16]>,
) -> Result<ServiceObservationV1, Refusal> {
    let path = profile_path.map_err(|_| Refusal::Profile)?;
    let (values, unit) = properties;
    match delivery {
        Delivery::Ordinary => root_peer_data::decode_peer_properties_into(path, pid, profile, values, unit, canonical),
        Delivery::Selected => root_peer_data::decode_selected_root_peer_properties_into(path, pid, profile, values, unit, canonical),
        Delivery::SelectedProducer => {
            root_peer_data::decode_selected_root_peer_with_producer_into(
                path, pid, profile, values, unit, canonical,
            ).map(|(observed, actual)| { *producer = Some(actual); observed })
        }
    }.map_err(Into::into)
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, Refusal> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Refusal::Service)
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_linux_descriptors::pidfd::PidFd;

    #[test]
    fn actual_pidfd_identity_cannot_be_rebound_to_another_root_task() {
        let pid = NonZeroU32::new(std::process::id()).unwrap();
        let process = PidFd::open(pid).unwrap();
        let observed = process.info().unwrap();
        let other = if observed.thread_group_id() == u32::MAX { 1 } else { u32::MAX };
        let other = NonZeroU32::new(other).unwrap();

        let result = require_root_process_identity_v1(other, 0, &observed);

        assert_eq!(result, Err(Refusal::Service));
        assert_eq!(observed.pid(), pid.get());
    }
}
