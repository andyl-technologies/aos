//! Preserves the fixed startup Root peer inside its private C observation.
//!
//! Actual P/I/Q/J origins now retain their exclusive archive in this profile.
//! This same native peer also retains the startup recipe; callers supply no
//! success callback, native finish, comparison result or financial amount.

use std::num::NonZeroU32;
use std::path::Path;
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use crate::immutable_image::RetainedImmutableFileV1;
use crate::profile_data::native_observation::retain_cgroup_anchor_data_v1 as retain_fixed_cgroup;
use crate::profile_data::images::require_unit;
use super::{ControllerSelfProfileOriginalV1, ControllerProfileErrorV1, baseline, delivery,
    observer, root_peer_data, schema};
use super::observer as service;

impl ControllerSelfProfileOriginalV1 {
    // Only the original-flight coordinator can consume this real
    // stream join. No public digest/path/peer or readiness factory exists.
    /// Observes the fixed Root peer through this actual private startup receiver.
    ///
    /// # Errors
    /// Preserves original profile, stream, process, unit or native scope refusal.
    #[doc(hidden)]
    pub fn observe_original_peer<'profile>(
        &'profile self,
        stream: &RetainedUnixStream,
    ) -> Result<ControllerStartupRootPeerV1<'profile>, ControllerProfileErrorV1> {
        let startup = self.use_original_startup_receiver_v1()?;
        if let Some(baseline) = self.baseline.as_ref().filter(|_| startup) {
            return baseline.run_peer(|| self.observe_original_peer_original(stream));
        }
        self.observe_original_peer_original(stream)
    }

    fn observe_original_peer_original<'profile>(
        &'profile self,
        stream: &RetainedUnixStream,
    ) -> Result<ControllerStartupRootPeerV1<'profile>, ControllerProfileErrorV1> {
        self.recheck()?;
        stream
            .revalidate_original()
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        let cgroup = retain_fixed_cgroup(Path::new(
            "system.slice/aos-sandbox-policy-authorityd.service",
        ))?;
        let pid = stream.peer().credentials().pid();
        let observed = self.observe_original_peer_properties(pid.get())?;
        let fragment = RetainedImmutableFileV1::observe_fragment(observed.fragment.clone())
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        require_unit(&fragment, &self.profile_file, &self.profile)?;
        let retained = ControllerStartupRootPeerV1 {
            profile: self,
            pid,
            cgroup,
            fragment,
            observed,
        };
        retained.recheck_stream(stream)?;
        Ok(retained)
    }

    fn observe_original_peer_properties(
        &self,
        pid: u32,
    ) -> Result<delivery::ServiceObservationV1, ControllerProfileErrorV1> {
        let (values, unit) = self.read_original_properties(
            schema::UNIT, pid, service::PEER_PROPERTIES,
        )?;
        root_peer_data::decode_peer_properties(self.profile_file.path(), pid, &self.profile, &values, &unit)
    }
}

/// Retains the actual Root stream/profile/native conjunction.
///
/// Fields are private and the complete same-C recipe is its only constructor.
#[must_use]
pub struct ControllerStartupRootPeerV1<'profile> {
    profile: &'profile ControllerSelfProfileOriginalV1,
    pid: NonZeroU32,
    cgroup: RetainedCgroupAnchor,
    fragment: RetainedImmutableFileV1,
    observed: delivery::ServiceObservationV1,
}

impl ControllerStartupRootPeerV1<'_> {
    /// Returns the original admitted source identity as comparison DATA.
    #[must_use]
    pub fn source_uid(&self) -> u32 {
        self.profile.profile.identities[0]
    }

    /// Rechecks this same stream and original measured Root peer.
    ///
    /// # Errors
    /// Refuses changed process, subject, delivery or native observation state.
    pub fn recheck_stream(
        &self,
        stream: &RetainedUnixStream,
    ) -> Result<(), ControllerProfileErrorV1> {
        let startup = self.profile.use_original_startup_receiver_v1()?;
        if let Some(baseline) = self.profile.baseline.as_ref().filter(|_| startup) {
            return baseline.run(baseline::ScopeKind::Peer, || self.recheck_stream_original(stream));
        }
        self.recheck_stream_original(stream)
    }

    fn recheck_stream_original(
        &self,
        stream: &RetainedUnixStream,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.profile.recheck()?;
        stream
            .revalidate_original()
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        let credentials = stream.peer().credentials();
        if credentials.pid() != self.pid
            || credentials.uid() != 0
            || credentials.gid() != self.profile.profile.identities[1]
        {
            return Err(ControllerProfileErrorV1::Service);
        }
        self.require_process(stream.peer().pidfd())?;
        let observed = self.profile.observe_original_peer_properties(self.pid.get())?;
        delivery::require_same(&self.observed, &observed)?;
        require_unit(
            &self.fragment,
            &self.profile.profile_file,
            &self.profile.profile,
        )
    }

    /// Compares one actual chunk's subject with this same stream and peer.
    ///
    /// # Errors
    /// Refuses changed stream/process, sender credentials, context or liveness.
    pub fn require_chunk(
        &self,
        stream: &RetainedUnixStream,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.recheck_stream(stream)?;
        let actual = chunk.subject().credentials();
        let expected = stream.peer().credentials();
        if chunk.socket_context() != schema::CONTEXT.as_bytes()
            || actual.pid() != expected.pid()
            || actual.uid() != expected.uid()
            || actual.gid() != expected.gid()
            || !chunk
                .subject()
                .is_alive()
                .map_err(|_| ControllerProfileErrorV1::Service)?
        {
            return Err(ControllerProfileErrorV1::Service);
        }
        self.require_process(chunk.subject().pidfd())
    }

    fn require_process(&self, process: &PidFd) -> Result<(), ControllerProfileErrorV1> {
        let info = self
            .cgroup
            .verify_exact_membership(process)
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        root_peer_data::require_root_process_identity_data_v1(
            self.pid, self.profile.profile.identities[1], &info,
        )
    }
}
