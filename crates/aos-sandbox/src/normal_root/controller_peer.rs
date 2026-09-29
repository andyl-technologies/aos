//! Compares the original Controller on Root's PRE-ROOT metadata connection.
//!
//! Actual PID1 delivery, original process/cgroup and sending socket SID are
//! compared under Root's selected startup owner. They do not seal Controller's
//! executable or authenticate a Ready worker/kernel request. No caller path,
//! identity tuple, OpenFile flag or decoded record constructs this peer.

use std::num::NonZeroU32;
use std::path::Path;

use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use aos_systemd::{OwnedValue, Value};

use super::{
    NormalRootStartupErrorV1 as Error, ProductionNormalRootStartupV1, client, retain_fixed_cgroup,
    service,
};
use crate::immutable_image::RetainedImmutableFileV1;

const UNIT: &str = "aos-sandboxd.service";
const CGROUP: &str = "aos.slice/aos-control.slice/aos-sandboxd.service";
const CONTEXT: &[u8] = b"system_u:system_r:aos_sandbox_controller_t:s0";

pub(crate) struct OriginalControllerPolicyPeerV1<'startup> {
    startup: &'startup ProductionNormalRootStartupV1,
    pid: NonZeroU32,
    cgroup: RetainedCgroupAnchor,
    fragment: RetainedImmutableFileV1,
    observed: service::ServiceObservationV1,
}

impl ProductionNormalRootStartupV1 {
    pub(crate) fn observe_controller_policy_peer(
        &self,
        stream: &RetainedUnixStream,
    ) -> Result<OriginalControllerPolicyPeerV1<'_>, Error> {
        self.recheck()?;
        stream.revalidate_original().map_err(|_| Error::Service)?;
        let pid = stream.peer().credentials().pid();
        let observed = observe(self, pid)?;
        let fragment = RetainedImmutableFileV1::observe_fragment(observed.fragment.clone())
            .map_err(|_| Error::Service)?;
        let peer = OriginalControllerPolicyPeerV1 {
            startup: self,
            pid,
            cgroup: retain_fixed_cgroup(Path::new(CGROUP))?,
            fragment,
            observed,
        };
        peer.recheck_stream(stream)?;
        Ok(peer)
    }
}

impl OriginalControllerPolicyPeerV1<'_> {
    pub(crate) fn recheck_stream(&self, stream: &RetainedUnixStream) -> Result<(), Error> {
        self.startup.recheck()?;
        stream.revalidate_original().map_err(|_| Error::Service)?;
        let credentials = stream.peer().credentials();
        if credentials.pid() != self.pid
            || credentials.uid() != self.startup.profile.identities[0]
            || credentials.gid() != self.startup.profile.identities[1]
        {
            return Err(Error::Service);
        }
        self.require_process(stream.peer().pidfd())?;
        service::require_same(&self.observed, &observe(self.startup, self.pid)?)?;
        self.fragment.revalidate().map_err(|_| Error::Service)
    }

    pub(crate) fn require_chunk(
        &self,
        stream: &RetainedUnixStream,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), Error> {
        self.recheck_stream(stream)?;
        let actual = chunk.subject().credentials();
        let expected = stream.peer().credentials();
        if chunk.socket_context() != CONTEXT
            || actual.pid() != expected.pid()
            || actual.uid() != expected.uid()
            || actual.gid() != expected.gid()
            || !chunk.subject().is_alive().map_err(|_| Error::Service)?
        {
            return Err(Error::Service);
        }
        self.require_process(chunk.subject().pidfd())
    }

    fn require_process(&self, process: &PidFd) -> Result<(), Error> {
        let info = self
            .cgroup
            .verify_exact_membership(process)
            .map_err(|_| Error::Service)?;
        let credentials = info.credentials().ok_or(Error::Service)?;
        let [uid, gid, _, _] = self.startup.profile.identities;
        if info.thread_group_id() != self.pid.get()
            || info.parent_pid() != 1
            || [
                credentials.real_user_id(),
                credentials.effective_user_id(),
                credentials.saved_user_id(),
                credentials.filesystem_user_id(),
            ] != [uid; 4]
            || [
                credentials.real_group_id(),
                credentials.effective_group_id(),
                credentials.saved_group_id(),
                credentials.filesystem_group_id(),
            ] != [gid; 4]
        {
            return Err(Error::Service);
        }
        Ok(())
    }
}

fn observe(
    startup: &ProductionNormalRootStartupV1,
    pid: NonZeroU32,
) -> Result<service::ServiceObservationV1, Error> {
    let (properties, unit) =
        service::read_properties(UNIT, pid.get(), service::SERVICE_PROPERTIES)?;
    service::immutable_observation(decode_delivery(
        &properties,
        &unit,
        startup.profile_file.path(),
    )?)
}

pub(super) fn decode_delivery(
    properties: &[OwnedValue],
    unit: &[OwnedValue],
    profile: &Path,
) -> Result<service::ServiceObservationV1, Error> {
    let Some(Value::Array(files)) = properties.get(1).map(|value| &**value) else {
        return Err(Error::Service);
    };
    // Optionality comes only from PID1's actual table. The existing strict
    // Controller decoder still checks every exact name/path/flag and duplicate.
    let tpm_image = match files.len() {
        1 => false,
        2 => true,
        _ => return Err(Error::Service),
    };
    client::decode_delivery(properties, unit, profile, tpm_image)
}
