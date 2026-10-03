//! Versioned, non-authorizing physical readback of the shifted payload PID 1.
//!
//! The canonical record is a bounded JSON object with `version: 1`. Its fields
//! bind the exact assignment, systemd invocation and launch binding to the
//! pinned process instance, four pidfd-acquired namespaces, and both actual
//! private-user maps. A decoded record is data, not a substitute for the live
//! pidfd and protected launch transaction that produced it.
//!
//! ```text
//! {"version":1,"host_boot_id":[16 octets],"sandbox_id":[16 octets],
//!  "incarnation_id":[16 octets],"assignment_epoch":u64,
//!  "desired_generation":u64,"assignment_digest":[32 octets],
//!  "launch_binding":[32 octets],"invocation_id":[16 octets],
//!  "payload_pid":u32,"payload_parent_pid":u32,
//!  "payload_start_time_ticks":u64,"payload_cgroup_id":u64,
//!  "user_namespace":{"device":u64,"inode":u64}, ...,
//!  "host_uid_start":u32,"host_gid_start":u32,"mapping_count":u32}
//! ```

use std::fs::File;
use std::io::Read as _;

use aos_sandbox_linux::pidfd::{NamespaceIdentity, NamespaceKind};
use aos_systemd::SandboxUnitSpec;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{HostRuntimeIdentity, PinnedLeader, PinnedPayloadLeader};
use crate::state::transition::{NamespaceProofSnapshot, RuntimeProofSnapshot};
use crate::{HostError, Result};

const VERSION: u8 = 1;
const MAXIMUM_RECORD_BYTES: usize = 2048;
const MAXIMUM_ID_MAP_BYTES: usize = 128;
const DIGEST_DOMAIN: &[u8] = b"aos.sandbox.shifted-payload-inspection.v1\0";

/// Captures one exact, versioned shifted-payload kernel observation.
///
/// Decoding validates the data contract but does not make a record trusted.
/// Physical authority requires [`VerifiedShiftedPayloadInspectionV1`] and its
/// live process pins at the decision boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShiftedPayloadInspectionRecordV1 {
    version: u8,
    host_boot_id: [u8; 16],
    sandbox_id: [u8; 16],
    incarnation_id: [u8; 16],
    assignment_epoch: u64,
    desired_generation: u64,
    assignment_digest: [u8; 32],
    launch_binding: [u8; 32],
    invocation_id: [u8; 16],
    payload_pid: u32,
    payload_parent_pid: u32,
    payload_start_time_ticks: u64,
    payload_cgroup_id: u64,
    user_namespace: NamespaceProofSnapshot,
    mount_namespace: NamespaceProofSnapshot,
    network_namespace: NamespaceProofSnapshot,
    pid_namespace: NamespaceProofSnapshot,
    host_user_namespace: NamespaceProofSnapshot,
    host_pid_namespace: NamespaceProofSnapshot,
    host_uid_start: u32,
    host_gid_start: u32,
    mapping_count: u32,
}

impl ShiftedPayloadInspectionRecordV1 {
    /// Encodes the fixed-field record in its canonical, bounded form.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or exceeds the record bound.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| HostError::Worker(format!("cannot encode shifted proof: {error}")))?;
        if bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(HostError::Worker(
                "shifted proof exceeds its bound".to_owned(),
            ));
        }
        Ok(bytes)
    }

    /// Decodes only an exact canonical version-one record.
    ///
    /// # Errors
    ///
    /// Rejects oversized, noncanonical, unsupported, or incomplete records.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAXIMUM_RECORD_BYTES {
            return Err(HostError::Worker(
                "shifted proof exceeds its bound".to_owned(),
            ));
        }
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|error| HostError::Worker(format!("invalid shifted proof: {error}")))?;
        record.validate()?;
        if record.encode()? != bytes {
            return Err(HostError::Worker("noncanonical shifted proof".to_owned()));
        }
        Ok(record)
    }

    /// Returns a domain-separated digest of the canonical record.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be encoded within its bound.
    pub fn digest(&self) -> Result<[u8; 32]> {
        let mut hash = Sha256::new();
        hash.update(DIGEST_DOMAIN);
        hash.update(self.encode()?);
        Ok(hash.finalize().into())
    }

    fn validate(&self) -> Result<()> {
        let namespaces = [
            self.user_namespace,
            self.mount_namespace,
            self.network_namespace,
            self.pid_namespace,
            self.host_user_namespace,
            self.host_pid_namespace,
        ];
        if self.version != VERSION
            || self.host_boot_id == [0; 16]
            || self.sandbox_id == [0; 16]
            || self.incarnation_id == [0; 16]
            || self.assignment_epoch == 0
            || self.desired_generation == 0
            || self.assignment_digest == [0; 32]
            || self.launch_binding == [0; 32]
            || self.invocation_id == [0; 16]
            || self.payload_pid <= 1
            || self.payload_parent_pid <= 1
            || self.payload_start_time_ticks == 0
            || self.payload_cgroup_id == 0
            || namespaces.iter().any(|ns| ns.device == 0 || ns.inode == 0)
            || self.user_namespace == self.host_user_namespace
            || self.pid_namespace == self.host_pid_namespace
            || self.host_uid_start == 0
            || self.host_gid_start == 0
            || self.mapping_count < 65_536
            || self
                .host_uid_start
                .checked_add(self.mapping_count)
                .is_none()
            || self
                .host_gid_start
                .checked_add(self.mapping_count)
                .is_none()
        {
            return Err(HostError::Worker("incomplete shifted proof".to_owned()));
        }
        Ok(())
    }
}

/// Owns evidence produced from a live, exact bound payload inspection.
///
/// This token is intentionally absent during observation-only recovery: a
/// durable runtime snapshot cannot reconstruct the exact launch mapping.
#[derive(Debug)]
pub struct VerifiedShiftedPayloadInspectionV1 {
    record: ShiftedPayloadInspectionRecordV1,
}

impl VerifiedShiftedPayloadInspectionV1 {
    pub(super) fn inspect(
        identity: &HostRuntimeIdentity,
        spec: &SandboxUnitSpec,
        invocation_id: [u8; 16],
        supervisor: &PinnedLeader,
        payload: &PinnedPayloadLeader,
        proof: &RuntimeProofSnapshot,
    ) -> Result<Self> {
        if spec.name()
            != &aos_systemd::SandboxUnitName::from_incarnation(*identity.incarnation_id())
            || !proof.validate()
        {
            return Err(HostError::Worker(
                "shifted proof has foreign launch scope".to_owned(),
            ));
        }
        let launch_binding = spec
            .launch_binding()
            .ok_or_else(|| HostError::Worker("shifted proof requires a bound launch".to_owned()))?;
        payload.recheck_kernel(supervisor)?;
        let before = payload
            .pidfd()
            .process_identity()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if before.pid() != proof.payload.pid
            || before.thread_group_id() != proof.payload.thread_group_id
            || before.parent_pid() != proof.payload.parent_pid
            || before.cgroup_id() != Some(proof.payload.cgroup_id)
            || before.start_time_ticks() != proof.payload.start_time_ticks
        {
            return Err(HostError::Worker(
                "shifted payload differs from launch proof".to_owned(),
            ));
        }

        // These four ioctls are performed by the actual Host service against
        // the actual shifted payload, never against a phase-zero surrogate.
        let host = super::PidfdNamespaceAccessProbe::current_service()?;
        let user = payload
            .pidfd()
            .namespace(NamespaceKind::User)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let mount = payload
            .pidfd()
            .namespace(NamespaceKind::Mount)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let network = payload
            .pidfd()
            .namespace(NamespaceKind::Network)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        let pid = payload
            .pidfd()
            .namespace(NamespaceKind::Pid)
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if user.identity() != payload.user().identity()
            || mount.identity() != payload.mount().identity()
            || network.identity() != payload.network().identity()
            || pid.identity() != payload.pid().identity()
            || namespace_snapshot(user.identity()) != proof.user_namespace
            || namespace_snapshot(mount.identity()) != proof.mount_namespace
            || namespace_snapshot(network.identity()) != proof.network_namespace
            || user.identity() == host.user().identity()
            || pid.identity() == host.pid().identity()
        {
            return Err(HostError::Worker(
                "payload is not in the pinned shifted namespaces".to_owned(),
            ));
        }

        let (host_id_start, mapping_count) = spec.private_user_range();
        read_exact_id_map(before.pid(), "uid_map", host_id_start, mapping_count)?;
        read_exact_id_map(before.pid(), "gid_map", host_id_start, mapping_count)?;

        let after = payload
            .pidfd()
            .process_identity()
            .map_err(|error| HostError::Worker(error.to_string()))?;
        if before != after
            || !payload
                .pidfd()
                .is_alive()
                .map_err(|error| HostError::Worker(error.to_string()))?
        {
            return Err(HostError::Worker(
                "shifted payload changed during inspection".to_owned(),
            ));
        }
        payload.recheck_kernel(supervisor)?;

        let record = ShiftedPayloadInspectionRecordV1 {
            version: VERSION,
            host_boot_id: proof.host_boot_id,
            sandbox_id: *identity.sandbox_id(),
            incarnation_id: *identity.incarnation_id(),
            assignment_epoch: identity.assignment_epoch(),
            desired_generation: identity.desired_generation(),
            assignment_digest: *identity.assignment_digest(),
            launch_binding,
            invocation_id,
            payload_pid: before.pid(),
            payload_parent_pid: before.parent_pid(),
            payload_start_time_ticks: before.start_time_ticks(),
            payload_cgroup_id: before.cgroup_id().ok_or_else(|| {
                HostError::Worker("kernel omitted shifted payload cgroup ID".to_owned())
            })?,
            user_namespace: namespace_snapshot(user.identity()),
            mount_namespace: namespace_snapshot(mount.identity()),
            network_namespace: namespace_snapshot(network.identity()),
            pid_namespace: namespace_snapshot(pid.identity()),
            host_user_namespace: namespace_snapshot(host.user().identity()),
            host_pid_namespace: namespace_snapshot(host.pid().identity()),
            host_uid_start: host_id_start,
            host_gid_start: host_id_start,
            mapping_count,
        };
        record.validate()?;
        Ok(Self { record })
    }

    /// Returns the physical observation as bounded canonical readback data.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be encoded within its bound.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.record.encode()
    }

    /// Returns a digest of the exact physical observation.
    ///
    /// # Errors
    ///
    /// Returns an error if the record cannot be encoded within its bound.
    pub fn digest(&self) -> Result<[u8; 32]> {
        self.record.digest()
    }
}

fn namespace_snapshot(value: NamespaceIdentity) -> NamespaceProofSnapshot {
    NamespaceProofSnapshot {
        device: value.device,
        inode: value.inode,
    }
}

fn read_exact_id_map(pid: u32, kind: &'static str, host_start: u32, count: u32) -> Result<()> {
    let path = format!("/proc/{pid}/{kind}");
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| HostError::Worker(format!("cannot open payload {kind}: {error}")))?;
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take((MAXIMUM_ID_MAP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| HostError::Worker(format!("cannot read payload {kind}: {error}")))?;
    if bytes.len() > MAXIMUM_ID_MAP_BYTES {
        return Err(HostError::Worker(
            "payload ID map exceeds its bound".to_owned(),
        ));
    }
    parse_exact_id_map(&bytes, host_start, count)
}

fn parse_exact_id_map(bytes: &[u8], host_start: u32, count: u32) -> Result<()> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| HostError::Worker("payload ID map is not UTF-8".to_owned()))?;
    let mut lines = text.lines();
    let line = lines
        .next()
        .ok_or_else(|| HostError::Worker("payload ID map is empty".to_owned()))?;
    if lines.next().is_some() {
        return Err(HostError::Worker(
            "payload ID map has multiple ranges".to_owned(),
        ));
    }
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    let values = fields
        .iter()
        .map(|field| field.parse::<u32>())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| HostError::Worker("payload ID map is malformed".to_owned()))?;
    if values.as_slice() != [0, host_start, count] {
        return Err(HostError::Worker(
            "payload ID map differs from the bound launch".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_map_rejects_extra_ranges_and_wrong_shift() {
        assert!(parse_exact_id_map(b"         0     100000      65536\n", 100000, 65536).is_ok());
        assert!(parse_exact_id_map(b"0 100001 65536\n", 100000, 65536).is_err());
        assert!(parse_exact_id_map(b"0 100000 65536\n65536 200000 1\n", 100000, 65536).is_err());
        assert!(parse_exact_id_map(b"0 100000 65536 trailing\n", 100000, 65536).is_err());
    }

    fn sample_record() -> ShiftedPayloadInspectionRecordV1 {
        let namespace = NamespaceProofSnapshot {
            device: 4,
            inode: 5,
        };
        ShiftedPayloadInspectionRecordV1 {
            version: VERSION,
            host_boot_id: [1; 16],
            sandbox_id: [2; 16],
            incarnation_id: [3; 16],
            assignment_epoch: 1,
            desired_generation: 1,
            assignment_digest: [4; 32],
            launch_binding: [5; 32],
            invocation_id: [6; 16],
            payload_pid: 200,
            payload_parent_pid: 199,
            payload_start_time_ticks: 123,
            payload_cgroup_id: 456,
            user_namespace: namespace,
            mount_namespace: namespace,
            network_namespace: namespace,
            pid_namespace: namespace,
            host_user_namespace: NamespaceProofSnapshot {
                device: 4,
                inode: 6,
            },
            host_pid_namespace: NamespaceProofSnapshot {
                device: 4,
                inode: 6,
            },
            host_uid_start: 100000,
            host_gid_start: 100000,
            mapping_count: 65536,
        }
    }

    #[test]
    fn record_readback_is_exact_and_versioned() {
        let record = sample_record();
        let encoded = record.encode().unwrap();
        assert_eq!(
            ShiftedPayloadInspectionRecordV1::decode(&encoded).unwrap(),
            record
        );
        assert_eq!(
            ShiftedPayloadInspectionRecordV1::decode(&encoded)
                .unwrap()
                .digest()
                .unwrap(),
            record.digest().unwrap()
        );

        let mut noncanonical = encoded.clone();
        noncanonical.push(b' ');
        assert!(ShiftedPayloadInspectionRecordV1::decode(&noncanonical).is_err());
        let newer = String::from_utf8(encoded)
            .unwrap()
            .replace("\"version\":1", "\"version\":2");
        assert!(ShiftedPayloadInspectionRecordV1::decode(newer.as_bytes()).is_err());

        let mut unshifted = record.clone();
        unshifted.host_user_namespace = unshifted.user_namespace;
        assert!(ShiftedPayloadInspectionRecordV1::decode(&unshifted.encode().unwrap()).is_err());

        let mut foreign_binding = record;
        foreign_binding.launch_binding = [0; 32];
        assert!(
            ShiftedPayloadInspectionRecordV1::decode(&foreign_binding.encode().unwrap()).is_err()
        );
    }
}
