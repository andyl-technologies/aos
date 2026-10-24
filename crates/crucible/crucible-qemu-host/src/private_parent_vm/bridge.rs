//! Publishes the finite Parent evidence channel before its actual QEMU birth.
//!
//! The retained original operator pays this endpoint and every pinned descriptor.
//! SO_PEERCRED is compared to the Child actually stored by the parent; neither
//! a caller PID nor an arbitrary socket path can establish an invocation.

use super::{ParentFailure, ParentRecord};
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

const FRAME_BYTES: usize = 224;
const MAX_POLICY: u64 = 16_384;
const MAX_DESCRIPTOR: u64 = 1 << 20;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Policy {
    schema: String,
    native_count: u64,
    mode: String,
    actor_task_limit: u64,
    actor_descriptors: u64,
    actor_cpu_slots: u64,
    actor_resident_bytes: u64,
    host_memory_bytes: u64,
    host_backing_bytes: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkflowSelection {
    schema: String,
    family: String,
    native_count: u64,
}

pub(super) struct Bridge {
    listener: UnixListener,
    peer: Option<UnixStream>,
    path: PathBuf,
    _policy: File,
    _images: File,
    _source: File,
    _workflow: File,
    frame: [u8; FRAME_BYTES],
}

impl Bridge {
    pub(super) fn prepare(
        path: PathBuf,
        policy_path: &Path,
        images_path: &Path,
        source_path: &Path,
        workflow_path: &Path,
    ) -> Result<Self, ParentFailure> {
        let mut policy = immutable(policy_path, MAX_POLICY)?;
        let mut policy_bytes = Vec::new();
        (&mut policy)
            .take(MAX_POLICY + 1)
            .read_to_end(&mut policy_bytes)
            .map_err(ParentFailure::Io)?;
        let fields: Policy =
            serde_json::from_slice(&policy_bytes).map_err(ParentFailure::Inventory)?;
        let mode = match fields.mode.as_str() {
            "nativeOnly" => 0,
            "kernelMeasurement" => 1,
            _ => return Err(ParentFailure::CompiledInput("operator family")),
        };
        if fields.schema != "crucible.measurement-operator.v1"
            || !matches!(fields.native_count, 1 | 2 | 4)
            || fields.actor_task_limit != 4096
            || fields.actor_descriptors != 1024
            || fields.actor_cpu_slots != 10
            || fields.actor_resident_bytes != 16 << 30
            || fields.host_memory_bytes != 20 << 30
            || fields.host_backing_bytes != 64 << 30
        {
            return Err(ParentFailure::CompiledInput("operator fixed role contract"));
        }
        // Workflow identity is bound before the endpoint is published. The
        // consumer validates the full service policy under this exact digest.
        let mut workflow = immutable(workflow_path, MAX_DESCRIPTOR)?;
        let mut workflow_bytes = Vec::new();
        (&mut workflow)
            .take(MAX_DESCRIPTOR + 1)
            .read_to_end(&mut workflow_bytes)
            .map_err(ParentFailure::Io)?;
        let selected: WorkflowSelection =
            serde_json::from_slice(&workflow_bytes).map_err(ParentFailure::Inventory)?;
        if selected.schema != "crucible.measurement-resident-workflow.v2"
            || selected.family != "residentThroughput"
            || fields.mode != "nativeOnly"
            || selected.native_count != fields.native_count
        {
            return Err(ParentFailure::CompiledInput("fixed workflow family/width"));
        }
        let mut images = immutable(images_path, MAX_DESCRIPTOR)?;
        let mut source = immutable(source_path, MAX_DESCRIPTOR)?;
        let mut frame = [0; FRAME_BYTES];
        frame[..8].copy_from_slice(b"CPARNT02");
        frame[8..40].copy_from_slice(blake3::hash(&policy_bytes).as_bytes());
        frame[40..72].copy_from_slice(&digest(&mut images, MAX_DESCRIPTOR)?);
        frame[72..104].copy_from_slice(&digest(&mut source, MAX_DESCRIPTOR)?);
        frame[192..224].copy_from_slice(blake3::hash(&workflow_bytes).as_bytes());
        File::open("/dev/urandom")
            .and_then(|mut random| random.read_exact(&mut frame[104..136]))
            .map_err(ParentFailure::Io)?;
        if frame[104..136] == [0; 32] {
            return Err(ParentFailure::CompiledInput("VM incarnation"));
        }
        frame[136..144].copy_from_slice(&1u64.to_le_bytes());
        frame[144] = fields.native_count as u8;
        frame[145] = mode;
        for (offset, value) in [
            (152, 4096u64),
            (160, 1024),
            (168, 16 << 30),
            (176, 20 << 30),
            (184, 64 << 30),
        ] {
            frame[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        let listener = UnixListener::bind(&path).map_err(ParentFailure::Io)?;
        listener.set_nonblocking(true).map_err(ParentFailure::Io)?;
        rustix::fs::chown(
            &path,
            Some(rustix::process::Uid::from_raw(65_533)),
            Some(rustix::process::Gid::from_raw(65_533)),
        )
        .map_err(|error| ParentFailure::Io(error.into()))?;
        Ok(Self {
            listener,
            peer: None,
            path,
            _policy: policy,
            _images: images,
            _source: source,
            _workflow: workflow,
            frame,
        })
    }

    pub(super) fn close_after_vm_wait(self) -> Result<(), ParentFailure> {
        // A caller may reach this only after waiting its actual QEMU Child.
        // All file/socket controls close while the external account remains.
        let path = self.path.clone();
        drop(self);
        std::fs::remove_file(path).map_err(ParentFailure::Io)
    }

    pub(super) fn qemu_argument(&self) -> String {
        format!(
            "socket,id=original-parent,path={},server=off",
            self.path.display()
        )
    }
}

impl ParentRecord {
    pub(super) fn exchange_parent_evidence(&mut self) -> Result<(), ParentFailure> {
        loop {
            self.boundary()?;
            let accepted = self
                .bridge
                .as_ref()
                .ok_or(ParentFailure::Occupied)?
                .listener
                .accept();
            match accepted {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.postchecked(Ok(()))?;
                    self.bridge_poll(false)?;
                }
                Err(error) => return self.postchecked(Err(ParentFailure::Io(error))),
                Ok((peer, _)) => {
                    self.bridge.as_mut().ok_or(ParentFailure::Occupied)?.peer = Some(peer);
                    self.postchecked(Ok(()))?;
                    break;
                }
            }
        }
        self.boundary()?;
        let peer = self
            .bridge
            .as_ref()
            .and_then(|bridge| bridge.peer.as_ref())
            .ok_or(ParentFailure::Occupied)?;
        let credentials = rustix::net::sockopt::socket_peercred(peer)
            .map_err(|error| ParentFailure::Io(error.into()));
        let credentials = match credentials {
            Ok(credentials) => {
                self.postchecked(Ok(()))?;
                credentials
            }
            Err(error) => return self.postchecked(Err(error)),
        };
        if credentials.pid.as_raw_nonzero().get() as u32
            != self.child.as_ref().ok_or(ParentFailure::Occupied)?.id()
            || credentials.uid.as_raw() != 65_533
        {
            return Err(ParentFailure::CompiledInput(
                "actual owned QEMU bridge peer",
            ));
        }
        self.boundary()?;
        let result = self
            .bridge
            .as_ref()
            .and_then(|bridge| bridge.peer.as_ref())
            .ok_or(ParentFailure::Occupied)?
            .set_nonblocking(true)
            .map_err(ParentFailure::Io);
        self.postchecked(result)?;
        let mut written = 0;
        while written != FRAME_BYTES {
            self.boundary()?;
            let bridge = self.bridge.as_mut().ok_or(ParentFailure::Occupied)?;
            let result = bridge
                .peer
                .as_mut()
                .ok_or(ParentFailure::Occupied)?
                .write(&bridge.frame[written..]);
            match result {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.postchecked(Ok(()))?;
                    self.bridge_poll(true)?;
                }
                Err(error) => return self.postchecked(Err(ParentFailure::Io(error))),
                Ok(0) => {
                    return self
                        .postchecked(Err(ParentFailure::CompiledInput("parent bridge closed")));
                }
                Ok(count) => {
                    written += count;
                    self.postchecked(Ok(()))?;
                }
            }
        }
        // Pins remain alongside the same Child and original account through
        // factual VM retirement, even after the finite frame has been sent.
        Ok(())
    }

    pub(super) fn observe_guest_completion(&mut self) -> Result<(), ParentFailure> {
        if self.guest_complete {
            return Ok(());
        }
        self.boundary()?;
        let peer = self
            .bridge
            .as_mut()
            .and_then(|bridge| bridge.peer.as_mut())
            .ok_or(ParentFailure::Occupied)?;
        let mut acknowledgement = [0];
        match peer.read(&mut acknowledgement) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                self.postchecked(Ok(()))
            }
            Err(error) => self.postchecked(Err(ParentFailure::Io(error))),
            Ok(1) if acknowledgement == [1] => {
                self.guest_complete = true;
                self.postchecked(Ok(()))
            }
            Ok(_) => self.postchecked(Err(ParentFailure::CompiledInput(
                "actual guest completion acknowledgement",
            ))),
        }
    }

    fn bridge_poll(&mut self, writing: bool) -> Result<(), ParentFailure> {
        self.boundary()?;
        let timeout = self.poll_timeout()?;
        let bridge = self.bridge.as_ref().ok_or(ParentFailure::Occupied)?;
        let events = if writing {
            rustix::event::PollFlags::OUT
        } else {
            rustix::event::PollFlags::IN
        };
        let descriptor = if writing {
            rustix::event::PollFd::new(bridge.peer.as_ref().ok_or(ParentFailure::Occupied)?, events)
        } else {
            rustix::event::PollFd::new(&bridge.listener, events)
        };
        let result = rustix::event::poll(&mut [descriptor], Some(&timeout))
            .map(|_| ())
            .map_err(|error| ParentFailure::Io(error.into()));
        self.postchecked(result)
    }
}

fn immutable(path: &Path, limit: u64) -> Result<File, ParentFailure> {
    if !path.starts_with("/nix/store/") {
        return Err(ParentFailure::CompiledInput("immutable bridge descriptor"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(ParentFailure::Io)?;
    let metadata = file.metadata().map_err(ParentFailure::Io)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o222 != 0
        || metadata.len() == 0
        || metadata.len() > limit
    {
        return Err(ParentFailure::CompiledInput(
            "bridge descriptor extent/owner",
        ));
    }
    Ok(file)
}

fn digest(file: &mut File, limit: u64) -> Result<[u8; 32], ParentFailure> {
    let expected = file.metadata().map_err(ParentFailure::Io)?.len();
    let mut hasher = blake3::Hasher::new();
    let mut bytes = [0; 4096];
    let mut total = 0u64;
    loop {
        let count = file.read(&mut bytes).map_err(ParentFailure::Io)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(ParentFailure::CompiledInput("bridge descriptor overflow"))?;
        if total > limit {
            return Err(ParentFailure::CompiledInput("bridge descriptor grew"));
        }
        hasher.update(&bytes[..count]);
    }
    if total != expected {
        return Err(ParentFailure::CompiledInput("bridge descriptor changed"));
    }
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
impl Bridge {
    pub(super) fn has_retained_test_peer(&self) -> bool {
        self.peer.is_some()
    }

    pub(super) fn untrusted_test_endpoint(path: PathBuf, pins: File) -> Self {
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self {
            listener,
            peer: None,
            path,
            _policy: pins.try_clone().unwrap(),
            _images: pins.try_clone().unwrap(),
            _source: pins.try_clone().unwrap(),
            _workflow: pins,
            frame: [0; FRAME_BYTES],
        }
    }
}
