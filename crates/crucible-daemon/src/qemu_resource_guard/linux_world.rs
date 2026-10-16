//! Routes one aggregate World guard through its real independent Linux members.

use super::*;

/// Retains the actual cancellation controls for an existing selected World.
#[derive(Debug)]
pub enum LinuxWorldCancellationSignal {
    /// Preserves the distinct single-owner component/private actor contract.
    Single(LinuxQemuAttemptCancellationSignal),
    /// Signals every actual member without multiplying scheduler quanta.
    World(Vec<LinuxQemuAttemptCancellationSignal>),
}

impl QemuAttemptCancellationSignal for LinuxWorldCancellationSignal {
    fn signal(&self) -> Result<(), QemuVmRealizationError> {
        match self {
            Self::Single(signal) => signal.signal(),
            Self::World(signals) => {
                let mut first = None;
                for signal in signals {
                    if let Err(error) = signal.signal() {
                        first.get_or_insert(error);
                    }
                }
                first.map_or(Ok(()), Err)
            }
        }
    }
}

impl LinuxQemuAttemptHostResourceOwner {
    /// Prices member and cancellation arrays separately from the inline guard.
    ///
    /// The caller adds this actual selected peak to the same World ledger
    /// before either array is born. Payload capacity is requested explicitly;
    /// allocator-internal metadata follows the containing Main conventions.
    pub(super) fn world_control_bytes(nodes: usize) -> Result<u64, QemuVmRealizationError> {
        if nodes == 0 {
            return Err(world_route_error());
        }
        let members = std::alloc::Layout::array::<LinuxWorldMember>(nodes)
            .map_err(|_| world_route_error())?;
        let signals = std::alloc::Layout::array::<LinuxQemuAttemptCancellationSignal>(nodes)
            .map_err(|_| world_route_error())?;
        members
            .size()
            .checked_add(signals.size())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(world_route_error)
    }

    pub(super) fn single(&self) -> Result<&LinuxQemuAttemptHostOwner, QemuVmRealizationError> {
        match &self.host {
            LinuxHostSet::Single(host) => Ok(host),
            LinuxHostSet::World { .. } => Err(world_route_error()),
        }
    }

    pub(super) fn single_mut(
        &mut self,
    ) -> Result<&mut LinuxQemuAttemptHostOwner, QemuVmRealizationError> {
        match &mut self.host {
            LinuxHostSet::Single(host) => Ok(host),
            LinuxHostSet::World { .. } => Err(world_route_error()),
        }
    }

    pub(super) fn member(&self, node: &NodeId) -> Result<&Self, QemuVmRealizationError> {
        match &self.host {
            LinuxHostSet::Single(_) => Ok(self),
            LinuxHostSet::World { identity, members } => {
                let key = world_node_key(identity.owner, node);
                members
                    .iter()
                    .find(|member| member.key == key)
                    .map(|member| &member.owner)
                    .ok_or_else(world_route_error)
            }
        }
    }

    pub(super) fn member_mut(
        &mut self,
        node: &NodeId,
    ) -> Result<&mut Self, QemuVmRealizationError> {
        if matches!(self.host, LinuxHostSet::Single(_)) {
            return Ok(self);
        }
        match &mut self.host {
            LinuxHostSet::Single(_) => Err(world_route_error()),
            LinuxHostSet::World { identity, members } => {
                let key = world_node_key(identity.owner, node);
                members
                    .iter_mut()
                    .find(|member| member.key == key)
                    .map(|member| &mut member.owner)
                    .ok_or_else(world_route_error)
            }
        }
    }

    pub(super) fn world_cancellation_signal(
        &self,
    ) -> Result<LinuxWorldCancellationSignal, QemuVmRealizationError> {
        match &self.host {
            LinuxHostSet::Single(host) => host
                .cancellation_signal()
                .map(LinuxWorldCancellationSignal::Single),
            LinuxHostSet::World { members, .. } => {
                let mut signals = Vec::new();
                signals
                    .try_reserve_exact(members.len())
                    .map_err(|_| world_route_error())?;
                for member in members {
                    signals.push(member.owner.single()?.cancellation_signal()?);
                }
                Ok(LinuxWorldCancellationSignal::World(signals))
            }
        }
    }
}

fn world_node_key(owner: [u8; 32], node: &NodeId) -> [u8; 32] {
    let mut key = blake3::Hasher::new();
    key.update(b"crucible.host-ram.node-owner.v1\0");
    key.update(&owner);
    key.update(node.name.as_bytes());
    *key.finalize().as_bytes()
}

fn world_route_error() -> QemuVmRealizationError {
    QemuVmRealizationError::ExecutorUnavailable {
        operation: "select exact native World member",
        message: String::from("native World requires its actual admitted node identity"),
    }
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
pub(super) fn park_route_error(
    original: &Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
) -> crucible_qemu::OriginalActorParkQuiescenceError {
    crucible_qemu::OriginalActorParkQuiescenceError::Binding {
        first: crucible_qemu::OriginalActorAccountError::Unavailable,
        original_after: original.wait_slice().err(),
    }
}
