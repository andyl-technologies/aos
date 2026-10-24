//! Routes one aggregate World guard through its real independent Linux members.

use super::*;

/// Retains the original Source-paid Target host-vector capacity.
///
/// Empty metadata carries no host, permit, role or allocation credit. The
/// matching real Target producer alone fills it after Main installs Pending.
pub(crate) struct LinuxTargetWorldStorage {
    pub(super) members: Vec<LinuxWorldMember>,
    pub(super) selected_bound: usize,
    started: bool,
    pub(crate) aggregate: Option<AttemptResourceLimits>,
    pub(crate) installed: Option<LinuxQemuAttemptHostResourceOwner>,
}

impl LinuxTargetWorldStorage {
    /// Reports actual partial members that still need their containing host.
    pub(crate) fn needs_host_cleanup(&self) -> bool {
        self.installed.is_none() && !self.members.is_empty()
    }

    pub(crate) fn can_reuse(&self) -> bool {
        !self.started
            && self.installed.is_none()
            && self.members.is_empty()
            && self.members.capacity() >= self.selected_bound
    }

    /// Recovers the SAME vector after its caller verifies every exact loan.
    ///
    /// Identity and capacity only bind existing storage. They do not attest
    /// physical return; the selected Target owner checks actual receipts first.
    pub(crate) fn recover_from_host(
        &mut self,
        identity: crucible_host_resources::host_services::process_birth::NativeWorldIdentity,
        host: &mut LinuxQemuAttemptHostResourceOwner,
    ) -> bool {
        if !self.started || !self.members.is_empty() || self.members.capacity() != 0 {
            return false;
        }
        let LinuxHostSet::World {
            identity: saved,
            members,
        } = &mut host.host
        else {
            return false;
        };
        if *saved != identity
            || members.len() > self.selected_bound
            || members.capacity() < self.selected_bound
        {
            return false;
        }
        let mut returned = std::mem::take(members);
        // This destroys the actually returned host fields and their remaining
        // nonphysical aliases before Source storage can be handed back.
        returned.clear();
        self.members = returned;
        self.started = false;
        self.aggregate = None;
        true
    }

    /// Resets an empty partial pass only after its caller checks genuine loans.
    ///
    /// This is metadata reconciliation; the containing storage checks actual
    /// native return journals before invoking it, including never-born members.
    pub(crate) fn reconcile_empty_return(&mut self) -> bool {
        if !self.members.is_empty()
            || self.installed.is_some()
            || self.members.capacity() < self.selected_bound
        {
            return false;
        }
        self.started = false;
        self.aggregate = None;
        true
    }

    /// Requests only the selected member capacity under existing Source payment.
    pub(crate) fn prepare(nodes: usize) -> Result<Self, QemuVmRealizationError> {
        if nodes == 0 || nodes > crate::MAX_QEMU_ATTEMPT_GENERATION_NODES {
            return Err(world_route_error());
        }
        let mut members = Vec::new();
        members
            .try_reserve_exact(nodes)
            .map_err(|_| world_route_error())?;
        Ok(Self {
            members,
            selected_bound: nodes,
            started: false,
            aggregate: None,
            installed: None,
        })
    }

    /// Latches the sole native-begin pass without admitting another role.
    pub(crate) fn begin_pass(&mut self, selected: usize, aggregate: AttemptResourceLimits) -> bool {
        if self.started
            || !self.members.is_empty()
            || selected > self.selected_bound
            || self.members.capacity() < self.selected_bound
        {
            return false;
        }
        self.aggregate = Some(aggregate);
        self.started = true;
        true
    }

    /// Checks capacity before an effect can return another physical owner.
    pub(crate) fn has_prepared_cell(&self) -> bool {
        self.started
            && self.members.len() < self.selected_bound
            && self.members.capacity() >= self.selected_bound
    }

    /// Records the next actual owner in its already-checked prepaid capacity.
    ///
    /// The sole caller checks `has_prepared_cell` before invoking a factory
    /// which cannot borrow this vector. Nothing changes its length/capacity
    /// between that check and this push, so it performs no allocation.
    pub(crate) fn record_member(
        &mut self,
        key: [u8; 32],
        resources: AttemptResourceLimits,
        host: LinuxQemuAttemptHostOwner,
    ) {
        self.members.push(LinuxWorldMember {
            key,
            owner: LinuxQemuAttemptHostResourceOwner {
                resources,
                host: LinuxHostSet::Single(host),
            },
        });
    }

    /// Refines the last recorded member only after its owner is durable here.
    pub(crate) fn refine_recorded_limits(
        &mut self,
        requested: AttemptResourceLimits,
    ) -> Result<(), QemuVmRealizationError> {
        let member = self.members.last_mut().ok_or_else(world_route_error)?;
        let actual = member.owner.single()?.resource_ceiling();
        member.owner.resources = effective_linux_limits(requested, actual)?;
        Ok(())
    }

    /// Moves the same member-vector allocation into the aggregate guard.
    pub(crate) fn take_host(
        &mut self,
        identity: crucible_host_resources::host_services::process_birth::NativeWorldIdentity,
        resources: AttemptResourceLimits,
    ) -> LinuxQemuAttemptHostResourceOwner {
        LinuxQemuAttemptHostResourceOwner {
            resources,
            host: LinuxHostSet::World {
                identity,
                members: std::mem::take(&mut self.members),
            },
        }
    }
}

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
    pub(crate) fn world_control_bytes(nodes: usize) -> Result<u64, QemuVmRealizationError> {
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

pub(crate) fn world_node_key(owner: [u8; 32], node: &NodeId) -> [u8; 32] {
    let mut key = blake3::Hasher::new();
    key.update(b"crucible.host-ram.node-owner.v1\0");
    key.update(&owner);
    key.update(node.name.as_bytes());
    *key.finalize().as_bytes()
}

pub(super) fn world_route_error() -> QemuVmRealizationError {
    QemuVmRealizationError::ExecutorUnavailable {
        operation: "select exact native World member",
        message: String::from("native World requires its actual admitted node identity"),
    }
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
pub(super) fn park_route_error(
    original: &Arc<crucible_host_resources::host_supervision::HostOperationGuard>,
) -> crucible_qemu_host::OriginalActorParkQuiescenceError {
    crucible_qemu_host::OriginalActorParkQuiescenceError::Binding {
        first: crucible_qemu_host::OriginalActorAccountError::Unavailable,
        original_after: original.wait_slice().err(),
    }
}
