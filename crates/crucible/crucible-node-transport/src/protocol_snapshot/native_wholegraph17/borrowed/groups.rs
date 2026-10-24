//! Conjoins only actual shared ordinals returned by the complete source walk.

use super::*;

/// Retains root and role ordinals obtained by one real complete false pass.
#[derive(Clone, Copy)]
pub(super) struct NativeCurrentGraph17Groups {
    pub(super) registrar: NativeRegistrar17GroupIds,
    pub(super) actor: usize,
    pub(super) supervisor: usize,
    pub(super) codec: usize,
    pub(super) policy: usize,
    pub(super) control_identity: usize,
    pub(super) hold: Option<usize>,
    pub(super) frames: usize,
    pub(super) deadline: usize,
    pub(super) mapping: usize,
    pub(super) receiver: NativeBlobReceiver17GroupIds,
    pub(super) boot: usize,
    pub(super) connection: NativeConnection17GroupIds,
    pub(super) endpoint: CurrentEndpoint17GroupIds,
    pub(super) control: CurrentControl17GroupIds,
    pub(super) service: CurrentNativeService17GroupIds,
}

impl NativeCurrentGraph17Groups {
    pub(super) fn authenticate_same_roots_data(&self, other: Self) -> Result<(), ProviderError> {
        self.authenticate_roles_data()?;
        other.authenticate_roles_data()?;
        if self.registrar != other.registrar
            || self.actor != other.actor
            || self.supervisor != other.supervisor
            || self.codec != other.codec
            || self.policy != other.policy
            || self.control_identity != other.control_identity
            || self.hold != other.hold
            || self.frames != other.frames
            || self.deadline != other.deadline
            || self.mapping != other.mapping
            || self.receiver != other.receiver
            || self.boot != other.boot
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn authenticate_roles_data(&self) -> Result<(), ProviderError> {
        let connection = self.connection;
        if (
            connection.actor,
            connection.supervisor,
            connection.codec,
            connection.policy,
            connection.frames,
            connection.deadline,
        ) != (
            self.actor,
            self.supervisor,
            self.codec,
            self.policy,
            self.frames,
            self.deadline,
        ) || connection.blobs != Some(self.receiver.ledger)
            || self.receiver.supervisor != self.supervisor
            || (self.endpoint.authority.0, self.endpoint.authority.1)
                != (self.registrar.epoch, self.registrar.gate)
            || self.endpoint.uploads != self.receiver
            || self.endpoint.boot != self.boot
            || self.control.capture_identity != self.control_identity
            || self.control.hold != self.hold
            || (
                self.service.supervisor,
                self.service.boot,
                self.service.policy,
                self.service.deadline,
            ) != (self.supervisor, self.boot, self.policy, self.deadline)
            || self.service.registrar != self.registrar
            || self.service.bootstrap.boot != self.boot
        {
            return Err(invalid());
        }
        self.endpoint
            .authenticate_connection_groups_data(connection)?;
        if self
            .control
            .evidence
            .is_some_and(|evidence| evidence.0 != self.boot || Some(evidence.2) != self.hold)
            || self
                .endpoint
                .flight
                .is_some_and(|flight| flight.mapping.is_some_and(|group| group != self.mapping))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
