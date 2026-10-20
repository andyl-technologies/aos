//! Retained original monitor registration packets and their owning pidfd checks.
//!
//! Successful packet capture is not monitor permission. The parent retains the
//! actual socket while its existing installation, root-subject and confined
//! child checks run. A failed packet or pidfd admission never leaves custody.

use aos_sandbox_linux::pidfd::{PidFd, PidFdOwnedAdmissionFailureV3};
use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;
use aos_sandbox_linux::seqpacket::{
    KernelAuthorizedRecordSubject, RecordBindingError, RetainedSeqpacketReceiveErrorV1,
    RetainedSeqpacketSendErrorV1, SeqpacketRightsRestrictionOriginalV6, SeqpacketSocket,
};

use super::{Error, InstalledScope, Ledger, MonitorCustody, control, validate_custody};

#[derive(Default)]
pub(super) struct RegistrationPacketV2 {
    pub(super) received: Option<Result<ReceivedDescriptorRecord, RetainedSeqpacketReceiveErrorV1>>,
    native_binding: Option<Result<u64, aos_sandbox_linux::Error>>,
    binding: Option<Result<(), RecordBindingError>>,
    child: Option<Result<PidFd, PidFdOwnedAdmissionFailureV3>>,
}

impl RegistrationPacketV2 {
    pub(super) fn receive(
        &mut self,
        connection: &mut SeqpacketSocket,
        first: bool,
        restriction: Option<&SeqpacketRightsRestrictionOriginalV6>,
    ) -> Result<bool, Error> {
        if self.received.is_some() {
            return Err(Error::LedgerConflict);
        }
        let maximum = if first {
            aos_sandbox_guest_protocol::openssh_monitor::OPENSSH_MONITOR_MAXIMUM_RECORD_BYTES_V2
        } else {
            aos_sandbox_guest_protocol::openssh_control::OPENSSH_CONTROL_MAXIMUM_REQUEST_BYTES_V5
        };
        self.received = Some(if first {
            connection.receive_guest_monitor_registration_retaining_v2(maximum)
        } else if let Some(restriction) = restriction {
            connection.receive_registered_guest_monitor_control_retaining_v2(maximum, restriction)
        } else {
            connection.receive_guest_monitor_relay_or_control_retaining_v2(maximum)
        });
        if self.received.as_ref().is_some_and(|result| {
            result.as_ref().is_err_and(|cause| {
                cause.is_nonconsuming_would_block() || cause.is_nonconsuming_interrupted()
            })
        }) {
            // This exact initial refusal consumed no record or ancillary roles.
            // Its completed native attempt has no outstanding owning prefix.
            self.received.take();
            return Ok(false);
        }
        let record = match self.received.as_ref() {
            Some(Ok(record)) => record,
            _ => return Err(Error::AmbiguousEffect),
        };
        self.binding = Some(
            connection.require_guest_monitor_registration_origin_retaining_v2(
                record,
                &mut self.native_binding,
            ),
        );
        if !matches!(self.binding, Some(Ok(()))) {
            return Err(Error::AmbiguousEffect);
        }
        Ok(true)
    }

    pub(super) fn record(&self) -> Result<&ReceivedDescriptorRecord, Error> {
        match self.received.as_ref() {
            Some(Ok(record)) => Ok(record),
            _ => Err(Error::AmbiguousEffect),
        }
    }

    pub(super) fn require_sender(&self, connection: &SeqpacketSocket) -> Result<(), Error> {
        let subject = self.record()?.subject();
        let sender = subject.credentials();
        let connector = connection.peer().credentials();
        if sender.pid() != connector.pid()
            || sender.uid() != connector.uid()
            || sender.gid() != connector.gid()
            || sender.uid() != 0
            || !subject.is_alive()?
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }

    pub(super) fn admit_child(&mut self) -> Result<(), Error> {
        if self.child.is_some() {
            return Err(Error::LedgerConflict);
        }
        let descriptor = match self.received.as_mut() {
            Some(Ok(record)) => record.take_guest_monitor_child_descriptor_data_v2(),
            _ => None,
        }
        .ok_or(Error::InvalidRequest)?;
        self.child = Some(PidFd::from_owned_retaining_v3(descriptor));
        self.child().map(|_| ())
    }

    pub(super) fn child(&self) -> Result<&PidFd, Error> {
        match self.child.as_ref() {
            Some(Ok(child)) => Ok(child),
            _ => Err(Error::AmbiguousEffect),
        }
    }

    pub(super) fn take_child(&mut self) -> Result<PidFd, Error> {
        match self.child.take() {
            Some(Ok(child)) => Ok(child),
            other => {
                self.child = other;
                Err(Error::AmbiguousEffect)
            }
        }
    }

    fn take_record(&mut self) -> Result<(Vec<u8>, KernelAuthorizedRecordSubject), Error> {
        match self.received.take() {
            Some(Ok(record)) => {
                let (payload, subject, remaining) = record.into_parts();
                // The sole descriptor was already moved into the typed child.
                // No fallible validation remains after this ownership move.
                debug_assert!(remaining.is_empty());
                Ok((payload, subject))
            }
            other => {
                self.received = other;
                Err(Error::AmbiguousEffect)
            }
        }
    }
}

pub(super) struct MonitorRegistrationOriginalV2 {
    connection: Option<SeqpacketSocket>,
    packet: RegistrationPacketV2,
    original_expiry: u64,
    ack: Option<Result<(), RetainedSeqpacketSendErrorV1>>,
    after: Option<Result<(), Error>>,
    pub(super) body: Option<Result<(), Error>>,
}

impl MonitorRegistrationOriginalV2 {
    pub(super) fn new(connection: SeqpacketSocket) -> Self {
        Self {
            connection: Some(connection),
            packet: Default::default(),
            original_expiry: 0,
            ack: None,
            after: None,
            body: None,
        }
    }

    pub(super) fn enter(
        &mut self,
        installed: &InstalledScope,
        ledger: &Ledger,
        deadline: std::time::Instant,
    ) -> Result<(), Error> {
        let connection = self.connection.as_mut().ok_or(Error::LedgerConflict)?;
        self.original_expiry =
            aos_sandbox_model::public_attach_ticket::PublicAttachTicketBindingV2::decode(
                &installed.original_ticket,
            )
            .map_err(|_| Error::InvalidRequest)?
            .expires_at;
        super::require_root_monitor(connection, &installed.runtime)?;
        loop {
            let _ = crate::process::poll_original_execution_timeouts_v1(ledger);
            if std::time::Instant::now() >= deadline {
                return Err(Error::InvalidRequest);
            }
            if self.packet.receive(connection, true, None)? {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        self.packet.require_sender(connection)?;
        self.packet.admit_child()?;
        for _ in 0..2 {
            let record = self.packet.record()?;
            validate_custody(
                installed,
                connection,
                record.subject(),
                self.packet.child()?,
                record.payload(),
                ledger,
            )?;
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::InvalidRequest);
        }
        let record = self.packet.record()?;
        control::require_control_custody(
            installed,
            connection,
            record.subject(),
            self.packet.child()?,
            record.payload(),
            self.original_expiry,
            ledger,
        )?;
        self.ack = Some(
            connection
                .send_retaining(aos_sandbox_guest_protocol::openssh_monitor::OPENSSH_MONITOR_BINDING_ACK_V2),
        );
        // The exact original after remains owed even on an ambiguous send.
        self.after = Some(validate_custody(
            installed,
            connection,
            record.subject(),
            self.packet.child()?,
            record.payload(),
            ledger,
        ));
        if matches!(self.ack, Some(Ok(()))) && matches!(self.after, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Error::AmbiguousEffect)
        }
    }

    pub(super) fn take_completed(&mut self) -> Result<MonitorCustody, Error> {
        if !matches!(self.body, Some(Ok(()))) {
            return Err(Error::AmbiguousEffect);
        }
        let child = self.packet.take_child()?;
        let (payload, subject) = self.packet.take_record()?;
        let connection = self.connection.take().ok_or(Error::LedgerConflict)?;
        Ok(MonitorCustody {
            connection,
            subject,
            child,
            original_witness: payload,
            original_expiry: self.original_expiry,
            relay: None,
            pending_io: None,
            controls: control::OriginalSessionControlsV5::new(),
            relay_registration: Default::default(),
            restriction: SeqpacketRightsRestrictionOriginalV6::new(),
            relay_ack: None,
            relay_after: None,
        })
    }
}
