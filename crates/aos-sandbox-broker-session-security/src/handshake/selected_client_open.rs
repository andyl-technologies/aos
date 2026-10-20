//! Shares the retained selected Client acquisition, HELLO and cold driver.
//!
//! Initial Controller and recurring Storage-to-Host callers lend distinct real
//! native originals through this closed adapter. The same endpoint/connect,
//! peer, three-flight, poll and cold owners stay resident on every failure.
//! No implementable payer callback, supplied authority or public stage exists.

use super::*;
use super::controller_initial::ControllerInitialClientClosedV1;
use aos_sandbox::{ControllerInitialBrokerSessionClosedV1 as NativeClosed,
    ControllerInitialBrokerSessionReceivingLoanV1 as Loan,
    ControllerInitialBrokerSessionRoleV1 as Role};
use std::path::Path;

#[derive(Clone, Copy)]
enum SelectedClientKindV1 { Controller, StorageHost, StartResource }

enum SelectedClientEndpointV1 {
    Controller(crate::endpoint::ProtectedBrokerSessionControllerClientOpeningV1),
    StorageHost(crate::endpoint::ProtectedBrokerSessionStorageHostClientOpeningV1),
}

pub(super) enum SelectedClientReceivingV1<'loan, 'original, 'context, 'cut, 'native, 'account> {
    Controller {
        receiving: &'loan mut Loan<'original>,
        account: Option<&'loan mut aos_sandbox::policy_compiler::GitCoverageAccountAttemptV1<'account>>,
    },
    StorageHost(&'loan mut crate::recovery::StorageHostClientReceivingV1<'context, 'cut, 'native>),
    StartResource(&'loan mut super::start_network_client::StartResourceColdReceivingV4<'context, 'cut>),
}

#[derive(Clone, Copy)]
enum FailureV1 {
    Coverage,
    Fixed,
    Launch,
    Deadline,
    Connection,
    Peer,
    Hello,
    Handshake,
    Poll,
    Cold,
}

pub(super) struct SelectedClientCaptureV1 {
    coverage_cut: Option<Result<u64, NativeClosed>>,
    lower: SelectedClientEndpointV1,
    kind: SelectedClientKindV1,
    fixed: Option<Result<ProtectedBrokerSessionFixedCustodyV1, BrokerSessionSecurityError>>,
    launch_image: Option<crate::production_startup::Pid1LaunchImageV1>,
    launch: Option<Result<(), BrokerSessionSecurityError>>,
    deadline: Option<Result<OriginalBrokerColdDeadlineV1, crate::DormantBrokerSessionHandshakeErrorV1>>,
    cutoff: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    connected: Option<Result<SeqpacketSocket, aos_sandbox_linux::seqpacket::RetainedSeqpacketAdmissionErrorV1>>,
    peer: Option<Result<ProcessEvidence, HandshakeError>>,
    hello: Option<Result<BrokerClientHello, aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError>>,
    handshake: Option<DormantControllerClientHandshakeV1>,
    handshake_error: Option<DormantBrokerSessionHandshakeErrorV1>,
    poll_native: Option<Result<usize, rustix::io::Errno>>,
    poll: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    cold: Option<RetainedStorageColdOpenV1>,
    pub(super) completed: Option<Result<DormantAuthenticatedBrokerSessionV1, crate::DormantBrokerSessionHandshakeErrorV1>>,
    first: Option<FailureV1>,
}

impl SelectedClientCaptureV1 {
    pub(super) fn controller(launch_image: Option<crate::production_startup::Pid1LaunchImageV1>) -> Self {
        Self {
            coverage_cut: None,
            lower: SelectedClientEndpointV1::Controller(crate::endpoint::ProtectedBrokerSessionControllerClientOpeningV1::new()),
            kind: SelectedClientKindV1::Controller,
            fixed: None,
            launch_image,
            launch: None,
            deadline: None,
            cutoff: None,
            connected: None,
            peer: None,
            hello: None,
            handshake: None,
            handshake_error: None,
            poll_native: None,
            poll: None,
            cold: None,
            completed: None,
            first: None,
        }
    }

    pub(super) fn storage_host(deadline: OriginalBrokerColdDeadlineV1) -> Self {
        let mut capture = Self::controller(None);
        capture.lower = SelectedClientEndpointV1::StorageHost(
            crate::endpoint::ProtectedBrokerSessionStorageHostClientOpeningV1::new());
        capture.kind = SelectedClientKindV1::StorageHost;
        capture.deadline = Some(Ok(deadline));
        capture
    }

    pub(super) fn start_network(deadline: OriginalBrokerColdDeadlineV1) -> Self {
        let mut capture = Self::controller(None);
        capture.kind = SelectedClientKindV1::StartResource;
        capture.deadline = Some(Ok(deadline));
        capture
    }

    fn close(&mut self, failure: FailureV1) -> Result<(), ControllerInitialClientClosedV1> {
        self.first.get_or_insert(failure);
        Err(ControllerInitialClientClosedV1)
    }

    pub(super) fn deadline_v1(&mut self) -> Result<OriginalBrokerColdDeadlineV1, ControllerInitialClientClosedV1> {
        let Some(Ok(deadline)) = self.deadline.as_ref() else {
            self.first.get_or_insert(FailureV1::Deadline);
            return Err(ControllerInitialClientClosedV1);
        };
        let deadline = *deadline;
        self.cutoff = Some(deadline.check());
        if !matches!(self.cutoff, Some(Ok(()))) {
            self.first.get_or_insert(FailureV1::Deadline);
            return Err(ControllerInitialClientClosedV1);
        }
        Ok(deadline)
    }

    pub(super) fn drive_once(
        &mut self,
        mut receiving: SelectedClientReceivingV1<'_, '_, '_, '_, '_, '_>,
    ) -> Result<(), ControllerInitialClientClosedV1> {
        let execution_cleanup = match &receiving {
            SelectedClientReceivingV1::Controller { receiving, account: None } =>
                match receiving.is_execution_cleanup_cold_data_v2() {
                    Ok(selected) => selected,
                    Err(_) => return self.close(FailureV1::Hello),
                },
            _ => false,
        };
        let stop_cleanup = match &receiving {
            SelectedClientReceivingV1::Controller { receiving, account: None } =>
                match receiving.is_host_stop_cleanup_data_v1() {
                    Ok(selected) => selected,
                    Err(_) => return self.close(FailureV1::Hello),
                },
            _ => false,
        };
        let selected_maintenance_role = match &receiving {
            SelectedClientReceivingV1::Controller { receiving, account: None } => {
                match receiving.selected_maintenance_client_role_v2() {
                    Ok(role) => role,
                    Err(_) => return self.close(FailureV1::Hello),
                }
            }
            _ => None,
        };
        let reconciliation_role = match &receiving {
            SelectedClientReceivingV1::Controller { receiving, .. } => receiving.reconciliation_role_data_v2(),
            _ => None,
        };
        let recover_cut = match &receiving {
            SelectedClientReceivingV1::Controller { receiving, account } => {
                let cutoff = receiving.operator_recover_cutoff_data_v1();
                if cutoff.is_some() && (account.is_some()
                    || (receiving.role_v1() != Role::Storage
                        && reconciliation_role.map(|role| role.broker_role_data_v2()) != Some(receiving.role_v1())
                        && !((execution_cleanup || stop_cleanup) && receiving.role_v1() == Role::Host))) {
                    return self.close(FailureV1::Coverage);
                }
                cutoff
            }
            SelectedClientReceivingV1::StorageHost(_) | SelectedClientReceivingV1::StartResource(_) => None,
        };
        let coverage_cut = match &mut receiving {
            SelectedClientReceivingV1::Controller { receiving, account: Some(account) } => {
                self.coverage_cut = Some(account.controller_initial_session_cutoff_v1(receiving));
                match self.coverage_cut {
                    Some(Ok(cutoff)) => Some(cutoff),
                    _ => return self.close(FailureV1::Coverage),
                }
            }
            _ => None,
        };
        self.fixed = Some(match (&mut self.lower, &mut receiving) {
            (SelectedClientEndpointV1::Controller(lower), SelectedClientReceivingV1::Controller { receiving, .. }) =>
                ProtectedBrokerSessionFixedCustodyV1::open_controller_initial_retaining_v1(lower, receiving),
            (SelectedClientEndpointV1::StorageHost(lower), SelectedClientReceivingV1::StorageHost(receiving)) =>
                ProtectedBrokerSessionFixedCustodyV1::open_storage_host_retaining_v1(lower, receiving),
            (SelectedClientEndpointV1::Controller(lower), SelectedClientReceivingV1::StartResource(receiving)) =>
                ProtectedBrokerSessionFixedCustodyV1::open_start_resource_retaining_v4(lower, receiving.loan),
            _ => Err(BrokerSessionSecurityError::Currentness),
        });
        if !matches!(self.fixed, Some(Ok(_))) {
            return self.close(FailureV1::Fixed);
        }
        let Some(Ok(fixed)) = self.fixed.as_mut() else { std::process::abort() };
        self.launch = Some(fixed.attach_launch_image_retaining_v1(self.launch_image.clone()));
        if !matches!(self.launch, Some(Ok(()))) {
            return self.close(FailureV1::Launch);
        }
        if matches!(receiving, SelectedClientReceivingV1::Controller { .. }) {
            self.deadline = Some(match (recover_cut, coverage_cut) {
                (Some(cutoff), None) => Ok(OriginalBrokerColdDeadlineV1::storage_accept(cutoff)),
                (None, Some(cutoff)) => OriginalBrokerColdDeadlineV1::git_coverage(cutoff),
                (None, None) => OriginalBrokerColdDeadlineV1::controller(),
                _ => return self.close(FailureV1::Coverage),
            });
        }
        let deadline = self.deadline_v1()?;
        let Some(Ok(fixed)) = self.fixed.as_ref() else { std::process::abort() };
        self.connected = Some(SeqpacketSocket::connect_zero_rights_retaining_v1(Path::new(fixed.production_socket_path())));
        if !matches!(self.connected, Some(Ok(_))) {
            return self.close(FailureV1::Connection);
        }
        self.deadline_v1()?;
        let Some(Ok(socket)) = self.connected.as_ref() else { std::process::abort() };
        self.peer = Some(ProcessEvidence::capture_peer_retaining(socket.peer()));
        if !matches!(self.peer, Some(Ok(_))) {
            return self.close(FailureV1::Peer);
        }
        let Some(Ok(fixed)) = self.fixed.as_ref() else { std::process::abort() };
        self.hello = Some(if let SelectedClientReceivingV1::StartResource(receiving) = &receiving {
            match receiving.loan.actual_role_v2() {
                Role::Host => aos_sandbox_broker_session_protocol::profile::start_host_catalog_launch_client_hello_v2(),
                Role::Network => aos_sandbox_broker_session_protocol::profile::network_service_client_hello_v5(),
                Role::Mount => aos_sandbox_broker_session_protocol::profile::mount_attachment_anchor_client_hello_v4(),
                Role::Storage => aos_sandbox_broker_session_protocol::profile::storage_lifecycle_client_hello_v2(),
                _ => return self.close(FailureV1::Hello),
            }
        } else if execution_cleanup {
            aos_sandbox_broker_session_protocol::profile::host_no_apply_cleanup_client_hello_v1()
        } else if stop_cleanup {
            aos_sandbox_broker_session_protocol::profile::host_stop_cleanup_client_hello_v1()
        } else if let Some(role) = reconciliation_role {
            match role.broker_role_data_v2() {
                Role::Host => aos_sandbox_broker_session_protocol::profile::controller_reconciliation_inventory_client_hello_v2(aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Host),
                Role::Mount => aos_sandbox_broker_session_protocol::profile::controller_reconciliation_inventory_client_hello_v2(aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Mount),
                Role::Network => aos_sandbox_broker_session_protocol::profile::controller_reconciliation_inventory_client_hello_v2(aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1::Network),
                _ => return self.close(FailureV1::Hello),
            }
        } else if recover_cut.is_some() {
            aos_sandbox_broker_session_protocol::profile::storage_operator_recover_client_hello_v1()
        } else if coverage_cut.is_some() {
            // Only the actual account/profile join above selects these existing
            // closed recipes. Their original 4096-byte response bound and
            // ordinary-plus-coverage method roster remain unchanged.
            let SelectedClientReceivingV1::Controller { receiving, .. } = &receiving else {
                return self.close(FailureV1::Coverage);
            };
            match receiving.role_v1() {
                Role::Mount => aos_sandbox_broker_session_protocol::profile::git_coverage_mount_client_hello_v1(),
                Role::Storage => aos_sandbox_broker_session_protocol::profile::git_coverage_storage_client_hello_v1(),
                _ => return self.close(FailureV1::Coverage),
            }
        } else if let Some(role @ (Role::Mount | Role::Network)) = selected_maintenance_role {
            // The actual newly funded ordinary receiver selects a singleton
            // inventory-first profile. This shared passive HELLO recipe does
            // not reuse the old Recover receiver, clock, prefix or funding.
            let protocol = match role {
                Role::Mount => BrokerSessionProtocolV1::Mount,
                Role::Network => BrokerSessionProtocolV1::Network,
                _ => return self.close(FailureV1::Hello),
            };
            aos_sandbox_broker_session_protocol::profile::controller_reconciliation_inventory_client_hello_v2(protocol)
        } else {
            aos_sandbox_broker_session_protocol::production_broker_client_hello_v1(
                fixed.production_protocol(), fixed.production_audience(),
                aos_sandbox_broker_session_protocol::AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as u32,
            )
        });
        if !matches!(self.hello, Some(Ok(_))) {
            return self.close(FailureV1::Hello);
        }

        // Every fallible original is already parked. These moves only select
        // the existing private retained-disposition three-flight reducer.
        let Some(Ok(fixed)) = self.fixed.take() else { std::process::abort() };
        let Some(Ok(socket)) = self.connected.take() else { std::process::abort() };
        let Some(Ok(hello)) = self.hello.take() else { std::process::abort() };
        let Some(Ok(peer)) = self.peer.as_ref() else { std::process::abort() };
        let (root, _, _, _, custody) = fixed.into_handshake_parts();
        let FixedEndpointCustodyV1::Client(custody) = custody else { std::process::abort() };
        self.handshake = Some(match &receiving {
            SelectedClientReceivingV1::Controller { .. } => DormantControllerClientHandshakeV1::begin_controller_initial_v1(
                root, custody, socket, hello, *peer),
            SelectedClientReceivingV1::StartResource(_) => DormantControllerClientHandshakeV1::begin_start_resource_v4(
                root, custody, socket, hello, *peer),
            SelectedClientReceivingV1::StorageHost(_) => DormantControllerClientHandshakeV1::begin_storage_host_v1(
                root, custody, socket, hello, *peer),
        });
        loop {
            self.deadline_v1()?;
            let Some(handshake) = self.handshake.take() else { std::process::abort() };
            match handshake.advance_retaining_storage() {
                Ok(ColdClientHandshakeProgressV1::Pending(pending)) => {
                    self.handshake = Some(pending);
                    let Some(pending) = self.handshake.as_ref() else { std::process::abort() };
                    let descriptor = match pending.as_fd() {
                        Ok(descriptor) => descriptor,
                        Err(cause) => {
                            self.handshake_error = Some(cause);
                            return self.close(FailureV1::Handshake);
                        }
                    };
                    self.poll = Some(crate::dormant_handshake::wait_for_handshake_readiness_retaining_v1(
                        descriptor, pending.wants_write(), deadline.value(), &mut self.poll_native,
                    ));
                    if !matches!(self.poll, Some(Ok(()))) {
                        return self.close(FailureV1::Poll);
                    }
                }
                Ok(ColdClientHandshakeProgressV1::Verified(verified)) => {
                    self.cold = Some(RetainedStorageColdOpenV1::retain_output(verified, deadline));
                    let Some(cold) = self.cold.as_mut() else { std::process::abort() };
                    self.completed = Some(match &mut receiving {
                        SelectedClientReceivingV1::Controller { receiving, .. } => cold.finish_controller_initial_v1(receiving),
                        SelectedClientReceivingV1::StorageHost(receiving) => cold.finish_storage_host_v1(receiving),
                        SelectedClientReceivingV1::StartResource(receiving) => cold.finish_start_resource_v4(receiving),
                    });
                    if !matches!(self.completed, Some(Ok(_))) {
                        return self.close(FailureV1::Cold);
                    }
                    self.deadline_v1()?;
                    return Ok(());
                }
                Ok(ColdClientHandshakeProgressV1::Complete(session)) => {
                    self.completed = Some(Ok(session));
                    return self.close(FailureV1::Handshake);
                }
                Err(cause) => {
                    self.handshake_error = Some(cause);
                    return self.close(FailureV1::Handshake);
                }
            }
        }
    }

    pub(super) fn take_start_resource_controls_v4(&mut self) -> Option<(
        aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1,
        aos_sandbox_linux::seqpacket::ReceivedRecord,
    )> {
        if !matches!(self.kind, SelectedClientKindV1::StartResource) || self.first.is_some() { return None; }
        let Some(Ok(session)) = self.completed.as_ref() else { return None; };
        if session.terminal_witness_failure || session.terminal_witness_debt.is_some()
            || !matches!(&session.client_witnesses, Ok(Some(witnesses)) if witnesses.first_failure.is_none()) { return None; }
        let cold = self.cold.as_mut()?;
        if cold.phase != StorageColdPhaseV1::Complete || cold.first_failure.is_some()
            || cold.output_witness_debt || cold.hello_disposal.is_some()
            || cold.warm_hello_disposal.is_some() { return None; }
        let controls = cold.hello_controls.as_mut()?;
        if !controls.sent.as_ref().is_some_and(|sent| sent.is_sent()) || controls.record.is_none() { return None; }
        match (controls.sent.take(), controls.record.take()) {
            (Some(sent), Some(record)) => Some((sent, record)),
            _ => std::process::abort(),
        }
    }

    pub(super) fn cold_failure_selected_v4(&self) -> bool {
        matches!(self.first, Some(FailureV1::Cold))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            FailureV1::Coverage => self.coverage_cut.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            FailureV1::Fixed => match &self.lower {
                SelectedClientEndpointV1::Controller(lower) => lower.failure(),
                SelectedClientEndpointV1::StorageHost(lower) => lower.failure(),
            }.or_else(|| self.fixed.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error)),
            FailureV1::Launch => self.launch.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            FailureV1::Deadline => self.deadline.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.cutoff.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error)),
            FailureV1::Connection => self.connected.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            FailureV1::Peer => self.peer.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            FailureV1::Hello => self.hello.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error),
            FailureV1::Handshake => self.handshake_error.as_ref()
                .map(|cause| cause as &dyn std::error::Error)
                .or(Some(&ControllerInitialClientClosedV1 as &dyn std::error::Error)),
            FailureV1::Poll => self.poll_native.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn std::error::Error)
                .or_else(|| self.poll.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error)),
            FailureV1::Cold => self.cold.as_ref().and_then(|cold| match self.kind {
                SelectedClientKindV1::Controller => cold.controller_initial_native_failure_v1(),
                SelectedClientKindV1::StorageHost => cold.storage_host_native_failure_v1(),
                SelectedClientKindV1::StartResource => None,
            })
                .or_else(|| self.cold.as_ref().and_then(RetainedStorageColdOpenV1::output_failure))
                .or_else(|| self.completed.as_ref()?.as_ref().err().map(|cause| cause as &dyn std::error::Error)),
        }
    }
}
