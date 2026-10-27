//! Exercises real original/event checks around modeled QMP I/O.

use super::*;
use crucible_host_resources::host_services::HostServiceAllocator;
use crucible_host_resources::host_supervision::{HostOperationBudgets, HostOperationState};
use std::io::{Cursor, Read, Write};
use std::os::fd::OwnedFd;

struct Original {
    supervisor: HostOperationSupervisor,
    guard: HostOperationGuard,
    event: OwnedFd,
    _account: HostServiceAllocator,
}

impl Original {
    fn new() -> Self {
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )
        .unwrap();
        let guard = supervisor.begin(HostOperationClass::Quiescence).unwrap();
        let event = rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )
        .unwrap();
        let account = HostServiceAllocator::new(1, 1, 8192).unwrap();
        let credit = account
            .reserve_resources(
                0,
                1,
                HostOperationGuard::original_quiescence_cancellation_bytes(),
            )
            .unwrap();
        let alias = rustix::io::fcntl_dupfd_cloexec(&event, 0).unwrap();
        guard
            .retain_original_quiescence_cancellation(alias, credit)
            .unwrap();
        Self {
            supervisor,
            guard,
            event,
            _account: account,
        }
    }
}

struct Stream<'a> {
    input: Cursor<Vec<u8>>,
    written: Vec<u8>,
    cancel_on_query_write: Option<&'a OwnedFd>,
    cancel_on_error_newline: Option<&'a OwnedFd>,
    line: Vec<u8>,
}

impl Stream<'_> {
    fn new(responses: &str) -> Self {
        let negotiation = "{\"QMP\":{\"version\":{},\"capabilities\":[]}}\n{\"return\":{}}\n";
        let mut input = negotiation.as_bytes().to_vec();
        input.extend_from_slice(responses.as_bytes());
        Self {
            input: Cursor::new(input),
            written: Vec::new(),
            cancel_on_query_write: None,
            cancel_on_error_newline: None,
            line: Vec::new(),
        }
    }
}

impl Read for Stream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let read = self.input.read(&mut bytes[..1])?;
        self.line.extend_from_slice(&bytes[..read]);
        if self.line.last() == Some(&b'\n') {
            if self.line.starts_with(b"{\"error\"")
                && let Some(event) = self.cancel_on_error_newline.take()
            {
                rustix::io::write(event, &1_u64.to_ne_bytes())?;
            }
            self.line.clear();
        }
        Ok(read)
    }
}

impl Write for Stream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written.extend_from_slice(bytes);
        if self
            .written
            .windows(b"query-status".len())
            .any(|s| s == b"query-status")
            && let Some(event) = self.cancel_on_query_write.take()
        {
            rustix::io::write(event, &1_u64.to_ne_bytes())?;
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl QmpTimeoutStream for Stream<'_> {
    fn set_qmp_read_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }
    fn set_qmp_write_timeout(&mut self, _timeout: Duration) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn successful_queries_neither_complete_original_nor_report_poll_progress() {
    let original = Original::new();
    let before = original.guard.status().unwrap();
    let mut client = QmpClient::connect(Stream::new("{\"return\":{}}\n{\"return\":{}}\n")).unwrap();

    for _ in 0..2 {
        client
            .exchange_under_checkpoint_original(QmpCommand::QueryStatus, &original.guard)
            .unwrap();
    }

    let after = original.guard.status().unwrap();
    assert_eq!(after.operation_id, before.operation_id);
    assert_eq!(after.state, HostOperationState::Running);
    assert_eq!(after.completed_work_units, before.completed_work_units);
    assert_eq!(after.outstanding_work_units, before.outstanding_work_units);
    assert!(
        after.effective_deadline.unwrap().remaining <= before.effective_deadline.unwrap().remaining
    );
    assert_eq!(original.supervisor.operation_statuses().unwrap().len(), 1);
}

#[test]
fn cancellation_before_exchange_refuses_without_any_command_write() {
    let original = Original::new();
    let mut client = QmpClient::connect(Stream::new("{\"return\":{}}\n")).unwrap();
    let before = client.stream.get_ref().written.len();
    rustix::io::write(&original.event, &1_u64.to_ne_bytes()).unwrap();

    let refusal = client
        .exchange_under_checkpoint_original(QmpCommand::QueryStatus, &original.guard)
        .unwrap_err();

    assert!(matches!(
        refusal.source,
        QmpError::CheckpointOriginal { .. }
    ));
    assert!(refusal.original_after.is_some());
    assert_eq!(client.stream.get_ref().written.len(), before);
}

#[test]
fn canceled_alias_after_write_poisons_uncertain_cursor_and_keeps_original() {
    let original = Original::new();
    let mut stream = Stream::new("{\"return\":{}}\n");
    stream.cancel_on_query_write = Some(&original.event);
    let mut client = QmpClient::connect(stream).unwrap();

    let refusal = client
        .exchange_under_checkpoint_original(QmpCommand::QueryStatus, &original.guard)
        .unwrap_err();

    assert!(matches!(
        refusal.source,
        QmpError::CheckpointOriginal { .. }
    ));
    assert!(refusal.original_after.is_some());
    assert!(client.poisoned);
    assert_eq!(original.supervisor.operation_statuses().unwrap().len(), 1);
}

#[test]
fn complete_command_refusal_stays_primary_when_original_cancels_on_final_read() {
    let original = Original::new();
    let mut stream = Stream::new("{\"error\":{\"class\":\"GenericError\",\"desc\":\"refused\"}}\n");
    stream.cancel_on_error_newline = Some(&original.event);
    let mut client = QmpClient::connect(stream).unwrap();

    let refusal = client
        .exchange_under_checkpoint_original(QmpCommand::QueryStatus, &original.guard)
        .unwrap_err();

    assert!(matches!(refusal.source, QmpError::Command { .. }));
    assert!(refusal.original_after.is_some());
    assert_eq!(original.supervisor.operation_statuses().unwrap().len(), 1);
}

#[test]
fn amended_original_expiration_prevents_retry_without_new_start_or_write() {
    let original = Original::new();
    let id = original.guard.status().unwrap().operation_id;
    let mut client = QmpClient::connect(Stream::new("{\"return\":{}}\n")).unwrap();
    let before = client.stream.get_ref().written.len();
    let (revision, mut budgets) = original.supervisor.budgets().unwrap();
    budgets.classes[HostOperationClass::Quiescence as usize].total_timeout =
        Some(Duration::from_nanos(1));
    original
        .supervisor
        .update_budgets(revision, budgets)
        .unwrap();

    let first = client
        .exchange_under_checkpoint_original(QmpCommand::QueryStatus, &original.guard)
        .unwrap_err();
    assert!(matches!(first.source, QmpError::CheckpointOriginal { .. }));
    assert!(first.original_after.is_some());
    assert!(client.poisoned);

    let retry = client
        .exchange_under_checkpoint_original(QmpCommand::QueryStatus, &original.guard)
        .unwrap_err();
    assert!(matches!(retry.source, QmpError::ConnectionPoisoned));
    assert_eq!(retry.original_after, first.original_after);

    assert_eq!(client.stream.get_ref().written.len(), before);
    assert_eq!(original.guard.status().unwrap().operation_id, id);
    assert_eq!(original.supervisor.operation_statuses().unwrap().len(), 1);
}

#[test]
fn used_client_commands_borrow_one_original_without_new_operation_births() {
    let (_owner, loan, supervisor, _event, _account) =
        crate::node::checkpoint_original_loan_fixture();
    let stream = Stream::new("{\"return\":{}}\n{\"return\":{}}\n");
    let mut client = QmpClient::connect(stream).unwrap();
    client.bind_checkpoint_original(loan).unwrap();

    client.send_command_return(QmpCommand::QueryStatus).unwrap();
    client.send_command_return(QmpCommand::QueryStatus).unwrap();

    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
    assert!(!client.poisoned);
}

#[test]
fn used_client_keeps_command_rejection_before_independent_original_postcut() {
    let (_owner, loan, supervisor, event, _account) =
        crate::node::checkpoint_original_loan_fixture();
    let mut stream =
        Stream::new("{\"error\":{\"class\":\"GenericError\",\"desc\":\"first cause\"}}\n");
    stream.cancel_on_error_newline = Some(&event);
    let mut client = QmpClient::connect(stream).unwrap();
    client.bind_checkpoint_original(loan).unwrap();

    let error = client
        .send_command_return(QmpCommand::QueryStatus)
        .unwrap_err();

    let QmpError::CheckpointPostcut {
        source,
        original_after,
    } = error
    else {
        panic!("expected initiating cause and independent postcut");
    };
    assert!(matches!(*source, QmpError::Command { .. }));
    assert!(matches!(
        original_after,
        HostSupervisionError::Terminal {
            state: HostOperationState::Canceled
        }
    ));
    assert!(client.poisoned);
    assert_eq!(supervisor.operation_statuses().unwrap().len(), 1);
}
