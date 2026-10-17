//! Fixed read-only scalar and RAM observations for admitted performance tests.
//!
//! Only ordinary RAM windows used by the checked-in BIOS/ROM oracle are read.
//! No caller-supplied monitor command, path, address, or output descriptor exists.

use super::*;
#[cfg(test)]
use std::sync::Arc;

const LINE_BYTES: usize = 32 * 1024;

/// Retains bounded post-stop evidence and its original resident credit.
pub struct QemuPerformanceObservation {
    /// Architectural register text from QEMU's fixed read-only monitor query.
    pub registers: String,
    /// Eight bytes at the BIOS arithmetic record's fixed physical address.
    pub bios_prefix: [u8; 8],
    /// Sixteen RAM bytes containing the finite ROM checksum/counter record.
    pub finite_record: [u8; 16],
    /// Eight RAM bytes containing the finite ROM's saved ECX and EAX.
    pub finite_saved_registers: [u8; 8],
    _resident: crucible_ram::ResourceLoan,
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(super) fn performance_observation(
        &mut self,
        guard: &HostOperationGuard,
        resident: crucible_ram::ResourceLoan,
    ) -> Result<QemuPerformanceObservation, QmpError> {
        if self.host_supervisor.is_none() {
            return Err(QmpError::InvalidBound {
                operation: "unadmitted performance observation",
            });
        }
        let old_limit = self.io_timeout_policy.max_line_bytes;
        self.io_timeout_policy.max_line_bytes = old_limit.min(LINE_BYTES);
        let result = self.performance_observation_inner(guard, resident);
        self.io_timeout_policy.max_line_bytes = old_limit;
        result
    }

    fn performance_observation_inner(
        &mut self,
        guard: &HostOperationGuard,
        resident: crucible_ram::ResourceLoan,
    ) -> Result<QemuPerformanceObservation, QmpError> {
        self.performance_paused(guard)?;
        let registers = self.performance_text("info registers", guard)?;
        let bios_prefix = parse_window(&self.performance_text("xp /8bx 0x7000", guard)?, 0x7000)?;
        let finite_record =
            parse_window(&self.performance_text("xp /16bx 0x7000", guard)?, 0x7000)?;
        let finite_saved_registers =
            parse_window(&self.performance_text("xp /8bx 0x5ff8", guard)?, 0x5ff8)?;
        self.performance_paused(guard)?;
        Ok(QemuPerformanceObservation {
            registers,
            bios_prefix,
            finite_record,
            finite_saved_registers,
            _resident: resident,
        })
    }

    pub(super) fn performance_paused(
        &mut self,
        guard: &HostOperationGuard,
    ) -> Result<(), QmpError> {
        let response = self.exchange_under(QmpCommand::QueryStatus, guard)?;
        if response.value.get("status").and_then(Value::as_str) != Some("paused")
            || response.value.get("running").and_then(Value::as_bool) != Some(false)
        {
            return Err(QmpError::InvalidBound {
                operation: "performance observation requires paused QEMU",
            });
        }
        Ok(())
    }

    pub(super) fn performance_text(
        &mut self,
        command: &'static str,
        guard: &HostOperationGuard,
    ) -> Result<String, QmpError> {
        let response =
            self.exchange_under(QmpCommand::PerformanceObservation { command }, guard)?;
        match response.value {
            Value::String(text) if text.len() <= LINE_BYTES => Ok(text),
            _ => Err(QmpError::InvalidBound {
                operation: "bounded performance observation text",
            }),
        }
    }
}

pub(super) fn parse_window<const N: usize>(text: &str, base: u64) -> Result<[u8; N], QmpError> {
    let invalid = || QmpError::InvalidBound {
        operation: "fixed physical RAM observation window",
    };
    let mut bytes = [0; N];
    let mut count = 0;
    for line in text.lines() {
        let (address, values) = line.split_once(':').ok_or_else(invalid)?;
        let address = u64::from_str_radix(address.trim().trim_start_matches("0x"), 16)
            .map_err(|_| invalid())?;
        if address != base + count as u64 {
            return Err(invalid());
        }
        for value in values.split_whitespace() {
            let byte = u8::from_str_radix(value.strip_prefix("0x").ok_or_else(invalid)?, 16)
                .map_err(|_| invalid())?;
            let slot = bytes.get_mut(count).ok_or_else(invalid)?;
            *slot = byte;
            count += 1;
        }
    }
    if count != N {
        return Err(invalid());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixtureStream {
        read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl std::io::Read for FixtureStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.read.read(bytes)
        }
    }

    impl std::io::Write for FixtureStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl QmpTimeoutStream for FixtureStream {
        fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    fn fixture(
        replies: &[Value],
    ) -> (
        QmpClient<FixtureStream>,
        HostOperationSupervisor,
        HostOperationGuard,
    ) {
        let mut lines = vec![
            json!({"QMP":{"version":{},"capabilities":[]}}),
            json!({"return":{}}),
        ];
        lines.extend_from_slice(replies);
        let bytes = lines
            .iter()
            .map(|line| format!("{line}\r\n"))
            .collect::<String>()
            .into_bytes();
        let supervisor = HostOperationSupervisor::new(
            crucible_linux_resource::host_supervision::HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )
        .unwrap_or_else(|error| panic!("finite component transport supervisor: {error}"));
        let guard = supervisor
            .begin(HostOperationClass::CheckpointCapture)
            .unwrap_or_else(|error| panic!("original component observation: {error}"));
        let mut client = QmpClient::connect(FixtureStream {
            read: std::io::Cursor::new(bytes),
            written: Vec::new(),
        })
        .unwrap_or_else(|error| panic!("component QMP transport: {error}"));
        client.set_host_operation_supervisor(supervisor.clone());
        (client, supervisor, guard)
    }

    #[test]
    fn original_cancel_refuses_before_the_first_monitor_byte() {
        let (mut client, supervisor, guard) = fixture(&[]);
        let written = client.stream.get_ref().written.len();
        supervisor
            .cancel()
            .unwrap_or_else(|error| panic!("cancel original component owner: {error}"));

        assert!(matches!(
            client.performance_observation(&guard, crucible_ram::ResourceLoan::new(())),
            Err(QmpError::OperationalSupervision { .. })
        ));
        assert_eq!(client.stream.get_ref().written.len(), written);
    }

    #[test]
    fn fixed_observation_stays_paused_and_retains_its_last_credit() {
        let paused = json!({"return":{"status":"paused","running":false}});
        let (mut client, _supervisor, guard) = fixture(&[
            paused.clone(),
            json!({"return":"EAX=00000001 ECX=00000002"}),
            json!({"return":"00007000: 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08"}),
            json!({"return":"00007000: 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08\n00007008: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"}),
            json!({"return":"00005ff8: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00"}),
            paused,
        ]);
        struct CreditMarker {
            _marker: Arc<()>,
        }

        let marker = Arc::new(());
        let weak = Arc::downgrade(&marker);
        let credit = crucible_ram::ResourceLoan::new(CreditMarker { _marker: marker });
        let observed = client
            .performance_observation(&guard, credit)
            .unwrap_or_else(|error| panic!("fixed component response: {error}"));

        assert_eq!(observed.bios_prefix, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&observed.bios_prefix, &observed.finite_record[..8]);
        assert!(weak.upgrade().is_some());
        assert!(
            guard.wait_slice().is_ok(),
            "the caller's guard remains live"
        );
        assert_eq!(
            client
                .stream
                .get_ref()
                .written
                .windows(b"query-status".len())
                .filter(|bytes| *bytes == b"query-status")
                .count(),
            2
        );
        drop(observed);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn oversized_register_reply_refuses_before_any_ram_read() {
        let (mut client, _supervisor, guard) = fixture(&[
            json!({"return":{"status":"paused","running":false}}),
            json!({"return":"R".repeat(LINE_BYTES)}),
        ]);
        let original_limit = client.io_timeout_policy.max_line_bytes;

        assert!(
            client
                .performance_observation(&guard, crucible_ram::ResourceLoan::new(()))
                .is_err()
        );
        assert_eq!(client.io_timeout_policy.max_line_bytes, original_limit);
        assert!(client.poisoned);
        assert!(
            !client
                .stream
                .get_ref()
                .written
                .windows(b"xp /".len())
                .any(|bytes| bytes == b"xp /")
        );
    }

    #[test]
    fn running_guest_is_rejected_before_any_memory_observation() {
        let (mut client, _supervisor, guard) =
            fixture(&[json!({"return":{"status":"running","running":true}})]);
        assert!(
            client
                .performance_observation(&guard, crucible_ram::ResourceLoan::new(()))
                .is_err()
        );
        assert!(
            !client
                .stream
                .get_ref()
                .written
                .windows(b"human-monitor-command".len())
                .any(|bytes| bytes == b"human-monitor-command")
        );
    }

    #[test]
    fn physical_windows_authenticate_each_address_and_exact_byte_count() {
        assert_eq!(
            parse_window::<4>("00007000: 0x01 0x02\n00007002: 0x03 0x04", 0x7000).ok(),
            Some([1, 2, 3, 4])
        );
        for text in [
            "00007001: 0x01 0x02 0x03 0x04",
            "00007000: 0x01",
            "00007000: 0x01 0x02 0x03 0x04 0x05",
            "00007000: 0x100",
        ] {
            assert!(parse_window::<4>(text, 0x7000).is_err());
        }
    }
}
