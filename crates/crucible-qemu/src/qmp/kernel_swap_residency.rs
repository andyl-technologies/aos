//! Bounded interval observations for the controlled kernel-swap experiment.
//!
//! Pausing the guest does not freeze host reclamation. These samples neither
//! certify a simultaneous residency target nor authenticate swap storage.

use super::*;
use std::os::fd::{AsFd, OwnedFd};

const CANCELLATION_NAME: &str = "kernel-swap-residency-cancellation";

/// Versioned command for an interval scan of the main guest RAM mapping.
pub const QMP_QUERY_KERNEL_SWAP_RESIDENCY_COMMAND: &str = "query-crucible-kernel-swap-residency-v1";

/// Versioned command for the sealed main-RAM identity at a paused boundary.
pub const QMP_QUERY_KERNEL_SWAP_ADMISSION_COMMAND: &str = "query-crucible-kernel-swap-admission-v1";

/// Identifies the immutable main-RAM inventory at the requested VM-stop.
///
/// The response contains no memory contents or residency certificate. Matching
/// identities do not grant storage, placement, cancellation or VM authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpKernelSwapAdmission {
    /// Actual paused VM-stop generation, checked before and after discovery.
    pub generation: u64,
    /// Actual generation of the sealed native main-RAM inventory.
    pub topology_generation: u64,
}

const GUEST_BYTES: u64 = 512 * 1024 * 1024;
const PAGE_BYTES: u64 = 4096;
const CHUNK_PAGES: u64 = 64;
const RESPONSE_BYTES: usize = 4096;

/// Records associated per-page samples over a paused observation interval.
///
/// Pagemap, its scan ioctl and mincore run separately. Even zero observed
/// discrepancies cannot establish one instantaneous whole-RAM snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpKernelSwapResidency {
    /// Admitted paused generation, checked before and after scanning.
    pub generation: u64,
    /// Generation of the immutable native admitted RAM inventory.
    pub topology_generation: u64,
    /// Pages with present pagemap entries when their chunk was read.
    pub pte_present_pages: u64,
    /// Pages with swapped pagemap entries when their chunk was read.
    pub pte_swapped_pages: u64,
    /// Pages with neither a present nor swapped entry at that sample.
    pub pte_absent_pages: u64,
    /// Mincore resident pages, including resident swap-cache pages.
    pub resident_pages: u64,
    /// Scan entries identifying the kernel zero-page alias.
    pub scan_zero_pages: u64,
    /// Same page coordinates sampled as swapped and later nonresident.
    pub sampled_swapped_nonresident_pages: u64,
    /// Present/swapped classification differences between the two PTE scans.
    pub changed_pte_pages: u64,
}

/// Retains one imported cancellation descriptor's host-side custody.
///
/// The experimental caller must admit its name and descriptor births, publish
/// this non-Clone value in the owned VM row before observation, and retain that
/// row through physical retirement whenever closure remains uncertain. The
/// caller also owns exclusive use of this fixed name on the exact connection
/// and generation. This value grants no VM, memory or swap authority.
#[derive(Debug)]
#[must_use = "retain descriptor custody through closure or physical VM retirement"]
pub struct QmpKernelSwapCancellation {
    name: QmpDescriptorName,
    descriptor: OwnedFd,
    phase: CancellationPhase,
}

#[derive(Debug, PartialEq, Eq)]
enum CancellationPhase {
    Prepared,
    ImportStarted,
    QueryStarted,
    CloseStarted,
    Closed,
}

impl QmpKernelSwapCancellation {
    /// Duplicates the retained process contract's existing cancellation event.
    ///
    /// The caller checks its original operation and prepays the enclosing
    /// purpose before constructing this value. Construction creates no timer,
    /// cancellation event, resource bank or admission loan.
    ///
    /// # Errors
    /// Returns the original spawn error if the existing eventfd cannot be
    /// duplicated. No descriptor has been imported into QEMU on this path.
    pub fn new(
        contract: &crate::spawn::QemuChildProcessContract,
    ) -> Result<Self, crate::QemuSpawnError> {
        let name = QmpDescriptorName(CANCELLATION_NAME.to_owned());
        let descriptor = contract.try_clone_cancellation_event()?;
        Ok(Self {
            name,
            descriptor,
            phase: CancellationPhase::Prepared,
        })
    }

    /// Discovers the sealed RAM identity under the same original operation.
    ///
    /// This single-use command imports the existing cancellation event before
    /// looking up mapping metadata. A parsed success acknowledges accepted
    /// handler consumption; any failure retains uncertain descriptor custody.
    /// The caller supplies the actual paused generation and owns the exact
    /// connection and fixed-name exclusivity, as for [`Self::observe`].
    ///
    /// # Errors
    /// Returns the existing QMP error for supervision, import, dispatch,
    /// transport or response validation, or refuses invalid or reused owners.
    pub fn discover_admission<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
        generation: u64,
        original: &HostOperationGuard,
    ) -> Result<QmpKernelSwapAdmission, QmpError> {
        client.ensure_usable()?;
        original
            .wait_slice()
            .map_err(|error| QmpError::OperationalSupervision {
                operation: "kernel-swap descriptor admission",
                message: error.to_string(),
            })?;
        if self.phase != CancellationPhase::Prepared || !valid_generation(generation) {
            return Err(invalid());
        }

        self.phase = CancellationPhase::ImportStarted;
        client.install_kernel_swap_cancellation(&self.name, self.descriptor.as_fd(), original)?;
        self.phase = CancellationPhase::QueryStarted;
        let response = client.query_kernel_swap_admission(generation, &self.name, original)?;
        self.phase = CancellationPhase::Closed;
        Ok(response)
    }

    /// Imports cancellation and observes RAM under the same original operation.
    ///
    /// A parsed success acknowledges the accepted handler's consume-and-close
    /// contract. Any uncertain import or query keeps this value responsible
    /// for cleanup; an error response alone cannot establish handler entry.
    /// This is a single-use operation on the caller's exact owned connection.
    ///
    /// # Errors
    /// Returns the existing QMP error unchanged for original supervision,
    /// descriptor transfer, dispatch, transport or response validation failure.
    /// Reusing an already started owner is refused before further I/O.
    pub fn observe<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
        generation: u64,
        topology_generation: u64,
        original: &HostOperationGuard,
    ) -> Result<QmpKernelSwapResidency, QmpError> {
        client.ensure_usable()?;
        original
            .wait_slice()
            .map_err(|error| QmpError::OperationalSupervision {
                operation: "kernel-swap descriptor admission",
                message: error.to_string(),
            })?;
        if self.phase != CancellationPhase::Prepared
            || !valid_generation(generation)
            || !valid_generation(topology_generation)
        {
            return Err(invalid());
        }

        // Publish uncertainty before the first descriptor-carrying write.
        self.phase = CancellationPhase::ImportStarted;
        client.install_kernel_swap_cancellation(&self.name, self.descriptor.as_fd(), original)?;
        self.phase = CancellationPhase::QueryStarted;
        let response = client.query_kernel_swap_residency(
            generation,
            topology_generation,
            &self.name,
            original,
        )?;
        self.phase = CancellationPhase::Closed;
        Ok(response)
    }

    /// Attempts one named-descriptor closure under the caller's Cleanup guard.
    ///
    /// The caller saves the observation's primary error before this exchange
    /// and retains this independent result. A rejected or ambiguous closure,
    /// including a textual missing-FD response, leaves retirement required.
    /// No operation is begun and the measurement deadline is never renewed.
    ///
    /// # Errors
    /// Returns the existing QMP error for cleanup supervision, rejection or
    /// transport failure, or refuses a value without an uncertain import.
    pub fn close_after_failure<S: QmpTimeoutStream>(
        &mut self,
        client: &mut QmpClient<S>,
        cleanup: &HostOperationGuard,
    ) -> Result<QmpCommandComplete, QmpError> {
        if !matches!(
            self.phase,
            CancellationPhase::ImportStarted | CancellationPhase::QueryStarted
        ) {
            return Err(invalid());
        }
        self.phase = CancellationPhase::CloseStarted;
        let response = client.exchange_under(QmpCommand::CloseFd { name: &self.name }, cleanup)?;
        self.phase = CancellationPhase::Closed;
        Ok(QmpCommandComplete {
            command: response.command,
        })
    }

    /// Reports whether uncertain native ownership still requires VM retirement.
    ///
    /// A false result after success records a monitor closure acknowledgement,
    /// not an external physical-close certificate or complete VM retirement.
    #[must_use]
    pub fn requires_native_retirement(&self) -> bool {
        matches!(
            self.phase,
            CancellationPhase::ImportStarted
                | CancellationPhase::QueryStarted
                | CancellationPhase::CloseStarted
        )
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    fn install_kernel_swap_cancellation(
        &mut self,
        name: &QmpDescriptorName,
        descriptor: BorrowedFd<'_>,
        original: &HostOperationGuard,
    ) -> Result<QmpCommandComplete, QmpError> {
        self.ensure_usable()?;
        let command = QmpCommand::GetFd { name };
        let kind = command.kind();
        let mut deadline = QmpOperationDeadline::new(self.io_timeout_policy.command_timeout);
        deadline.borrowed = Some(original);
        let result = self
            .write_json_line_with_descriptor(
                kind.wire_name(),
                command.request(),
                descriptor,
                &deadline,
            )
            .and_then(|()| self.read_command_response(kind, &deadline))
            .and_then(|response| {
                deadline.complete(kind.wire_name())?;
                Ok(QmpCommandComplete {
                    command: response.command,
                })
            });
        self.poison_after_descriptor_mutation_error(result)
    }

    fn query_kernel_swap_admission(
        &mut self,
        generation: u64,
        name: &QmpDescriptorName,
        original: &HostOperationGuard,
    ) -> Result<QmpKernelSwapAdmission, QmpError> {
        if !valid_generation(generation) {
            return Err(invalid());
        }

        let old_limit = self.io_timeout_policy.max_line_bytes;
        self.io_timeout_policy.max_line_bytes = old_limit.min(RESPONSE_BYTES);
        let result = self.exchange_under(
            QmpCommand::QueryKernelSwapAdmission {
                generation,
                cancellation: name,
            },
            original,
        );
        self.io_timeout_policy.max_line_bytes = old_limit;

        parse_admission(&result?.value, generation)
    }

    /// Observes main RAM without reading its contents or changing guest state.
    ///
    /// The cancellation descriptor must already belong to QEMU under `name`
    /// and to this original operation. An accepted handler consumes and closes
    /// that descriptor; earlier dispatch refusal does not. The enclosing owner
    /// retains uncertain custody until named closure or physical VM cleanup.
    ///
    /// # Errors
    /// Refuses invalid generations, expired original supervision, unsupported
    /// native mappings, cancellation and malformed or inconsistent responses.
    fn query_kernel_swap_residency(
        &mut self,
        generation: u64,
        topology_generation: u64,
        name: &QmpDescriptorName,
        original: &HostOperationGuard,
    ) -> Result<QmpKernelSwapResidency, QmpError> {
        if !valid_generation(generation) || !valid_generation(topology_generation) {
            return Err(invalid());
        }

        let old_limit = self.io_timeout_policy.max_line_bytes;
        self.io_timeout_policy.max_line_bytes = old_limit.min(RESPONSE_BYTES);
        let result = self.exchange_under(
            QmpCommand::QueryKernelSwapResidency {
                generation,
                topology_generation,
                cancellation: name,
            },
            original,
        );
        self.io_timeout_policy.max_line_bytes = old_limit;

        let response = result?;
        parse_residency(&response.value, generation, topology_generation)
    }
}

fn valid_generation(generation: u64) -> bool {
    generation != 0 && generation != u64::MAX
}

fn invalid() -> QmpError {
    QmpError::InvalidBound {
        operation: "kernel-swap interval observation",
    }
}

fn parse_admission(value: &Value, generation: u64) -> Result<QmpKernelSwapAdmission, QmpError> {
    const FIELDS: [&str; 5] = [
        "schema-version",
        "generation",
        "topology-generation",
        "native-page-size",
        "guest-bytes",
    ];
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != FIELDS.len() || object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(invalid());
    }
    let number = |key: &str| object.get(key).and_then(Value::as_u64).ok_or_else(invalid);
    let topology_generation = number("topology-generation")?;
    if !valid_generation(generation)
        || !valid_generation(topology_generation)
        || number("schema-version")? != 1
        || number("generation")? != generation
        || number("native-page-size")? != PAGE_BYTES
        || number("guest-bytes")? != GUEST_BYTES
    {
        return Err(invalid());
    }

    Ok(QmpKernelSwapAdmission {
        generation,
        topology_generation,
    })
}

fn parse_residency(
    value: &Value,
    generation: u64,
    topology_generation: u64,
) -> Result<QmpKernelSwapResidency, QmpError> {
    const FIELDS: [&str; 16] = [
        "schema-version",
        "observation",
        "generation",
        "topology-generation",
        "native-page-size",
        "guest-bytes",
        "guest-pages",
        "chunks",
        "pte-present-pages",
        "pte-swapped-pages",
        "pte-absent-pages",
        "resident-pages",
        "scan-zero-pages",
        "sampled-swapped-nonresident-pages",
        "changed-pte-pages",
        "target-certified",
    ];
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != FIELDS.len() || object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(invalid());
    }
    let number = |key: &str| object.get(key).and_then(Value::as_u64).ok_or_else(invalid);
    let pages = GUEST_BYTES / PAGE_BYTES;
    if !valid_generation(generation)
        || !valid_generation(topology_generation)
        || number("schema-version")? != 1
        || object.get("observation").and_then(Value::as_str) != Some("interval")
        || object.get("target-certified").and_then(Value::as_bool) != Some(false)
        || number("generation")? != generation
        || number("topology-generation")? != topology_generation
        || number("native-page-size")? != PAGE_BYTES
        || number("guest-bytes")? != GUEST_BYTES
        || number("guest-pages")? != pages
        || number("chunks")? != pages.div_ceil(CHUNK_PAGES)
    {
        return Err(invalid());
    }

    let observed = QmpKernelSwapResidency {
        generation,
        topology_generation,
        pte_present_pages: number("pte-present-pages")?,
        pte_swapped_pages: number("pte-swapped-pages")?,
        pte_absent_pages: number("pte-absent-pages")?,
        resident_pages: number("resident-pages")?,
        scan_zero_pages: number("scan-zero-pages")?,
        sampled_swapped_nonresident_pages: number("sampled-swapped-nonresident-pages")?,
        changed_pte_pages: number("changed-pte-pages")?,
    };
    if observed
        .pte_present_pages
        .checked_add(observed.pte_swapped_pages)
        .and_then(|sum| sum.checked_add(observed.pte_absent_pages))
        != Some(pages)
        || observed.resident_pages > pages
        || observed.scan_zero_pages > pages
        || observed.changed_pte_pages > pages
        || observed.sampled_swapped_nonresident_pages > observed.pte_swapped_pages
        || observed.sampled_swapped_nonresident_pages > pages - observed.resident_pages
    {
        return Err(invalid());
    }
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn fixture() -> Value {
        json!({
            "schema-version":1,"observation":"interval","generation":17,
            "topology-generation":23,"native-page-size":4096,
            "guest-bytes":GUEST_BYTES,"guest-pages":131072,"chunks":2048,
            "pte-present-pages":65536,"pte-swapped-pages":32768,
            "pte-absent-pages":32768,"resident-pages":70000,"scan-zero-pages":100,
            "sampled-swapped-nonresident-pages":30000,"changed-pte-pages":19,
            "target-certified":false
        })
    }

    #[derive(Debug)]
    struct Stream {
        read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for Stream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.read.read(bytes)
        }
    }

    impl Write for Stream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl QmpTimeoutStream for Stream {
        fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }
        fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    fn client() -> (
        QmpClient<Stream>,
        HostOperationSupervisor,
        HostOperationGuard,
    ) {
        let input = format!(
            "{}\n{}\n{}\n",
            json!({"QMP":{"version":{},"capabilities":[]}}),
            json!({"return":{}}),
            json!({"return":fixture()})
        );
        let supervisor = HostOperationSupervisor::new(
            crucible_linux_resource::host_supervision::HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )
        .expect("finite component supervisor");
        let guard = supervisor
            .begin(HostOperationClass::CheckpointCapture)
            .expect("original");
        let client = QmpClient::connect(Stream {
            read: std::io::Cursor::new(input.into_bytes()),
            written: Vec::new(),
        })
        .expect("component transport");
        (client, supervisor, guard)
    }

    #[test]
    fn canceled_original_refuses_before_query_bytes() {
        let (mut client, supervisor, guard) = client();
        let before = client.stream.get_ref().written.len();
        supervisor.cancel().expect("cancel original");
        let name = QmpDescriptorName::new("original-residency-cancellation").expect("name");
        assert!(matches!(
            client.query_kernel_swap_residency(17, 23, &name, &guard),
            Err(QmpError::OperationalSupervision { .. })
        ));
        assert_eq!(client.stream.get_ref().written.len(), before);
        assert_eq!(client.io_timeout_policy.max_line_bytes, QMP_MAX_LINE_BYTES);
    }

    #[test]
    fn exchange_borrows_original_without_completing_it() {
        let (mut client, _supervisor, guard) = client();
        let name = QmpDescriptorName::new("original-residency-cancellation").expect("name");
        let observed = client
            .query_kernel_swap_residency(17, 23, &name, &guard)
            .expect("interval");
        assert_eq!(observed.generation, 17);
        assert!(guard.wait_slice().is_ok());
        let request = std::str::from_utf8(&client.stream.get_ref().written).expect("JSON");
        assert!(request.contains("query-crucible-kernel-swap-residency-v1"));
        assert!(request.contains("expected-topology-generation"));
        assert_eq!(client.io_timeout_policy.max_line_bytes, QMP_MAX_LINE_BYTES);
    }

    #[test]
    fn interval_preserves_temporal_discrepancies_and_swap_cache() {
        let observed = parse_residency(&fixture(), 17, 23).expect("valid interval");
        assert_eq!(observed.changed_pte_pages, 19);
        assert_eq!(observed.resident_pages, 70000);
        assert_eq!(observed.sampled_swapped_nonresident_pages, 30000);
    }

    #[test]
    fn zero_discrepancies_do_not_certify_a_target() {
        let mut value = fixture();
        value["changed-pte-pages"] = json!(0);
        assert!(parse_residency(&value, 17, 23).is_ok());
        value["target-certified"] = json!(true);
        assert!(parse_residency(&value, 17, 23).is_err());
    }

    #[test]
    fn rejects_foreign_scope_overflow_and_impossible_association() {
        let value = fixture();
        assert!(parse_residency(&value, 18, 23).is_err());
        assert!(parse_residency(&value, 17, 24).is_err());
        for (field, replacement) in [
            ("generation", json!(0)),
            ("chunks", json!(2049)),
            ("pte-present-pages", json!(u64::MAX)),
            ("sampled-swapped-nonresident-pages", json!(65000)),
            ("observation", json!("atomic")),
            ("native-page-size", json!(8192)),
        ] {
            let mut changed = value.clone();
            changed[field] = replacement;
            assert!(parse_residency(&changed, 17, 23).is_err(), "{field}");
        }
        let mut extra = value;
        extra["native-pointer"] = json!(0);
        assert!(parse_residency(&extra, 17, 23).is_err());
    }
}

#[cfg(test)]
mod descriptor_custody_tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};

    #[derive(Debug)]
    struct DescriptorStream {
        input: io::Cursor<Vec<u8>>,
        imported: Option<OwnedFd>,
        imports: usize,
        queries: usize,
        closes: usize,
        consume_on_query: bool,
        close_succeeds: bool,
        panic_on_query: bool,
    }

    impl Read for DescriptorStream {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.input.read(output)
        }
    }

    impl Write for DescriptorStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let request: Value = serde_json::from_slice(bytes).expect("fixture complete request");
            match request
                .get("execute")
                .or_else(|| request.get("exec-oob"))
                .and_then(Value::as_str)
                .expect("command")
            {
                QMP_QUERY_KERNEL_SWAP_RESIDENCY_COMMAND
                | QMP_QUERY_KERNEL_SWAP_ADMISSION_COMMAND => {
                    self.queries += 1;
                    assert!(!self.panic_on_query, "fixture query write panic");
                    if self.consume_on_query {
                        drop(self.imported.take());
                    }
                }
                "closefd" => {
                    self.closes += 1;
                    if self.close_succeeds {
                        drop(self.imported.take());
                    }
                }
                "qmp_capabilities" | QMP_QUERY_PAUSED_CPU_COMMAND => {}
                command => panic!("unexpected fixture command: {command}"),
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl QmpTimeoutStream for DescriptorStream {
        fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn send_qmp_bytes_with_descriptor(
            &mut self,
            bytes: &[u8],
            descriptor: BorrowedFd<'_>,
        ) -> io::Result<usize> {
            assert!(self.imported.is_none(), "fixed name is exclusively owned");
            self.imported = Some(descriptor.try_clone_to_owned()?);
            self.imports += 1;
            let request: Value = serde_json::from_slice(bytes).expect("getfd request");
            assert_eq!(request["exec-oob"], "getfd");
            assert_eq!(request["arguments"]["fdname"], CANCELLATION_NAME);
            Ok(bytes.len())
        }
    }

    fn rejection(class: &str, description: &str) -> Value {
        json!({"error":{"class":class,"desc":description}})
    }

    fn fixture_client(responses: &[Value]) -> QmpClient<DescriptorStream> {
        let mut input = format!(
            "{}\n{}\n",
            json!({"QMP":{"version":{},"capabilities":[]}}),
            json!({"return":{}})
        );
        for response in responses {
            input.push_str(&format!("{response}\n"));
        }
        QmpClient::connect(DescriptorStream {
            input: io::Cursor::new(input.into_bytes()),
            imported: None,
            imports: 0,
            queries: 0,
            closes: 0,
            consume_on_query: false,
            close_succeeds: true,
            panic_on_query: false,
        })
        .expect("component transport")
    }

    fn original() -> (HostOperationSupervisor, HostOperationGuard) {
        let supervisor = HostOperationSupervisor::new(
            crucible_linux_resource::host_supervision::HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )
        .expect("finite original component policy");
        let operation = supervisor
            .begin(HostOperationClass::CheckpointCapture)
            .expect("original operation");
        (supervisor, operation)
    }

    fn cancellation() -> (QmpKernelSwapCancellation, OwnedFd) {
        // SAFETY: eventfd has no pointer arguments. A successful call creates
        // one fresh descriptor which is immediately given exactly one owner.
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(raw >= 0);
        // SAFETY: raw is the live, uniquely owned successful eventfd result.
        let event = unsafe { OwnedFd::from_raw_fd(raw) };
        let retained = event.try_clone().expect("same original event");
        let procs: OwnedFd = std::fs::File::open("/dev/null")
            .expect("model process descriptor")
            .into();
        let contract = crate::spawn::QemuChildProcessContract::from_unvalidated_test_descriptors(
            procs,
            event,
            1,
            GUEST_BYTES,
            4 * 1024 * 1024 * 1024,
        );
        // This exercises the actual contract duplicate method, not physical
        // containment or an experiment grant. The original fixture event lives
        // independently of both the contract and this query's duplicate.
        let cancellation = QmpKernelSwapCancellation::new(&contract).expect("contract duplicate");
        (cancellation, retained)
    }

    fn admission_fixture() -> Value {
        json!({
            "schema-version": 1,
            "generation": 17,
            "topology-generation": 23,
            "native-page-size": PAGE_BYTES,
            "guest-bytes": GUEST_BYTES,
        })
    }

    #[test]
    fn admission_parser_keeps_actual_identity_and_refuses_other_editions() {
        eprintln!(
            "admission={} alignment={} cancellation={} residency={} command={}",
            std::mem::size_of::<QmpKernelSwapAdmission>(),
            std::mem::align_of::<QmpKernelSwapAdmission>(),
            std::mem::size_of::<QmpKernelSwapCancellation>(),
            std::mem::size_of::<QmpKernelSwapResidency>(),
            std::mem::size_of::<QmpCommandKind>(),
        );
        let fixture = admission_fixture();
        assert_eq!(
            parse_admission(&fixture, 17).expect("closed response"),
            QmpKernelSwapAdmission {
                generation: 17,
                topology_generation: 23,
            }
        );
        assert!(parse_admission(&fixture, 18).is_err());
        for (field, replacement) in [
            ("schema-version", json!(2)),
            ("generation", json!(0)),
            ("generation", json!(u64::MAX)),
            ("topology-generation", json!(0)),
            ("topology-generation", json!(u64::MAX)),
            ("native-page-size", json!(8192)),
            ("guest-bytes", json!(GUEST_BYTES - 1)),
            ("topology-generation", json!("23")),
        ] {
            let mut changed = fixture.clone();
            changed[field] = replacement;
            assert!(parse_admission(&changed, 17).is_err(), "{field}");
        }
        for field in [
            "schema-version",
            "generation",
            "topology-generation",
            "native-page-size",
            "guest-bytes",
        ] {
            let mut missing = fixture.clone();
            missing
                .as_object_mut()
                .expect("fixture object")
                .remove(field);
            assert!(parse_admission(&missing, 17).is_err(), "{field}");
        }
        let mut extra = fixture;
        extra["native-pointer"] = json!(0);
        assert!(parse_admission(&extra, 17).is_err());
    }

    #[test]
    fn admission_owner_imports_once_and_keeps_original_live() {
        let (mut owner, _event) = cancellation();
        let (_supervisor, original) = original();
        let mut client =
            fixture_client(&[json!({"return":{}}), json!({"return":admission_fixture()})]);
        client.stream.get_mut().consume_on_query = true;

        let identity = owner
            .discover_admission(&mut client, 17, &original)
            .expect("identity");

        assert_eq!(identity.topology_generation, 23);
        assert_eq!(owner.phase, CancellationPhase::Closed);
        assert!(!owner.requires_native_retirement());
        assert!(client.stream.get_ref().imported.is_none());
        assert!(original.wait_slice().is_ok());
        assert!(
            owner
                .discover_admission(&mut client, 17, &original)
                .is_err()
        );
        assert!(owner.observe(&mut client, 17, 23, &original).is_err());
        assert_eq!(client.stream.get_ref().imports, 1);
        assert_eq!(client.stream.get_ref().queries, 1);
        assert_eq!(client.stream.get_ref().closes, 0);
    }

    #[test]
    fn admission_owner_keeps_dispatch_primary_and_independent_cleanup() {
        let (mut owner, _event) = cancellation();
        let (supervisor, original) = original();
        let mut client = fixture_client(&[
            json!({"return":{}}),
            rejection("CommandNotFound", "admission unsupported"),
            json!({"return":{}}),
        ]);

        let primary = owner
            .discover_admission(&mut client, 17, &original)
            .expect_err("dispatch");
        assert!(owner.requires_native_retirement());
        let cleanup = supervisor
            .begin(HostOperationClass::Cleanup)
            .expect("same supervisor cleanup");
        owner
            .close_after_failure(&mut client, &cleanup)
            .expect("one monitor removal");

        assert!(matches!(primary, QmpError::Command {
            command: QmpCommandKind::QueryKernelSwapAdmission,
            ref class,
            ref description,
        } if class == "CommandNotFound" && description == "admission unsupported"));
        assert_eq!(client.stream.get_ref().closes, 1);
        assert_eq!(owner.phase, CancellationPhase::Closed);
    }

    #[test]
    fn admission_closed_original_cannot_borrow_ambient_authority() {
        let (mut owner, _event) = cancellation();
        let (supervisor, original) = original();
        let (ambient, _ambient_operation) = self::original();
        let mut client = fixture_client(&[]);
        client.set_host_operation_supervisor(ambient);
        supervisor.cancel().expect("cancel actual original");

        assert!(matches!(
            owner.discover_admission(&mut client, 17, &original),
            Err(QmpError::OperationalSupervision { .. })
        ));
        assert_eq!(owner.phase, CancellationPhase::Prepared);
        assert_eq!(client.stream.get_ref().imports, 0);
        assert_eq!(client.stream.get_ref().queries, 0);
    }

    #[test]
    fn admission_invalid_generation_refuses_before_descriptor_birth_in_vm() {
        for generation in [0, u64::MAX] {
            let (mut owner, _event) = cancellation();
            let (_supervisor, original) = original();
            let mut client = fixture_client(&[]);

            assert!(
                owner
                    .discover_admission(&mut client, generation, &original)
                    .is_err()
            );

            assert_eq!(owner.phase, CancellationPhase::Prepared);
            assert_eq!(client.stream.get_ref().imports, 0);
            assert_eq!(client.stream.get_ref().queries, 0);
        }
    }

    #[test]
    fn admission_loss_and_unwind_keep_uncertain_owner_reachable() {
        for responses in [vec![], vec![json!({"return":{}})]] {
            let (mut owner, _event) = cancellation();
            let (_supervisor, original) = original();
            let mut client = fixture_client(&responses);

            assert!(
                owner
                    .discover_admission(&mut client, 17, &original)
                    .is_err()
            );

            assert!(owner.requires_native_retirement());
            assert!(client.stream.get_ref().imported.is_some());
            assert_eq!(client.stream.get_ref().imports, 1);
        }
        let (mut owner, _event) = cancellation();
        let (_supervisor, original) = original();
        let mut client = fixture_client(&[json!({"return":{}})]);
        client.stream.get_mut().panic_on_query = true;

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.discover_admission(&mut client, 17, &original)
        }));

        assert!(panic.is_err());
        assert_eq!(owner.phase, CancellationPhase::QueryStarted);
        assert!(owner.requires_native_retirement());
        assert!(client.stream.get_ref().imported.is_some());
    }

    #[test]
    fn admission_malformed_response_keeps_uncertainty_even_after_handler_close() {
        let (mut owner, _event) = cancellation();
        let (_supervisor, original) = original();
        let mut client =
            fixture_client(&[json!({"return":{}}), json!({"return":{"generation":17}})]);
        client.stream.get_mut().consume_on_query = true;

        assert!(
            owner
                .discover_admission(&mut client, 17, &original)
                .is_err()
        );

        assert_eq!(owner.phase, CancellationPhase::QueryStarted);
        assert!(owner.requires_native_retirement());
        assert!(client.stream.get_ref().imported.is_none());
        assert_eq!(client.stream.get_ref().queries, 1);
    }

    #[test]
    fn dispatch_refusal_closes_once_and_preserves_original_primary() {
        for (class, description) in [
            ("CommandNotFound", "unknown query"),
            ("GenericError", "bad QAPI arguments"),
        ] {
            let (mut owner, _event) = cancellation();
            let (supervisor, operation) = original();
            let mut client = fixture_client(&[
                json!({"return":{}}),
                rejection(class, description),
                json!({"return":{}}),
            ]);
            let primary = owner
                .observe(&mut client, 17, 23, &operation)
                .expect_err("refused before handler consumption");
            assert!(owner.requires_native_retirement());
            assert!(client.stream.get_ref().imported.is_some());

            let cleanup = supervisor
                .begin_control(HostOperationClass::Cleanup)
                .expect("same supervisor cleanup");
            owner
                .close_after_failure(&mut client, &cleanup)
                .expect("named descriptor removed");
            assert!(
                matches!(primary, QmpError::Command { class: actual, description: actual_text, .. }
                if actual == class && actual_text == description)
            );
            assert!(!owner.requires_native_retirement());
            assert!(client.stream.get_ref().imported.is_none());
            assert_eq!(client.stream.get_ref().closes, 1);
            assert!(owner.close_after_failure(&mut client, &cleanup).is_err());
            assert_eq!(client.stream.get_ref().closes, 1);
            assert!(operation.wait_slice().is_ok());
        }
    }

    #[test]
    fn accepted_handler_success_has_no_redundant_close_and_is_single_use() {
        let (mut owner, _event) = cancellation();
        let (_supervisor, operation) = original();
        let mut client = fixture_client(&[
            json!({"return":{}}),
            json!({"return":super::tests::fixture()}),
        ]);
        client.stream.get_mut().consume_on_query = true;
        let response = owner
            .observe(&mut client, 17, 23, &operation)
            .expect("interval");
        assert_eq!(response.generation, 17);
        assert!(!owner.requires_native_retirement());
        assert!(client.stream.get_ref().imported.is_none());
        assert_eq!(client.stream.get_ref().closes, 0);
        assert!(owner.observe(&mut client, 17, 23, &operation).is_err());
        assert_eq!(
            (
                client.stream.get_ref().imports,
                client.stream.get_ref().queries
            ),
            (1, 1)
        );
        assert!(operation.wait_slice().is_ok());
    }

    #[test]
    fn unknown_import_ack_requires_retirement_without_query_or_close() {
        let (mut owner, _event) = cancellation();
        let (supervisor, operation) = original();
        let mut client = fixture_client(&[]);
        let primary = owner
            .observe(&mut client, 17, 23, &operation)
            .expect_err("lost getfd ack");
        assert!(matches!(
            primary,
            QmpError::Io {
                kind: ErrorKind::UnexpectedEof,
                ..
            }
        ));
        assert!(client.poisoned);
        assert!(owner.requires_native_retirement());
        assert!(client.stream.get_ref().imported.is_some());
        let cleanup = supervisor
            .begin_control(HostOperationClass::Cleanup)
            .expect("cleanup");
        assert!(matches!(
            owner.close_after_failure(&mut client, &cleanup),
            Err(QmpError::ConnectionPoisoned)
        ));
        assert_eq!(
            (
                client.stream.get_ref().queries,
                client.stream.get_ref().closes
            ),
            (0, 0)
        );
        // Only the fixture's explicit physical descriptor teardown closes it.
        drop(client.stream.get_mut().imported.take());
        assert!(owner.requires_native_retirement());
    }

    #[test]
    fn lost_query_and_close_ack_keep_imported_custody() {
        for responses in [
            vec![json!({"return":{}})],
            vec![
                json!({"return":{}}),
                rejection("CommandNotFound", "unknown query"),
            ],
        ] {
            let (mut owner, _event) = cancellation();
            let (supervisor, operation) = original();
            let mut client = fixture_client(&responses);
            client.stream.get_mut().close_succeeds = false;
            let primary = owner
                .observe(&mut client, 17, 23, &operation)
                .expect_err("query failure");
            let cleanup = supervisor
                .begin_control(HostOperationClass::Cleanup)
                .expect("cleanup");
            let secondary = owner
                .close_after_failure(&mut client, &cleanup)
                .expect_err("uncertain close");
            assert!(matches!(
                primary,
                QmpError::Command { .. } | QmpError::Io { .. }
            ));
            assert!(matches!(
                secondary,
                QmpError::ConnectionPoisoned | QmpError::Io { .. }
            ));
            assert!(owner.requires_native_retirement());
            assert!(client.stream.get_ref().imported.is_some());
            assert!(client.poisoned);
            let before = client.stream.get_ref().closes;
            assert!(owner.close_after_failure(&mut client, &cleanup).is_err());
            assert_eq!(client.stream.get_ref().closes, before);
        }
    }

    #[test]
    fn missing_fd_rejection_cannot_prove_native_retirement() {
        let (mut owner, _event) = cancellation();
        let (supervisor, operation) = original();
        let mut client = fixture_client(&[
            json!({"return":{}}),
            rejection("GenericError", "native mapping refusal"),
            rejection("GenericError", "FD not found"),
        ]);
        client.stream.get_mut().consume_on_query = true;
        let primary = owner
            .observe(&mut client, 17, 23, &operation)
            .expect_err("handler refusal");
        let cleanup = supervisor
            .begin_control(HostOperationClass::Cleanup)
            .expect("cleanup");
        let secondary = owner
            .close_after_failure(&mut client, &cleanup)
            .expect_err("missing fd");
        assert!(
            matches!(primary, QmpError::Command { description, .. } if description == "native mapping refusal")
        );
        assert!(
            matches!(secondary, QmpError::Command { description, .. } if description == "FD not found")
        );
        assert!(client.stream.get_ref().imported.is_none());
        assert!(owner.requires_native_retirement());
        assert_eq!(client.stream.get_ref().closes, 1);
        assert!(owner.close_after_failure(&mut client, &cleanup).is_err());
        assert_eq!(client.stream.get_ref().closes, 1);
    }

    #[test]
    fn canceled_original_has_zero_descriptor_effects() {
        let (mut owner, _event) = cancellation();
        let (supervisor, operation) = original();
        let mut client = fixture_client(&[]);
        let (unrelated, unrelated_operation) = original();
        client.set_host_operation_supervisor(unrelated);
        supervisor.cancel().expect("cancel original");
        assert!(matches!(
            owner.observe(&mut client, 17, 23, &operation),
            Err(QmpError::OperationalSupervision { .. })
        ));
        assert!(!owner.requires_native_retirement());
        assert_eq!(
            (
                client.stream.get_ref().imports,
                client.stream.get_ref().queries,
                client.stream.get_ref().closes
            ),
            (0, 0, 0)
        );
        assert!(!client.poisoned);
        assert_eq!(
            unrelated_operation
                .status()
                .expect("unrelated live")
                .completed_work_units,
            0
        );
    }

    #[test]
    fn completed_cleanup_cannot_reopen_original_or_issue_close_bytes() {
        let (mut owner, _event) = cancellation();
        let (supervisor, operation) = original();
        let mut client = fixture_client(&[
            json!({"return":{}}),
            rejection("CommandNotFound", "primary refusal"),
        ]);
        let (unrelated, unrelated_operation) = original();
        client.set_host_operation_supervisor(unrelated);
        let primary = owner
            .observe(&mut client, 17, 23, &operation)
            .expect_err("primary");
        let cleanup = supervisor
            .begin_control(HostOperationClass::Cleanup)
            .expect("cleanup");
        cleanup
            .complete()
            .expect("close original cleanup operation");
        assert!(matches!(
            owner.close_after_failure(&mut client, &cleanup),
            Err(QmpError::OperationalSupervision { .. })
        ));
        assert!(
            matches!(primary, QmpError::Command { description, .. } if description == "primary refusal")
        );
        assert_eq!(client.stream.get_ref().closes, 0);
        assert!(client.stream.get_ref().imported.is_some());
        assert!(owner.requires_native_retirement());
        assert_eq!(
            unrelated_operation
                .status()
                .expect("unrelated live")
                .completed_work_units,
            0
        );
    }

    #[test]
    fn imported_descriptor_observes_same_original_cancellation_event() {
        let (mut owner, event) = cancellation();
        let (_supervisor, operation) = original();
        let mut client = fixture_client(&[
            json!({"return":{}}),
            rejection("CommandNotFound", "pending handler"),
        ]);
        assert!(owner.observe(&mut client, 17, 23, &operation).is_err());
        let mut writer = std::fs::File::from(event);
        writer
            .write_all(&41_u64.to_ne_bytes())
            .expect("signal original event");
        let imported = client
            .stream
            .get_ref()
            .imported
            .as_ref()
            .expect("retained import")
            .try_clone()
            .expect("sample same event");
        let mut reader = std::fs::File::from(imported);
        let mut bytes = [0_u8; 8];
        reader.read_exact(&mut bytes).expect("same counter");
        assert_eq!(u64::from_ne_bytes(bytes), 41);
        assert!(owner.requires_native_retirement());
    }

    #[test]
    fn query_unwind_keeps_published_owner_and_import_reachable() {
        let (mut owner, _event) = cancellation();
        let (_supervisor, operation) = original();
        let mut client = fixture_client(&[json!({"return":{}})]);
        client.stream.get_mut().panic_on_query = true;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.observe(&mut client, 17, 23, &operation)
        }));
        assert!(result.is_err());
        assert!(owner.requires_native_retirement());
        assert!(client.stream.get_ref().imported.is_some());
        assert_eq!(
            (
                client.stream.get_ref().imports,
                client.stream.get_ref().queries
            ),
            (1, 1)
        );
    }

    #[test]
    fn admission_adapter_uses_the_same_client_and_observed_pause_generation() {
        use crate::node::QemuQmpMachineControlChannel;

        let (mut owner, _event) = cancellation();
        let (_supervisor, operation) = original();
        let mut client = fixture_client(&[
            json!({"return":{
                "schema-version":1,"scope":1,"generation":17,"vcpu-index":0,
                "pc":1048592,"absolute-icount":123456,
            }}),
            json!({"return":{}}),
            json!({"return":admission_fixture()}),
        ]);
        client.stream.get_mut().consume_on_query = true;
        let vmstate = crate::QemuQmpVmStateControlChannel::new(client);
        let mut adapter = crate::node_factory::QemuQmpExactSnapshotControlChannel::new(vmstate);

        let paused = adapter
            .query_paused_cpu(0, None)
            .expect("existing parsed CPU observation");
        let identity = adapter
            .discover_kernel_swap_admission(&mut owner, paused.generation, &operation)
            .expect("same existing client admission");

        assert_eq!(identity.generation, paused.generation);
        assert_eq!(identity.topology_generation, 23);
        assert_eq!(owner.phase, CancellationPhase::Closed);
        assert!(operation.wait_slice().is_ok());
        assert!(
            adapter
                .discover_kernel_swap_admission(&mut owner, paused.generation, &operation)
                .is_err()
        );
        assert!(
            adapter
                .observe_kernel_swap_residency(&mut owner, 17, 23, &operation)
                .is_err()
        );
        eprintln!(
            "cancellation name len={} capacity={}",
            owner.name.0.len(),
            owner.name.0.capacity()
        );
    }

    #[test]
    fn admission_adapter_keeps_typed_primary_through_independent_cleanup() {
        use crate::node::QemuQmpMachineControlChannel;

        let (mut owner, _event) = cancellation();
        let (supervisor, operation) = original();
        let client = fixture_client(&[
            json!({"return":{}}),
            rejection("CommandNotFound", "admission command absent"),
            json!({"return":{}}),
        ]);
        let vmstate = crate::QemuQmpVmStateControlChannel::new(client);
        let mut adapter = crate::node_factory::QemuQmpExactSnapshotControlChannel::new(vmstate);

        let primary = adapter
            .discover_kernel_swap_admission(&mut owner, 17, &operation)
            .expect_err("actual dispatch refusal");
        assert!(owner.requires_native_retirement());
        let cleanup = supervisor
            .begin_control(HostOperationClass::Cleanup)
            .expect("same original cleanup");
        let secondary = adapter.close_kernel_swap_cancellation(&mut owner, &cleanup);

        assert!(matches!(primary, QmpError::Command {
            command: QmpCommandKind::QueryKernelSwapAdmission,
            ref class,
            ref description,
        } if class == "CommandNotFound" && description == "admission command absent"));
        assert!(secondary.is_ok());
        assert_eq!(owner.phase, CancellationPhase::Closed);
        assert!(operation.wait_slice().is_ok());
    }

    #[test]
    fn admission_adapter_refuses_closed_original_despite_ambient_authority() {
        use crate::node::QemuQmpMachineControlChannel;

        let (mut owner, _event) = cancellation();
        let (supervisor, operation) = original();
        let (ambient, _ambient_operation) = original();
        let mut client = fixture_client(&[]);
        client.set_host_operation_supervisor(ambient);
        let vmstate = crate::QemuQmpVmStateControlChannel::new(client);
        let mut adapter = crate::node_factory::QemuQmpExactSnapshotControlChannel::new(vmstate);
        supervisor.cancel().expect("cancel actual original");

        let result = adapter.discover_kernel_swap_admission(&mut owner, 17, &operation);

        assert!(matches!(
            result,
            Err(QmpError::OperationalSupervision { .. })
        ));
        assert_eq!(owner.phase, CancellationPhase::Prepared);
        assert!(!owner.requires_native_retirement());
    }

    #[test]
    fn actual_node_adapter_lends_its_existing_client_to_owner() {
        use crate::node::QemuQmpMachineControlChannel;

        let (mut owner, _event) = cancellation();
        let (_supervisor, operation) = original();
        let mut client = fixture_client(&[
            json!({"return":{}}),
            json!({"return":super::tests::fixture()}),
        ]);
        client.stream.get_mut().consume_on_query = true;
        let vmstate = crate::QemuQmpVmStateControlChannel::new(client);
        let mut adapter = crate::node_factory::QemuQmpExactSnapshotControlChannel::new(vmstate);

        let report = adapter
            .observe_kernel_swap_residency(&mut owner, 17, 23, &operation)
            .expect("same existing connection interval");

        assert_eq!((report.generation, report.topology_generation), (17, 23));
        assert_eq!(owner.phase, CancellationPhase::Closed);
        assert!(!owner.requires_native_retirement());
        assert!(operation.wait_slice().is_ok());
        assert!(
            adapter
                .observe_kernel_swap_residency(&mut owner, 17, 23, &operation)
                .is_err()
        );
    }

    #[test]
    fn actual_node_adapter_preserves_primary_and_separate_cleanup() {
        use crate::node::QemuQmpMachineControlChannel;

        let (mut owner, _event) = cancellation();
        let (supervisor, operation) = original();
        let client = fixture_client(&[
            json!({"return":{}}),
            rejection("CommandNotFound", "identity not installed"),
            json!({"return":{}}),
        ]);
        let vmstate = crate::QemuQmpVmStateControlChannel::new(client);
        let mut adapter = crate::node_factory::QemuQmpExactSnapshotControlChannel::new(vmstate);

        let primary = adapter
            .observe_kernel_swap_residency(&mut owner, 17, 23, &operation)
            .expect_err("actual dispatch refusal");
        assert!(owner.requires_native_retirement());
        let cleanup = supervisor
            .begin_control(HostOperationClass::Cleanup)
            .expect("same original component cleanup");
        let secondary = adapter.close_kernel_swap_cancellation(&mut owner, &cleanup);

        assert!(
            matches!(primary, QmpError::Command { class, description, .. }
            if class == "CommandNotFound" && description == "identity not installed")
        );
        assert!(secondary.is_ok());
        assert_eq!(owner.phase, CancellationPhase::Closed);
        assert!(operation.wait_slice().is_ok());
        assert!(
            adapter
                .close_kernel_swap_cancellation(&mut owner, &cleanup)
                .is_err()
        );
    }

    #[test]
    fn actual_node_adapter_does_not_replace_closed_original_with_ambient() {
        use crate::node::QemuQmpMachineControlChannel;

        let (mut owner, _event) = cancellation();
        let (supervisor, operation) = original();
        let (ambient, _ambient_operation) = original();
        let mut client = fixture_client(&[]);
        client.set_host_operation_supervisor(ambient);
        let vmstate = crate::QemuQmpVmStateControlChannel::new(client);
        let mut adapter = crate::node_factory::QemuQmpExactSnapshotControlChannel::new(vmstate);
        supervisor.cancel().expect("cancel same original");

        let result = adapter.observe_kernel_swap_residency(&mut owner, 17, 23, &operation);

        assert!(matches!(
            result,
            Err(QmpError::OperationalSupervision { .. })
        ));
        assert_eq!(owner.phase, CancellationPhase::Prepared);
        assert!(!owner.requires_native_retirement());
    }

    #[test]
    fn actual_host_layouts_are_recorded_without_admission_claim() {
        eprintln!(
            "KernelSwapResidency size={} align={} Cancellation size={} align={} Phase size={}",
            std::mem::size_of::<QmpKernelSwapResidency>(),
            std::mem::align_of::<QmpKernelSwapResidency>(),
            std::mem::size_of::<QmpKernelSwapCancellation>(),
            std::mem::align_of::<QmpKernelSwapCancellation>(),
            std::mem::size_of::<CancellationPhase>()
        );
        assert_eq!(std::mem::size_of::<QmpKernelSwapResidency>(), 72);
        assert_eq!(std::mem::align_of::<QmpKernelSwapResidency>(), 8);
    }
}
