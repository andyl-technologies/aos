//! Baseline Crucible instrumentation for the native AOS ability executor.
//!
//! This crate owns the optional AOS side of RFC-0022's guest integration. It
//! consumes the production executor's protected boundary-observer protocol and
//! translates validated observations into existing generic [`crucible_guest`]
//! lifecycle, event, coverage, and assertion markers. It introduces no choice,
//! measurement, campaign, QEMU, or shared-memory protocol.
//!
//! The package-owned adapter configuration is canonical JSON. Service readiness
//! is established by a second invocation that waits for the protected socket;
//! the adapter does not implement a service-manager notification protocol.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use aos_ability_model::{OperationId, TransactionId};
use aos_contract::Sha256Digest;
use crucible_guest::{
    DoorbellTransport, GuestCommand, InstructionDoorbellTransport,
    WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION, WhiteboxMarkerDetail, emit_command,
};
use serde::{Deserialize, Serialize};

const CONFIG_SCHEMA: &str = "aos.ability-crucible-adapter/v1";
const EVENT_SCHEMA: &str = "aos.ability-execution-boundary-event/v1";
const ACK_SCHEMA: &str = "aos.ability-execution-boundary-ack/v1";
const EVENT_DIGEST_DOMAIN: &str = "aos.ability-execution-boundary-event/v1";
const FRAME_MAX_BYTES: usize = 16 * 1024;
const CONFIG_MAX_BYTES: u64 = 4 * 1024;
const MAX_ACTIVE_MONITORS: usize = 1024;
const READY_WAIT_INTERVAL: Duration = Duration::from_millis(10);
const REQUIRED_MARKER_KINDS: [&str; 4] = ["assertion", "coverage", "event", "lifecycle"];

/// Runs the baseline adapter with command-line arguments after the binary name.
///
/// Accepted forms are `--config PATH` and `--wait-ready SOCKET`.
///
/// # Errors
///
/// Returns an error when arguments, protected configuration, generic marker
/// compatibility, socket setup, event framing, or marker delivery fail.
pub fn run_from_args<I>(args: I) -> Result<()>
where
    I: IntoIterator<Item = OsString>,
{
    match parse_args(args)? {
        CommandMode::Serve(config_path) => {
            let config = AdapterConfig::load(&config_path)?;
            let transport = InstructionDoorbellTransport::native()
                .context("selecting the Crucible guest doorbell transport")?;
            let emitter = DoorbellEmitter { transport };

            Adapter::new(config, emitter).serve()
        }
        CommandMode::WaitReady(socket) => wait_until_ready(&socket),
    }
}

#[derive(Debug, Eq, PartialEq)]
enum CommandMode {
    Serve(PathBuf),
    WaitReady(PathBuf),
}

fn parse_args<I>(args: I) -> Result<CommandMode>
where
    I: IntoIterator<Item = OsString>,
{
    let words = args.into_iter().collect::<Vec<_>>();
    match words.as_slice() {
        [flag, path] if flag == "--config" => Ok(CommandMode::Serve(PathBuf::from(path))),
        [flag, path] if flag == "--wait-ready" => {
            Ok(CommandMode::WaitReady(PathBuf::from(path)))
        }
        _ => bail!("usage: aos-ability-crucible (--config PATH | --wait-ready SOCKET)"),
    }
}

fn wait_until_ready(socket: &Path) -> Result<()> {
    loop {
        match UnixStream::connect(socket) {
            Ok(_) => return Ok(()),
            Err(_) => {
                thread::sleep(READY_WAIT_INTERVAL);
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdapterConfig {
    schema: String,
    socket: PathBuf,
    required_instruction_abi: u16,
    required_marker_kinds: Vec<String>,
}

impl AdapterConfig {
    fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspecting adapter configuration {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file() || metadata.file_type().is_symlink(),
            "adapter configuration is not a regular file or immutable store link"
        );
        let bytes = fs::read(path)
            .with_context(|| format!("reading adapter configuration {}", path.display()))?;
        ensure!(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= CONFIG_MAX_BYTES,
            "adapter configuration exceeds its byte limit"
        );
        let config: Self =
            aos_contract::canonical::from_slice(&bytes, "ability Crucible adapter configuration")
                .context("decoding adapter configuration")?;
        ensure!(
            aos_contract::canonical::to_vec(&config)? == bytes,
            "adapter configuration is not canonical"
        );
        config.validate()?;

        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.schema == CONFIG_SCHEMA, "unsupported adapter schema");
        ensure!(
            self.required_instruction_abi == WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
            "required Crucible guest instruction ABI is unavailable"
        );
        ensure!(
            self.required_marker_kinds == REQUIRED_MARKER_KINDS.map(str::to_owned),
            "required Crucible baseline marker declarations are unavailable"
        );
        let socket_text = self
            .socket
            .to_str()
            .context("adapter socket path is not UTF-8")?;
        ensure!(
            is_canonical_absolute(socket_text),
            "adapter socket path is not canonical"
        );
        Ok(())
    }
}

fn is_canonical_absolute(path: &str) -> bool {
    path.starts_with('/')
        && path != "/"
        && !path.ends_with('/')
        && !path.contains("//")
        && !path.split('/').any(|part| matches!(part, "." | ".."))
}

trait MarkerEmitter {
    fn emit(&mut self, command: &GuestCommand) -> Result<()>;
}

struct DoorbellEmitter<Transport> {
    transport: Transport,
}

impl<Transport> MarkerEmitter for DoorbellEmitter<Transport>
where
    Transport: DoorbellTransport,
{
    fn emit(&mut self, command: &GuestCommand) -> Result<()> {
        emit_command(command, &mut self.transport)
            .context("emitting a generic Crucible guest marker")?;
        Ok(())
    }
}

struct Adapter<Emitter> {
    config: AdapterConfig,
    emitter: Emitter,
    monitors: BTreeMap<MonitorKey, MonitorState>,
}

impl<Emitter> Adapter<Emitter>
where
    Emitter: MarkerEmitter,
{
    fn new(config: AdapterConfig, emitter: Emitter) -> Self {
        Self {
            config,
            emitter,
            monitors: BTreeMap::new(),
        }
    }

    fn serve(mut self) -> Result<()> {
        ensure!(
            !self.config.socket.exists(),
            "adapter socket already exists at {}",
            self.config.socket.display()
        );
        let listener = UnixListener::bind(&self.config.socket)
            .with_context(|| format!("binding adapter socket {}", self.config.socket.display()))?;
        fs::set_permissions(&self.config.socket, fs::Permissions::from_mode(0o600))
            .context("protecting adapter socket")?;

        // Setup is declared only after config compatibility and the protected
        // listener both exist. Marker delivery itself proves the baseline path.
        self.announce_ready()?;

        loop {
            let (mut stream, _) = listener.accept().context("accepting executor observer")?;
            validate_peer(&stream)?;
            self.serve_connection(&mut stream)?;
        }
    }

    fn announce_ready(&mut self) -> Result<()> {
        self.emitter.emit(&GuestCommand::setup_complete())
    }

    fn serve_connection(&mut self, stream: &mut UnixStream) -> Result<()> {
        while let Some(bytes) = read_frame(stream)? {
            let event: BoundaryEvent =
                aos_contract::canonical::from_slice(&bytes, "ability execution boundary event")
                    .context("decoding executor boundary event")?;
            ensure!(
                aos_contract::canonical::to_vec(&event)? == bytes,
                "executor boundary event is not canonical"
            );

            self.process_event(&event)?;
            let acknowledgement = BoundaryAcknowledgement {
                action: "continue",
                event_digest: Sha256Digest::separated(EVENT_DIGEST_DOMAIN, &bytes),
                schema: ACK_SCHEMA,
            };
            let acknowledgement = aos_contract::canonical::to_vec(&acknowledgement)?;
            write_frame(stream, &acknowledgement)?;
        }

        Ok(())
    }

    fn process_event(&mut self, event: &BoundaryEvent) -> Result<()> {
        event.validate()?;
        let transition = event.boundary.transition();
        let key = event.monitor_key()?;
        let prior = self.monitors.get(&key).copied();
        let ordered = prior == transition.expected;
        let details = event.marker_details()?;
        let order_assertion = GuestCommand::always(
            "aos.execution-boundary.ordered",
            "executor boundary follows intent, return, durable outcome order",
            ordered,
        )
        .with_assertion_details(details.clone())
        .context("attaching exact execution-boundary assertion details")?;
        self.emitter.emit(&order_assertion)?;
        ensure!(ordered, "executor boundary order is invalid");

        self.emitter.emit(&GuestCommand::event(
            "aos.ability.execution-boundary",
            details,
        ))?;
        self.emitter.emit(&GuestCommand::coverage(format!(
            "aos.ability.boundary.{}",
            event.boundary.as_str()
        )))?;
        self.emitter.emit(&GuestCommand::reachable(
            format!("aos.ability.boundary.{}", event.boundary.as_str()),
            "production executor reached the declared durable boundary",
        ))?;

        if transition.next.is_terminal() {
            self.monitors.remove(&key);
        } else {
            ensure!(
                self.monitors.contains_key(&key) || self.monitors.len() < MAX_ACTIVE_MONITORS,
                "active boundary monitor limit exceeded"
            );
            self.monitors.insert(key, transition.next);
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn validate_peer(stream: &UnixStream) -> Result<()> {
    let credentials = rustix::net::sockopt::socket_peercred(stream)
        .context("reading executor observer peer credentials")?;
    ensure!(
        credentials.uid.as_raw() == 0,
        "executor observer peer is not UID 0"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_peer(_stream: &UnixStream) -> Result<()> {
    bail!("ability Crucible adapter requires peer credentials")
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundaryEvent {
    schema: String,
    transaction: TransactionId,
    operation: OperationId,
    attempt: u32,
    purpose: String,
    boundary: BoundaryName,
    cancelled: bool,
    attempt_remaining_millis: u64,
    recovery_remaining_millis: u64,
}

impl BoundaryEvent {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == EVENT_SCHEMA,
            "unsupported boundary event schema"
        );
        ensure!(self.attempt > 0, "boundary event attempt must be nonzero");
        ensure!(
            matches!(
                self.purpose.as_str(),
                "effect" | "reconcile" | "cancel" | "compensate" | "reconcile-compensation"
            ),
            "boundary event purpose is unsupported"
        );
        ensure!(!self.cancelled, "cancelled boundary event cannot continue");
        ensure!(
            self.attempt_remaining_millis > 0 && self.recovery_remaining_millis > 0,
            "boundary event has no live execution budget"
        );
        ensure!(
            self.boundary.accepts_purpose(&self.purpose),
            "boundary event purpose does not match its boundary family"
        );
        Ok(())
    }

    fn monitor_key(&self) -> Result<MonitorKey> {
        Ok(MonitorKey {
            transaction: aos_contract::canonical::to_vec(&self.transaction)?,
            operation: aos_contract::canonical::to_vec(&self.operation)?,
            attempt: self.attempt,
            family: self.boundary.family(),
        })
    }

    fn marker_details(&self) -> Result<Vec<WhiteboxMarkerDetail>> {
        let event_bytes = aos_contract::canonical::to_vec(self)?;
        let event_digest = Sha256Digest::separated(EVENT_DIGEST_DOMAIN, &event_bytes);
        let transaction = String::from_utf8(aos_contract::canonical::to_vec(&self.transaction)?)
            .context("encoding marker transaction identity")?;
        let operation = String::from_utf8(aos_contract::canonical::to_vec(&self.operation)?)
            .context("encoding marker operation identity")?;
        Ok(vec![
            WhiteboxMarkerDetail::new("transaction", transaction),
            WhiteboxMarkerDetail::new("operation", operation),
            WhiteboxMarkerDetail::new("attempt", self.attempt.to_string()),
            WhiteboxMarkerDetail::new("purpose", &self.purpose),
            WhiteboxMarkerDetail::new("boundary", self.boundary.as_str()),
            WhiteboxMarkerDetail::new("cancelled", self.cancelled.to_string()),
            WhiteboxMarkerDetail::new(
                "attempt_remaining_millis",
                self.attempt_remaining_millis.to_string(),
            ),
            WhiteboxMarkerDetail::new(
                "recovery_remaining_millis",
                self.recovery_remaining_millis.to_string(),
            ),
            WhiteboxMarkerDetail::new("event_digest", event_digest.to_string()),
        ])
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BoundaryName {
    EffectIntentDurable,
    EffectReturned,
    EffectOutcomeDurable,
    ReconciliationIntentDurable,
    ReconciliationReturned,
    ReconciliationOutcomeDurable,
    CancellationIntentDurable,
    CancellationReturned,
    CancellationOutcomeDurable,
}

impl BoundaryName {
    const fn as_str(self) -> &'static str {
        match self {
            Self::EffectIntentDurable => "effect-intent-durable",
            Self::EffectReturned => "effect-returned",
            Self::EffectOutcomeDurable => "effect-outcome-durable",
            Self::ReconciliationIntentDurable => "reconciliation-intent-durable",
            Self::ReconciliationReturned => "reconciliation-returned",
            Self::ReconciliationOutcomeDurable => "reconciliation-outcome-durable",
            Self::CancellationIntentDurable => "cancellation-intent-durable",
            Self::CancellationReturned => "cancellation-returned",
            Self::CancellationOutcomeDurable => "cancellation-outcome-durable",
        }
    }

    const fn family(self) -> BoundaryFamily {
        match self {
            Self::EffectIntentDurable | Self::EffectReturned | Self::EffectOutcomeDurable => {
                BoundaryFamily::Effect
            }
            Self::ReconciliationIntentDurable
            | Self::ReconciliationReturned
            | Self::ReconciliationOutcomeDurable => BoundaryFamily::Reconciliation,
            Self::CancellationIntentDurable
            | Self::CancellationReturned
            | Self::CancellationOutcomeDurable => BoundaryFamily::Cancellation,
        }
    }

    fn accepts_purpose(self, purpose: &str) -> bool {
        match self.family() {
            BoundaryFamily::Effect => matches!(purpose, "effect" | "compensate"),
            BoundaryFamily::Reconciliation => {
                matches!(purpose, "reconcile" | "reconcile-compensation")
            }
            BoundaryFamily::Cancellation => purpose == "cancel",
        }
    }

    const fn transition(self) -> MonitorTransition {
        match self {
            Self::EffectIntentDurable
            | Self::ReconciliationIntentDurable
            | Self::CancellationIntentDurable => MonitorTransition {
                expected: None,
                next: MonitorState::Intent,
            },
            Self::EffectReturned | Self::ReconciliationReturned | Self::CancellationReturned => {
                MonitorTransition {
                    expected: Some(MonitorState::Intent),
                    next: MonitorState::Returned,
                }
            }
            Self::EffectOutcomeDurable
            | Self::ReconciliationOutcomeDurable
            | Self::CancellationOutcomeDurable => MonitorTransition {
                expected: Some(MonitorState::Returned),
                next: MonitorState::Terminal,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum BoundaryFamily {
    Effect,
    Reconciliation,
    Cancellation,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct MonitorKey {
    transaction: Vec<u8>,
    operation: Vec<u8>,
    attempt: u32,
    family: BoundaryFamily,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MonitorState {
    Intent,
    Returned,
    Terminal,
}

impl MonitorState {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal)
    }
}

struct MonitorTransition {
    expected: Option<MonitorState>,
    next: MonitorState,
}

#[derive(Serialize)]
struct BoundaryAcknowledgement {
    action: &'static str,
    event_digest: Sha256Digest,
    schema: &'static str,
}

fn read_frame(stream: &mut UnixStream) -> Result<Option<Vec<u8>>> {
    let mut encoded_length = [0_u8; 4];
    let first = stream
        .read(&mut encoded_length[..1])
        .context("reading executor frame length")?;
    if first == 0 {
        return Ok(None);
    }
    stream
        .read_exact(&mut encoded_length[1..])
        .context("reading complete executor frame length")?;
    let length = usize::try_from(u32::from_be_bytes(encoded_length))
        .context("decoding executor frame length")?;
    ensure!(
        length <= FRAME_MAX_BYTES,
        "executor frame exceeds its byte limit"
    );
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .context("reading executor frame payload")?;
    Ok(Some(bytes))
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).context("encoding acknowledgement frame length")?;
    stream
        .write_all(&length.to_be_bytes())
        .context("writing acknowledgement frame length")?;
    stream
        .write_all(bytes)
        .context("writing acknowledgement frame payload")
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use aos_ability_model::{LocalKey, PlanId, ScopePath, ScopedOperationKey};
    use aos_contract::Sha256Digest;
    use crucible_guest::{WhiteboxAssertionMarkerFlavor, WhiteboxMarkerPayload};

    use super::*;

    #[derive(Default)]
    struct CapturingEmitter {
        commands: Vec<GuestCommand>,
    }

    struct FailingEmitter;

    impl MarkerEmitter for FailingEmitter {
        fn emit(&mut self, _command: &GuestCommand) -> Result<()> {
            bail!("marker protocol unavailable")
        }
    }

    impl MarkerEmitter for CapturingEmitter {
        fn emit(&mut self, command: &GuestCommand) -> Result<()> {
            self.commands.push(command.clone());
            Ok(())
        }
    }

    fn config(socket: PathBuf) -> AdapterConfig {
        AdapterConfig {
            schema: CONFIG_SCHEMA.to_owned(),
            socket,
            required_instruction_abi: WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
            required_marker_kinds: REQUIRED_MARKER_KINDS.map(str::to_owned).to_vec(),
        }
    }

    fn operation() -> OperationId {
        OperationId {
            plan: PlanId(Sha256Digest::of_bytes(b"plan")),
            operation: ScopedOperationKey {
                scope: ScopePath::root(),
                key: LocalKey::new("publish").unwrap(),
            },
        }
    }

    fn event(boundary: BoundaryName) -> BoundaryEvent {
        BoundaryEvent {
            schema: EVENT_SCHEMA.to_owned(),
            transaction: TransactionId(LocalKey::new("transaction").unwrap()),
            operation: operation(),
            attempt: 1,
            purpose: "effect".to_owned(),
            boundary,
            cancelled: false,
            attempt_remaining_millis: 1_000,
            recovery_remaining_millis: 2_000,
        }
    }

    #[test]
    fn configuration_path_is_explicit() {
        assert!(parse_args(Vec::<OsString>::new()).is_err());
        assert_eq!(
            parse_args([
                OsString::from("--config"),
                OsString::from("/run/aos/config.json")
            ])
                .unwrap(),
            CommandMode::Serve(PathBuf::from("/run/aos/config.json"))
        );
        assert_eq!(
            parse_args([
                OsString::from("--wait-ready"),
                OsString::from("/run/aos/controller.sock"),
            ])
            .unwrap(),
            CommandMode::WaitReady(PathBuf::from("/run/aos/controller.sock"))
        );
    }

    #[test]
    fn readiness_waits_for_the_package_socket_without_manager_protocols() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("controller.sock");
        let server_socket = socket.clone();
        let server = thread::spawn(move || -> std::io::Result<()> {
            thread::sleep(Duration::from_millis(30));
            let listener = UnixListener::bind(server_socket)?;
            listener.accept()?;
            Ok(())
        });

        wait_until_ready(&socket)?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("readiness test server panicked"))??;
        Ok(())
    }

    #[test]
    fn required_baseline_declarations_fail_closed() {
        let mut missing = config(PathBuf::from("/run/aos-instrumentation/controller.sock"));
        missing.required_marker_kinds.pop();
        assert!(missing.validate().is_err());

        let mut future = config(PathBuf::from("/run/aos-instrumentation/controller.sock"));
        future.required_instruction_abi += 1;
        assert!(future.validate().is_err());
    }

    #[test]
    fn valid_boundary_chain_emits_generic_assertions_events_and_coverage() -> Result<()> {
        let emitter = CapturingEmitter::default();
        let mut adapter = Adapter::new(
            config(PathBuf::from("/run/aos-instrumentation/controller.sock")),
            emitter,
        );
        adapter.process_event(&event(BoundaryName::EffectIntentDurable))?;
        adapter.process_event(&event(BoundaryName::EffectReturned))?;
        adapter.process_event(&event(BoundaryName::EffectOutcomeDurable))?;

        assert_eq!(adapter.emitter.commands.len(), 12);
        assert!(adapter.monitors.is_empty());
        assert!(adapter.emitter.commands.iter().any(|command| matches!(
            command.payload(),
            WhiteboxMarkerPayload::Assertion(assertion)
                if assertion.flavor == WhiteboxAssertionMarkerFlavor::Always
                    && assertion.condition
        )));
        assert!(
            adapter
                .emitter
                .commands
                .iter()
                .any(|command| matches!(command.payload(), WhiteboxMarkerPayload::Event(_)))
        );
        assert!(
            adapter
                .emitter
                .commands
                .iter()
                .any(|command| matches!(command.payload(), WhiteboxMarkerPayload::Coverage(_)))
        );
        Ok(())
    }

    #[test]
    fn returned_without_intent_emits_false_assertion_and_withholds_progress() {
        let emitter = CapturingEmitter::default();
        let mut adapter = Adapter::new(
            config(PathBuf::from("/run/aos-instrumentation/controller.sock")),
            emitter,
        );
        assert!(
            adapter
                .process_event(&event(BoundaryName::EffectReturned))
                .is_err()
        );
        assert_eq!(adapter.emitter.commands.len(), 1);
        assert!(matches!(
            adapter.emitter.commands[0].payload(),
            WhiteboxMarkerPayload::Assertion(assertion)
                if assertion.flavor == WhiteboxAssertionMarkerFlavor::Always
                    && !assertion.condition
        ));
    }

    #[test]
    fn canonical_event_receives_digest_bound_ack_after_marker_delivery() -> Result<()> {
        let emitter = CapturingEmitter::default();
        let mut adapter = Adapter::new(
            config(PathBuf::from("/run/aos-instrumentation/controller.sock")),
            emitter,
        );
        let (mut client, mut server) = UnixStream::pair()?;
        let event_bytes =
            aos_contract::canonical::to_vec(&event(BoundaryName::EffectIntentDurable))?;
        write_frame(&mut client, &event_bytes)?;
        client.shutdown(std::net::Shutdown::Write)?;

        adapter.serve_connection(&mut server)?;
        let ack = read_frame(&mut client)?.context("missing acknowledgement")?;
        let expected = BoundaryAcknowledgement {
            action: "continue",
            event_digest: Sha256Digest::separated(EVENT_DIGEST_DOMAIN, &event_bytes),
            schema: ACK_SCHEMA,
        };
        assert_eq!(ack, aos_contract::canonical::to_vec(&expected)?);
        assert_eq!(adapter.emitter.commands.len(), 4);
        Ok(())
    }

    #[test]
    fn emitted_violation_reaches_host_verdict_and_reproduces() -> Result<()> {
        use crucible::{
            AssertionViolationArtifactReplay, Icount, NodeId, NodeTemplate, Plan, Properties,
            ReadyPoint, RecordedAssertionLog, ReproductionArtifact, ScenarioDefForm, Schedule,
            Seed, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
            check_assertion_violation_reproduction, observable_event_from_whitebox_marker_payload,
        };

        let emitter = CapturingEmitter::default();
        let mut adapter = Adapter::new(
            config(PathBuf::from("/run/aos-instrumentation/controller.sock")),
            emitter,
        );
        assert!(
            adapter
                .process_event(&event(BoundaryName::EffectReturned))
                .is_err()
        );
        let false_assertion = adapter.emitter.commands[0].payload();

        let node = NodeId {
            name: "aos-guest".to_owned(),
        };
        let world = World::from_nodes(vec![WorldNode {
            id: node.clone(),
            arch: VmArchitecture::X86_64,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 1 },
            },
            white_box: WhiteBoxPolicy::Enabled,
            smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
            icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
            kernel: None,
            root_image: None,
            initrd: None,
        }])?;
        let mapped = observable_event_from_whitebox_marker_payload(
            Icount { retired: 7 },
            node,
            false_assertion,
        )
        .context("adapter assertion did not map into a host observation")?;
        let entries = vec![
            crucible::test_support::condition_observation_entry_for_test(0, &mapped),
            crucible::test_support::condition_boundary_entry_for_test(
                1,
                VirtualTime { ticks: 7 },
                crucible::SchedulerEvaluationBoundaryKind::Quantum,
            ),
        ];
        let recorded = RecordedAssertionLog::from_segments(vec![entries])?;
        let scenario = ScenarioDefForm::from_components(
            &world,
            &Plan::empty(),
            &Properties::empty(),
            Seed::from_u64(22),
        )?;
        let artifact = ReproductionArtifact::capture(&scenario, &Schedule::empty())?;
        let replayed =
            AssertionViolationArtifactReplay::from_artifact(&artifact, recorded.clone())?;

        let report = check_assertion_violation_reproduction(&artifact, &recorded, &replayed)?;
        assert_eq!(report.expected, report.reproduced);
        assert_eq!(report.reproduced.violations().len(), 1);
        assert_eq!(
            report.reproduced.violations()[0].assertion.name,
            "aos.execution-boundary.ordered"
        );
        assert_eq!(report.replay.artifact, artifact.id());
        Ok(())
    }

    #[test]
    fn marker_transport_failure_prevents_readiness() {
        let mut adapter = Adapter::new(
            config(PathBuf::from("/run/aos-instrumentation/controller.sock")),
            FailingEmitter,
        );

        assert!(adapter.announce_ready().is_err());
    }
}
