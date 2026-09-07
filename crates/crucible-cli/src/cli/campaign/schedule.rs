//! Strict offline authoring for canonical Schedule V2 bodies.

use super::*;

use crucible::{
    ChoiceTag, Decision, DeliveryOrderDecision, EventKey, Icount, IrqVector, NodeId,
    OverrideDecision, PreemptionDecision, PreemptionKind, RngDecision, RngStreamId, Schedule,
    SchedulerNodeId, SchedulingNodeKind, SchedulingPoint, VcpuId, VirtualTime,
};
use crucible_daemon::MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES;
use serde::{Deserialize, Serialize};

use super::authoring::{read_bounded_utf8, write_new_record};

const CAMPAIGN_SCHEDULE_AUTHORING_SCHEMA_VERSION: u32 = 1;
const CAMPAIGN_SCHEDULE_COMPILATION_REPORT_SCHEMA: &str =
    "crucible.cli.campaign-schedule-compilation.v1";
const MAX_CAMPAIGN_SCHEDULE_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
const MAX_AUTHORED_SCHEDULE_DECISIONS: usize = 65_536;
const MAX_AUTHORED_DELIVERY_EVENTS: usize = 65_536;
const MAX_AUTHORED_SCHEDULE_TEXT_BYTES: usize = 4_096;

/// Result of compiling one strict authored decision list.
#[derive(Debug, Serialize)]
pub(super) struct CampaignScheduleCompilationReport {
    schema: &'static str,
    input: String,
    output: String,
    schedule: String,
    decisions: usize,
    encoded_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredCampaignSchedule {
    schema_version: u32,
    decisions: Vec<AuthoredDecision>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum AuthoredDecision {
    DeliveryOrder {
        at_ticks: u64,
        order: Vec<AuthoredEventKey>,
    },
    RngDraw {
        stream_domain: String,
        stream_name: String,
        value: u64,
    },
    Override {
        point: String,
        choice: String,
    },
    Preemption {
        node: String,
        retired: u64,
        action: AuthoredPreemptionAction,
        from_vcpu: Option<u32>,
        to_vcpu: Option<u32>,
        target_vcpu: Option<u32>,
        irq: Option<u32>,
    },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthoredPreemptionAction {
    VcpuSwitch,
    InterruptAt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredEventKey {
    virtual_time_ticks: u64,
    consumer: AuthoredSchedulerNode,
    producer: AuthoredSchedulerNode,
    sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredSchedulerNode {
    node: String,
    kind: AuthoredSchedulingNodeKind,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthoredSchedulingNodeKind {
    Vm,
    Disk,
    NineP,
    Network,
    ControlPlane,
}

pub(super) fn compile_campaign_schedule(
    input: &Path,
    output: &Path,
) -> Result<CampaignScheduleCompilationReport, CliError> {
    let text = read_bounded_utf8(
        input,
        "campaign schedule manifest",
        MAX_CAMPAIGN_SCHEDULE_MANIFEST_BYTES,
    )?;
    let authored: AuthoredCampaignSchedule = toml::from_str(&text).map_err(|error| {
        usage_error(format!(
            "invalid campaign schedule manifest at {}: {error}",
            input.display()
        ))
    })?;
    let schedule = authored.into_schedule()?;
    let bytes = schedule.to_compact_binary();
    if bytes.len() > MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES {
        return Err(usage_error(format!(
            "compiled schedule contains {} bytes; campaign import limit is {MAX_CRUCIBLE_CAMPAIGN_IMPORT_FILE_BYTES}",
            bytes.len()
        )));
    }
    let decoded = Schedule::from_compact_binary(&bytes)
        .map_err(|error| usage_error(format!("compiled campaign schedule is invalid: {error}")))?;
    if decoded != schedule || decoded.to_compact_binary() != bytes {
        return Err(backend_error(
            "compiled campaign schedule did not round-trip canonically",
        ));
    }

    write_new_record(output, "campaign schedule", &bytes)?;
    Ok(CampaignScheduleCompilationReport {
        schema: CAMPAIGN_SCHEDULE_COMPILATION_REPORT_SCHEMA,
        input: input.display().to_string(),
        output: output.display().to_string(),
        schedule: schedule.content_hash().to_hex(),
        decisions: schedule.len(),
        encoded_bytes: bytes.len(),
    })
}

pub(super) fn render_campaign_schedule_compilation(
    report: &CampaignScheduleCompilationReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report).map_err(|error| {
            backend_error(format!("campaign schedule JSON encoding failed: {error}"))
        }),
        OutputFormat::Json => serde_json::to_string_pretty(report).map_err(|error| {
            backend_error(format!("campaign schedule JSON encoding failed: {error}"))
        }),
        OutputFormat::Table => Ok([
            format!("{:<16} {}", "schedule", report.schedule),
            format!("{:<16} {}", "decisions", report.decisions),
            format!("{:<16} {}", "encoded_bytes", report.encoded_bytes),
            format!("{:<16} {}", "output", report.output),
        ]
        .join("\n")),
        OutputFormat::Markdown => Ok(format!(
            "| Field | Value |\n| --- | --- |\n| schedule | {} |\n| decisions | {} |\n| encoded bytes | {} |\n| output | {} |",
            report.schedule, report.decisions, report.encoded_bytes, report.output
        )),
    }
}

impl AuthoredCampaignSchedule {
    fn into_schedule(self) -> Result<Schedule, CliError> {
        if self.schema_version != CAMPAIGN_SCHEDULE_AUTHORING_SCHEMA_VERSION {
            return Err(usage_error(format!(
                "unsupported campaign schedule manifest schema version {}; expected {}",
                self.schema_version, CAMPAIGN_SCHEDULE_AUTHORING_SCHEMA_VERSION
            )));
        }
        if self.decisions.is_empty() || self.decisions.len() > MAX_AUTHORED_SCHEDULE_DECISIONS {
            return Err(usage_error(format!(
                "campaign schedule must contain 1..={MAX_AUTHORED_SCHEDULE_DECISIONS} decisions"
            )));
        }
        self.decisions
            .into_iter()
            .map(AuthoredDecision::into_decision)
            .collect::<Result<Vec<_>, _>>()
            .map(Schedule::from_decisions)
    }
}

impl AuthoredDecision {
    fn into_decision(self) -> Result<Decision, CliError> {
        match self {
            Self::DeliveryOrder { at_ticks, order } => {
                if order.is_empty() || order.len() > MAX_AUTHORED_DELIVERY_EVENTS {
                    return Err(usage_error(format!(
                        "delivery order must contain 1..={MAX_AUTHORED_DELIVERY_EVENTS} events"
                    )));
                }
                Ok(Decision::DeliveryOrder(DeliveryOrderDecision {
                    at: VirtualTime { ticks: at_ticks },
                    order: order
                        .into_iter()
                        .map(AuthoredEventKey::into_event)
                        .collect::<Result<_, _>>()?,
                }))
            }
            Self::RngDraw {
                stream_domain,
                stream_name,
                value,
            } => {
                validate_text("RNG stream domain", &stream_domain)?;
                validate_text("RNG stream name", &stream_name)?;
                Ok(Decision::RngDraw(RngDecision {
                    stream: RngStreamId::new(stream_domain, stream_name),
                    value,
                }))
            }
            Self::Override { point, choice } => {
                validate_text("override scheduling point", &point)?;
                validate_text("override choice", &choice)?;
                Ok(Decision::Override(OverrideDecision {
                    point: SchedulingPoint { key: point },
                    choice: ChoiceTag { name: choice },
                }))
            }
            Self::Preemption {
                node,
                retired,
                action,
                from_vcpu,
                to_vcpu,
                target_vcpu,
                irq,
            } => {
                validate_text("preemption node", &node)?;
                Ok(Decision::Preemption(PreemptionDecision {
                    node: NodeId { name: node },
                    at: Icount { retired },
                    kind: action.into_kind(from_vcpu, to_vcpu, target_vcpu, irq)?,
                }))
            }
        }
    }
}

impl AuthoredPreemptionAction {
    fn into_kind(
        self,
        from_vcpu: Option<u32>,
        to_vcpu: Option<u32>,
        target_vcpu: Option<u32>,
        irq: Option<u32>,
    ) -> Result<PreemptionKind, CliError> {
        match self {
            Self::VcpuSwitch => match (from_vcpu, to_vcpu, target_vcpu, irq) {
                (Some(from_vcpu), Some(to_vcpu), None, None) => Ok(PreemptionKind::VcpuSwitch {
                    from_vcpu: VcpuId { index: from_vcpu },
                    to_vcpu: VcpuId { index: to_vcpu },
                }),
                _ => Err(usage_error(
                    "vcpu-switch preemption requires only from_vcpu and to_vcpu",
                )),
            },
            Self::InterruptAt => match (from_vcpu, to_vcpu, target_vcpu, irq) {
                (None, None, Some(target_vcpu), Some(irq)) => Ok(PreemptionKind::InterruptAt {
                    target_vcpu: VcpuId { index: target_vcpu },
                    irq: IrqVector { vector: irq },
                }),
                _ => Err(usage_error(
                    "interrupt-at preemption requires only target_vcpu and irq",
                )),
            },
        }
    }
}

impl AuthoredEventKey {
    fn into_event(self) -> Result<EventKey, CliError> {
        Ok(EventKey::new(
            VirtualTime {
                ticks: self.virtual_time_ticks,
            },
            self.consumer.into_node()?,
            self.producer.into_node()?,
            self.sequence,
        ))
    }
}

impl AuthoredSchedulerNode {
    fn into_node(self) -> Result<SchedulerNodeId, CliError> {
        validate_text("scheduler node", &self.node)?;
        Ok(SchedulerNodeId {
            node: NodeId { name: self.node },
            kind: self.kind.into_kind(),
        })
    }
}

impl AuthoredSchedulingNodeKind {
    const fn into_kind(self) -> SchedulingNodeKind {
        match self {
            Self::Vm => SchedulingNodeKind::Vm,
            Self::Disk => SchedulingNodeKind::Disk,
            Self::NineP => SchedulingNodeKind::NineP,
            Self::Network => SchedulingNodeKind::Network,
            Self::ControlPlane => SchedulingNodeKind::ControlPlane,
        }
    }
}

fn validate_text(field: &str, value: &str) -> Result<(), CliError> {
    if value.is_empty()
        || value.len() > MAX_AUTHORED_SCHEDULE_TEXT_BYTES
        || value
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r'))
    {
        return Err(usage_error(format!(
            "{field} must contain 1..={MAX_AUTHORED_SCHEDULE_TEXT_BYTES} bytes without NUL or line breaks"
        )));
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- authoring tests use exact panic localization.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    use tempfile::tempdir;

    fn manifest() -> &'static str {
        r#"schema_version = 1

[[decisions]]
kind = "delivery-order"
at_ticks = 10

[[decisions.order]]
virtual_time_ticks = 10
consumer = { node = "node-b", kind = "vm" }
producer = { node = "node-a", kind = "network" }
sequence = 7

[[decisions]]
kind = "rng-draw"
stream_domain = "crucible.test.schedule"
stream_name = "loss"
value = 42

[[decisions]]
kind = "override"
point = "scheduler.network.delivery"
choice = "drop"

[[decisions]]
kind = "preemption"
node = "node-a"
retired = 1000
action = "vcpu-switch"
from_vcpu = 0
to_vcpu = 1

[[decisions]]
kind = "preemption"
node = "node-b"
retired = 2000
action = "interrupt-at"
target_vcpu = 0
irq = 32
"#
    }

    #[test]
    fn authored_decisions_compile_to_canonical_schedule_v2() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("decisions.toml");
        let output = temporary.path().join("schedule.bin");
        std::fs::write(&input, manifest()).expect("write schedule manifest");

        let report = compile_campaign_schedule(&input, &output).expect("compile schedule");
        let bytes = std::fs::read(&output).expect("read schedule");
        let schedule = Schedule::from_compact_binary(&bytes).expect("decode schedule");

        assert_eq!(report.decisions, 5);
        assert_eq!(report.encoded_bytes, bytes.len());
        assert_eq!(report.schedule, schedule.content_hash().to_hex());
        assert_eq!(schedule.to_compact_binary(), bytes);
        assert!(matches!(
            schedule.decisions()[0],
            Decision::DeliveryOrder(_)
        ));
        assert!(matches!(schedule.decisions()[1], Decision::RngDraw(_)));
        assert!(matches!(schedule.decisions()[2], Decision::Override(_)));
        assert!(matches!(
            schedule.decisions()[3],
            Decision::Preemption(PreemptionDecision {
                kind: PreemptionKind::VcpuSwitch { .. },
                ..
            })
        ));
        assert!(matches!(
            schedule.decisions()[4],
            Decision::Preemption(PreemptionDecision {
                kind: PreemptionKind::InterruptAt { .. },
                ..
            })
        ));
    }

    #[test]
    fn invalid_or_legacy_decisions_create_no_schedule() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("decisions.toml");
        let output = temporary.path().join("schedule.bin");
        for invalid in [
            "schema_version = 1\ndecisions = []\n",
            "schema_version = 1\n[[decisions]]\nkind = \"app-random\"\n",
            "schema_version = 1\n[[decisions]]\nkind = \"selection\"\n",
            "schema_version = 1\n[[decisions]]\nkind = \"delivery-order\"\nat_ticks = 1\norder = []\n",
            "schema_version = 1\nunknown = true\n[[decisions]]\nkind = \"override\"\npoint = \"p\"\nchoice = \"c\"\n",
            "schema_version = 1\n[[decisions]]\nkind = \"preemption\"\nnode = \"n\"\nretired = 1\naction = \"vcpu-switch\"\nfrom_vcpu = 0\n",
            "schema_version = 1\n[[decisions]]\nkind = \"preemption\"\nnode = \"n\"\nretired = 1\naction = \"vcpu-switch\"\nfrom_vcpu = 0\nto_vcpu = 1\nirq = 32\n",
            "schema_version = 1\n[[decisions]]\nkind = \"preemption\"\nnode = \"n\"\nretired = 1\naction = \"interrupt-at\"\ntarget_vcpu = 0\n",
            "schema_version = 1\n[[decisions]]\nkind = \"preemption\"\nnode = \"n\"\nretired = 1\naction = \"interrupt-at\"\ntarget_vcpu = 0\nirq = 32\nfrom_vcpu = 0\n",
        ] {
            std::fs::write(&input, invalid).expect("write invalid manifest");
            assert!(compile_campaign_schedule(&input, &output).is_err());
            assert!(!output.exists());
        }
    }

    #[test]
    fn existing_schedule_is_never_replaced() {
        let temporary = tempdir().expect("temporary directory");
        let input = temporary.path().join("decisions.toml");
        let output = temporary.path().join("schedule.bin");
        std::fs::write(&input, manifest()).expect("write schedule manifest");
        std::fs::write(&output, b"existing").expect("write existing output");

        assert!(compile_campaign_schedule(&input, &output).is_err());
        assert_eq!(std::fs::read(&output).expect("read existing"), b"existing");
    }

    #[test]
    fn authored_decision_and_delivery_bounds_are_exact() {
        let too_many_decisions = std::iter::repeat_with(|| AuthoredDecision::Override {
            point: "p".to_owned(),
            choice: "c".to_owned(),
        })
        .take(MAX_AUTHORED_SCHEDULE_DECISIONS + 1)
        .collect();
        assert!(
            AuthoredCampaignSchedule {
                schema_version: CAMPAIGN_SCHEDULE_AUTHORING_SCHEMA_VERSION,
                decisions: too_many_decisions,
            }
            .into_schedule()
            .is_err()
        );

        let too_many_events = std::iter::repeat_with(|| AuthoredEventKey {
            virtual_time_ticks: 1,
            consumer: AuthoredSchedulerNode {
                node: "consumer".to_owned(),
                kind: AuthoredSchedulingNodeKind::Vm,
            },
            producer: AuthoredSchedulerNode {
                node: "producer".to_owned(),
                kind: AuthoredSchedulingNodeKind::Network,
            },
            sequence: 1,
        })
        .take(MAX_AUTHORED_DELIVERY_EVENTS + 1)
        .collect();
        assert!(
            AuthoredDecision::DeliveryOrder {
                at_ticks: 1,
                order: too_many_events,
            }
            .into_decision()
            .is_err()
        );
    }
}
