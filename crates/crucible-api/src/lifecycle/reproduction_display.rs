//! Borrowed canonical command reproduction material with no owned nested scratch.

use super::session_contract::{breakpoint_policy_material, log_level_material};
use super::*;
use std::fmt::{self, Display, Write};

struct Render<F>(F);

impl<F: Fn(&mut dyn Write) -> fmt::Result> Display for Render<F> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        (self.0)(output)
    }
}

struct HexText<T>(T);

impl<T: Display> Display for HexText<T> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Encoder<'a>(&'a mut dyn Write);
        impl Write for Encoder<'_> {
            fn write_str(&mut self, value: &str) -> fmt::Result {
                for byte in value.bytes() {
                    write!(self.0, "{byte:02x}")?;
                }
                Ok(())
            }
        }
        write!(&mut Encoder(output), "{}", self.0)
    }
}

pub(super) fn payload_display(payload: &SessionControlPayload) -> impl Display + '_ {
    Render(move |output: &mut dyn Write| match payload {
        SessionControlPayload::CommandKind { command } => {
            write!(output, "payload=command-kind\ncommand={command:?}\n")
        }
        SessionControlPayload::Fork { from } => {
            write!(output, "payload=fork\nfrom={}\n", checkpoint_display(*from))
        }
        SessionControlPayload::SetBreakpoint { spec } => write!(
            output,
            "payload=set-breakpoint\npredicate={}\ndisposition={}\npolicy={}\n",
            HexText(spec.predicate.canonical_display()),
            disposition_display(&spec.disposition),
            breakpoint_policy_material(spec.policy),
        ),
        SessionControlPayload::RemoveBreakpoint { id } => {
            write!(output, "payload=remove-breakpoint\nid={id}\n")
        }
        SessionControlPayload::CreateSavepoint { label } => {
            write!(
                output,
                "payload=create-savepoint\nlabel={}\n",
                HexText(label)
            )
        }
    })
}

pub(super) fn control_display(control: &ControlOperationKind) -> &'static str {
    match control {
        ControlOperationKind::Pause => "control=pause\n",
        ControlOperationKind::Resume => "control=resume\n",
        ControlOperationKind::Step => "control=step\n",
        ControlOperationKind::Snapshot => "control=snapshot\n",
        ControlOperationKind::Fork => "control=fork\n",
        ControlOperationKind::Query => "control=query\n",
    }
}

fn checkpoint_display(from: CheckpointRef) -> impl Display {
    Render(move |output: &mut dyn Write| match from {
        CheckpointRef::Current => output.write_str("current"),
        CheckpointRef::Checkpoint(hash) => {
            output.write_str("checkpoint:")?;
            for byte in hash.bytes {
                write!(output, "{byte:02x}")?;
            }
            Ok(())
        }
    })
}

fn disposition_display(disposition: &BreakpointDisposition) -> impl Display + '_ {
    Render(move |output: &mut dyn Write| match disposition {
        BreakpointDisposition::Suspend => output.write_str("suspend"),
        BreakpointDisposition::Trace => output.write_str("trace"),
        BreakpointDisposition::Action(action) => {
            write!(output, "action:{}", HexText(action_display(action)))
        }
    })
}

fn optional_label(label: Option<&str>) -> impl Display + '_ {
    Render(move |output: &mut dyn Write| match label {
        Some(label) => write!(output, "{}", HexText(label)),
        None => output.write_str("none"),
    })
}

fn action_display(action: &Action) -> impl Display + '_ {
    Render(move |output: &mut dyn Write| match action {
        Action::ArmTimer { name, after } => write!(
            output,
            "action=arm-timer\nname={}\nafter-ticks={}\n",
            HexText(&name.name),
            after.ticks,
        ),
        Action::CancelTimer { name } => {
            write!(
                output,
                "action=cancel-timer\nname={}\n",
                HexText(&name.name)
            )
        }
        Action::StartNode { node } => {
            write!(output, "action=start-node\nnode={}\n", HexText(&node.name))
        }
        Action::StopNode { node } => {
            write!(output, "action=stop-node\nnode={}\n", HexText(&node.name))
        }
        Action::CreateSavepoint { label } => write!(
            output,
            "action=create-savepoint\nlabel={}\n",
            optional_label(label.as_deref()),
        ),
        Action::Fork { label } => write!(
            output,
            "action=fork\nlabel={}\n",
            optional_label(label.as_deref()),
        ),
        Action::Pass => output.write_str("action=pass\n"),
        Action::Fail { reason } => {
            write!(output, "action=fail\nreason={}\n", HexText(reason))
        }
        Action::Log { level, message } => write!(
            output,
            "action=log\nlevel={}\nmessage={}\n",
            log_level_material(*level),
            HexText(message),
        ),
        Action::Group(actions) => {
            write!(output, "action=group\ncount={}\n", actions.len())?;
            for (index, action) in actions.iter().enumerate() {
                writeln!(output, "member.{index}={}", HexText(action_display(action)))?;
            }
            Ok(())
        }
    })
}
