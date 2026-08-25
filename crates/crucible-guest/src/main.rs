//! Command-line entry point for the optional guest marker and selectable client.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::process::ExitCode;

use crucible_guest::guest_introspection_agent::{
    GuestIntrospectionAgentConfig, run_guest_introspection_agent,
};
use crucible_guest::{
    AlternativeId, ChoiceDomain, ChoiceValue, DiscreteAlternative, DiscreteDomain, ExactRational,
    GuestCommandOutcome, GuestEmitterError, InstructionDoorbellTransport, IntegerDomain,
    IntegerRepresentation, IntegerValue, SelectableRegister, SelectionRequest,
    build_selectable_registration, emit_command, emit_selectable_registration, parse_cli_args,
    request_typed_selection, usage,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crucible-guest: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os()
        .skip(1)
        .map(utf8_arg)
        .collect::<Result<Vec<_>, _>>()?;
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{}", usage());
        return Ok(());
    }

    if args.first().is_some_and(|arg| arg == "agent") {
        args.remove(0);
        let config = parse_agent_config(&args)?;
        let mut transport = InstructionDoorbellTransport::native()?;
        return run_guest_introspection_agent(config, &mut transport)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error>);
    }

    if args.first().is_some_and(|arg| arg == "selectable") {
        args.remove(0);
        let command = parse_selectable_command(&args)?;
        let mut transport = InstructionDoorbellTransport::native()?;
        match command {
            SelectableCliCommand::Register(registration) => {
                emit_selectable_registration(&registration, &mut transport)?;
            }
            SelectableCliCommand::Choose { request, domain } => {
                let selected = request_typed_selection(&request, &domain, &mut transport)?;
                println!("{}", display_choice_value(selected.value()));
            }
        }
        return Ok(());
    }

    let command = parse_cli_args(args.iter().map(String::as_str))?;
    let mut transport = InstructionDoorbellTransport::native()?;
    match emit_command(&command, &mut transport)? {
        GuestCommandOutcome::Marker { .. } => Ok(()),
        GuestCommandOutcome::Random { reply, .. } => {
            println!("{}", hex_lower(&reply));
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SelectableCliCommand {
    Register(SelectableRegister),
    Choose {
        request: SelectionRequest,
        domain: ChoiceDomain,
    },
}

fn parse_selectable_command(args: &[String]) -> Result<SelectableCliCommand, GuestEmitterError> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(usage_error("selectable requires a subcommand"));
    };
    match verb.as_str() {
        "register-discrete" => parse_register_discrete(rest),
        "register-u64" => parse_register_u64(rest),
        "choose-discrete" => parse_choose_discrete(rest),
        "choose-u64" => parse_choose_u64(rest),
        _ => Err(usage_error(format!(
            "unknown selectable subcommand `{verb}`"
        ))),
    }
}

fn parse_register_discrete(args: &[String]) -> Result<SelectableCliCommand, GuestEmitterError> {
    if args.len() < 4 {
        return Err(usage_error(
            "selectable register-discrete requires <sequence> <id> <default-id> <alternative-id>=<label>...",
        ));
    }
    let sequence = parse_u64("sequence", &args[0])?;
    let default = parse_alternative_id("default-id", &args[2])?;
    let mut alternatives = BTreeMap::new();
    for item in &args[3..] {
        let Some((id, label)) = item.split_once('=') else {
            return Err(usage_error(format!(
                "discrete alternative `{item}` must use <alternative-id>=<label>"
            )));
        };
        let id = parse_alternative_id("alternative-id", id)?;
        let alternative = DiscreteAlternative::new(id, label, None)
            .map_err(|error| usage_error(format!("invalid discrete alternative: {error}")))?;
        if alternatives.insert(id, alternative).is_some() {
            return Err(usage_error("discrete alternative IDs must be unique"));
        }
    }
    let domain = ChoiceDomain::Discrete(
        DiscreteDomain::new(1, alternatives)
            .map_err(|error| usage_error(format!("invalid discrete domain: {error}")))?,
    );
    let registration = build_selectable_registration(
        sequence,
        args[1].clone(),
        &domain,
        &ChoiceValue::Discrete(default),
        Vec::new(),
    )
    .map_err(|error| usage_error(format!("invalid selectable registration: {error}")))?;
    Ok(SelectableCliCommand::Register(registration))
}

fn parse_register_u64(args: &[String]) -> Result<SelectableCliCommand, GuestEmitterError> {
    if args.len() != 7 {
        return Err(usage_error(
            "selectable register-u64 requires <sequence> <id> <minimum> <maximum> <step> <default> <unit|->",
        ));
    }
    let sequence = parse_u64("sequence", &args[0])?;
    let minimum = parse_u64("minimum", &args[2])?;
    let maximum = parse_u64("maximum", &args[3])?;
    let step = parse_u64("step", &args[4])?;
    let default = parse_u64("default", &args[5])?;
    let domain = unsigned_domain(minimum, maximum, step, unit(&args[6]))?;
    let registration = build_selectable_registration(
        sequence,
        args[1].clone(),
        &domain,
        &ChoiceValue::Integer(IntegerValue::Unsigned(default)),
        Vec::new(),
    )
    .map_err(|error| usage_error(format!("invalid selectable registration: {error}")))?;
    Ok(SelectableCliCommand::Register(registration))
}

fn parse_choose_discrete(args: &[String]) -> Result<SelectableCliCommand, GuestEmitterError> {
    if args.len() < 4 {
        return Err(usage_error(
            "selectable choose-discrete requires <sequence> <id> <instance> <alternative-id>...",
        ));
    }
    let sequence = parse_u64("sequence", &args[0])?;
    let mut alternatives = BTreeMap::new();
    for value in &args[3..] {
        let id = parse_alternative_id("alternative-id", value)?;
        let alternative = DiscreteAlternative::new(id, id.to_hex(), None)
            .map_err(|error| usage_error(format!("invalid discrete alternative: {error}")))?;
        if alternatives.insert(id, alternative).is_some() {
            return Err(usage_error("discrete alternative IDs must be unique"));
        }
    }
    let domain = ChoiceDomain::Discrete(
        DiscreteDomain::new(1, alternatives)
            .map_err(|error| usage_error(format!("invalid discrete domain: {error}")))?,
    );
    choose_request(sequence, &args[1], &args[2], domain)
}

fn parse_choose_u64(args: &[String]) -> Result<SelectableCliCommand, GuestEmitterError> {
    if args.len() != 6 {
        return Err(usage_error(
            "selectable choose-u64 requires <sequence> <id> <instance> <minimum> <maximum> <step>",
        ));
    }
    let sequence = parse_u64("sequence", &args[0])?;
    let domain = unsigned_domain(
        parse_u64("minimum", &args[3])?,
        parse_u64("maximum", &args[4])?,
        parse_u64("step", &args[5])?,
        None,
    )?;
    choose_request(sequence, &args[1], &args[2], domain)
}

fn choose_request(
    sequence: u64,
    selectable_id: &str,
    instance: &str,
    domain: ChoiceDomain,
) -> Result<SelectableCliCommand, GuestEmitterError> {
    let request = SelectionRequest::new(sequence, selectable_id, instance, None, 512)
        .map_err(|error| usage_error(format!("invalid selection request: {error}")))?;
    Ok(SelectableCliCommand::Choose { request, domain })
}

fn unsigned_domain(
    minimum: u64,
    maximum: u64,
    step: u64,
    unit: Option<String>,
) -> Result<ChoiceDomain, GuestEmitterError> {
    let scale = ExactRational::new(1, 1)
        .map_err(|error| usage_error(format!("invalid integer scale: {error}")))?;
    IntegerDomain::new(
        1,
        IntegerRepresentation::Unsigned64,
        IntegerValue::Unsigned(minimum),
        IntegerValue::Unsigned(maximum),
        step,
        unit,
        scale,
        Vec::new(),
    )
    .map(ChoiceDomain::Integer)
    .map_err(|error| usage_error(format!("invalid unsigned integer domain: {error}")))
}

fn parse_alternative_id(field: &str, value: &str) -> Result<AlternativeId, GuestEmitterError> {
    AlternativeId::parse(value).map_err(|error| usage_error(format!("invalid {field}: {error}")))
}

fn parse_u64(field: &str, value: &str) -> Result<u64, GuestEmitterError> {
    value
        .parse::<u64>()
        .map_err(|_error| usage_error(format!("{field} must be an unsigned 64-bit integer")))
}

fn unit(value: &str) -> Option<String> {
    (value != "-").then(|| value.to_owned())
}

fn display_choice_value(value: &ChoiceValue) -> String {
    match value {
        ChoiceValue::Boolean(value) => format!("boolean={value}"),
        ChoiceValue::Discrete(value) => format!("discrete={}", value.to_hex()),
        ChoiceValue::Integer(IntegerValue::Signed(value)) => format!("i64={value}"),
        ChoiceValue::Integer(IntegerValue::Unsigned(value)) => format!("u64={value}"),
    }
}

fn parse_agent_config(args: &[String]) -> Result<GuestIntrospectionAgentConfig, GuestEmitterError> {
    let mut max_channels =
        crucible_guest::guest_introspection_agent::GUEST_INTROSPECTION_DEFAULT_MAX_CHANNELS;
    let mut ssh_argv: Option<Vec<String>> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--max-channels" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| usage_error("agent --max-channels requires an integer"))?;
                max_channels = value.parse::<u16>().map_err(|_error| {
                    usage_error("agent --max-channels must be an integer in 1..=64")
                })?;
                index += 2;
            }
            "--ssh-program" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| usage_error("agent --ssh-program requires a guest path"))?;
                ssh_argv = Some(vec![value.clone()]);
                index += 2;
            }
            "--ssh-arg" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| usage_error("agent --ssh-arg requires a value"))?;
                ssh_argv
                    .as_mut()
                    .ok_or_else(|| usage_error("agent --ssh-arg requires --ssh-program first"))?
                    .push(value.clone());
                index += 2;
            }
            option => return Err(usage_error(format!("unknown agent option `{option}`"))),
        }
    }
    GuestIntrospectionAgentConfig::new(max_channels, ssh_argv).map_err(usage_error)
}

fn usage_error(message: impl ToString) -> GuestEmitterError {
    GuestEmitterError::Usage {
        message: format!("{}\n\n{}", message.to_string(), usage()),
    }
}

fn utf8_arg(arg: OsString) -> Result<String, GuestEmitterError> {
    arg.into_string().map_err(|_arg| GuestEmitterError::Usage {
        message: String::from("crucible-guest arguments must be valid UTF-8"),
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SAFE: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    fn must<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| panic!("test fixture construction failed: {error}"))
    }

    #[test]
    fn selectable_cli_builds_typed_discrete_and_integer_registrations() {
        let discrete = must(parse_selectable_command(&[
            String::from("register-discrete"),
            String::from("1"),
            String::from("network.recovery-policy"),
            String::from(SAFE),
            format!("{FAST}=fast"),
            format!("{SAFE}=safe"),
        ]));
        let SelectableCliCommand::Register(discrete) = discrete else {
            panic!("expected registration");
        };
        let domain = must(ChoiceDomain::from_canonical_bytes(discrete.domain()));
        assert!(domain.contains(&ChoiceValue::Discrete(must(AlternativeId::parse(SAFE)))));

        let integer = must(parse_selectable_command(&[
            String::from("register-u64"),
            String::from("2"),
            String::from("network.retry-quanta"),
            String::from("1"),
            String::from("9"),
            String::from("2"),
            String::from("3"),
            String::from("quanta"),
        ]));
        let SelectableCliCommand::Register(integer) = integer else {
            panic!("expected registration");
        };
        let domain = must(ChoiceDomain::from_canonical_bytes(integer.domain()));
        assert!(domain.contains(&ChoiceValue::Integer(IntegerValue::Unsigned(7))));
    }

    #[test]
    fn selectable_cli_builds_bounded_typed_requests_and_display_values() {
        let command = must(parse_selectable_command(&[
            String::from("choose-discrete"),
            String::from("3"),
            String::from("network.recovery-policy"),
            String::from("routing/7"),
            String::from(FAST),
            String::from(SAFE),
        ]));
        let SelectableCliCommand::Choose { request, domain } = command else {
            panic!("expected request");
        };
        assert_eq!(request.reply_capacity(), 512);
        assert!(domain.contains(&ChoiceValue::Discrete(must(AlternativeId::parse(FAST)))));
        assert_eq!(
            display_choice_value(&ChoiceValue::Integer(IntegerValue::Unsigned(7))),
            "u64=7"
        );
    }

    #[test]
    fn selectable_cli_rejects_duplicate_or_illegal_values() {
        assert!(
            parse_selectable_command(&[
                String::from("register-discrete"),
                String::from("1"),
                String::from("network.recovery-policy"),
                String::from(SAFE),
                format!("{FAST}=fast"),
                format!("{FAST}=duplicate"),
            ])
            .is_err()
        );
        assert!(
            parse_selectable_command(&[
                String::from("register-u64"),
                String::from("2"),
                String::from("network.retry-quanta"),
                String::from("1"),
                String::from("9"),
                String::from("2"),
                String::from("4"),
                String::from("quanta"),
            ])
            .is_err()
        );
    }
}
