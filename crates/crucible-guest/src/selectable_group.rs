//! CLI for one atomic guest group registration or choice request.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use crucible_campaign::{
    AlternativeId, BooleanDomain, ChoiceDomain, ChoiceGroup, ChoiceValue, DiscreteAlternative,
    DiscreteDomain, ExactRational, IntegerDomain, IntegerRepresentation, IntegerValue,
    SelectableId,
};
use crucible_guest::group::{build_group_registration, build_guest_group, request_group_selection};
use crucible_guest::{
    GuestEmitterError, InstructionDoorbellTransport, SelectionRequest, emit_selectable_registration,
};

struct GroupSpec {
    group: ChoiceGroup,
    default: ChoiceValue,
    member_ids: BTreeMap<String, SelectableId>,
}

pub(super) fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let Some((verb, rest)) = args.split_first() else {
        return Err(usage("selectable group requires register-group or choose-group").into());
    };
    let is_request = verb == "choose-group";
    let minimum = if is_request { 7 } else { 6 };
    if rest.len() < minimum {
        return Err(usage(
            "group requires <sequence> <id> [instance] <node> <adapter> <version> <member-spec>...",
        )
        .into());
    }
    let sequence = rest[0]
        .parse::<u64>()
        .map_err(|_error| usage("group sequence must be an unsigned integer"))?;
    let name = &rest[1];
    let (instance, common) = if is_request {
        (Some(rest[2].as_str()), &rest[3..])
    } else {
        (None, &rest[2..])
    };
    let version = common[2]
        .parse::<u32>()
        .map_err(|_error| usage("group application version must be an unsigned integer"))?;
    let spec = parse_group(&common[0], &common[1], version, &common[3..])?;
    let mut transport = InstructionDoorbellTransport::native()?;

    if let Some(instance) = instance {
        let request = SelectionRequest::new(sequence, name, instance, None, 4096)?;
        let selection = request_group_selection(&request, &spec.group, &mut transport)?;
        for (member, id) in &spec.member_ids {
            let value = selection
                .value()
                .tuple()
                .values()
                .get(id)
                .ok_or_else(|| usage("selected group tuple omitted a member"))?;
            println!("{member}={}", display_group_value(value));
        }
    } else {
        let registration = build_group_registration(sequence, name, &spec.group, &spec.default)?;
        emit_selectable_registration(&registration, &mut transport)?;
    }
    Ok(())
}

fn parse_group(
    node: &str,
    adapter: &str,
    version: u32,
    specs: &[String],
) -> Result<GroupSpec, GuestEmitterError> {
    let members = specs
        .iter()
        .map(|spec| parse_member(spec))
        .collect::<Result<Vec<_>, _>>()?;
    let names = members
        .iter()
        .map(|(name, _, _)| name)
        .collect::<std::collections::BTreeSet<_>>();
    if names.len() != members.len() {
        return Err(usage("group member names must be unique"));
    }
    let (group, default, member_ids) =
        build_guest_group(node, adapter, version, members, BTreeSet::new())
            .map_err(|error| usage(format!("invalid group: {error}")))?;
    Ok(GroupSpec {
        group,
        default,
        member_ids,
    })
}

fn parse_member(spec: &str) -> Result<(String, ChoiceDomain, ChoiceValue), GuestEmitterError> {
    let fields = spec.split('@').collect::<Vec<_>>();
    match fields.as_slice() {
        ["bool", name, default] => {
            let default = parse_bool(default)?;
            let domain = BooleanDomain::new(1)
                .map(ChoiceDomain::Boolean)
                .map_err(|error| usage(format!("invalid boolean member: {error}")))?;
            Ok(((*name).to_owned(), domain, ChoiceValue::Boolean(default)))
        }
        ["u64", name, minimum, maximum, step, default, unit] => {
            let minimum = parse_u64("minimum", minimum)?;
            let maximum = parse_u64("maximum", maximum)?;
            let step = parse_u64("step", step)?;
            let default = parse_u64("default", default)?;
            let unit = (*unit != "-").then(|| (*unit).to_owned());
            let scale = ExactRational::new(1, 1)
                .map_err(|error| usage(format!("invalid integer scale: {error}")))?;
            let domain = IntegerDomain::new(
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
            .map_err(|error| usage(format!("invalid integer member: {error}")))?;
            Ok((
                (*name).to_owned(),
                domain,
                ChoiceValue::Integer(IntegerValue::Unsigned(default)),
            ))
        }
        ["discrete", name, default, alternatives] => {
            let default = AlternativeId::parse(default)
                .map_err(|error| usage(format!("invalid discrete default: {error}")))?;
            let mut choices = BTreeMap::new();
            for item in alternatives.split(',') {
                let (id, label) = item
                    .split_once('=')
                    .ok_or_else(|| usage("discrete alternative requires <id>=<label>"))?;
                let id = AlternativeId::parse(id)
                    .map_err(|error| usage(format!("invalid discrete alternative ID: {error}")))?;
                let choice = DiscreteAlternative::new(id, label, None)
                    .map_err(|error| usage(format!("invalid discrete alternative: {error}")))?;
                if choices.insert(id, choice).is_some() {
                    return Err(usage("duplicate discrete alternative ID"));
                }
            }
            let domain = DiscreteDomain::new(1, choices)
                .map(ChoiceDomain::Discrete)
                .map_err(|error| usage(format!("invalid discrete member: {error}")))?;
            Ok(((*name).to_owned(), domain, ChoiceValue::Discrete(default)))
        }
        _ => Err(usage(
            "member spec must be bool@name@default, u64@name@min@max@step@default@unit, or discrete@name@default@id=label,...",
        )),
    }
}

fn display_group_value(value: &ChoiceValue) -> String {
    match value {
        ChoiceValue::Boolean(value) => format!("boolean:{value}"),
        ChoiceValue::Discrete(value) => format!("discrete:{}", value.to_hex()),
        ChoiceValue::Integer(IntegerValue::Signed(value)) => format!("i64:{value}"),
        ChoiceValue::Integer(IntegerValue::Unsigned(value)) => format!("u64:{value}"),
        ChoiceValue::Group(_) => String::from("invalid-nested-group"),
    }
}

fn parse_bool(value: &str) -> Result<bool, GuestEmitterError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(usage("boolean member default must be true or false")),
    }
}

fn parse_u64(field: &str, value: &str) -> Result<u64, GuestEmitterError> {
    value
        .parse()
        .map_err(|_error| usage(format!("{field} must be an unsigned integer")))
}

fn usage(message: impl Into<String>) -> GuestEmitterError {
    GuestEmitterError::Usage {
        message: message.into(),
    }
}
