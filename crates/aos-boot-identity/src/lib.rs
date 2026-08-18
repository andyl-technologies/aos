//! Parses and validates the AOS security-relevant kernel command line.
//!
//! Normal boot and recovery verification share this parser so a tuple that is
//! rejected before dm-verity activation cannot later be accepted by an
//! offline slot verifier. The parser intentionally understands only the
//! security-relevant scalar fields; unrelated repeatable fields such as
//! `console=` remain outside its policy.

use std::error::Error;
use std::fmt;

const ROOT_A: &str = "/dev/disk/by-partlabel/root-a";
const ROOT_B: &str = "/dev/disk/by-partlabel/root-b";
const ROOT_A_HASH: &str = "/dev/disk/by-partlabel/root-a-hash";
const ROOT_B_HASH: &str = "/dev/disk/by-partlabel/root-b-hash";

/// Identifies one immutable AOS root slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootSlot {
    /// The `root-a` and `root-a-hash` partition pair.
    A,
    /// The `root-b` and `root-b-hash` partition pair.
    B,
}

/// Describes the validated identity inputs for a normal boot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalBootIdentity {
    /// The root device passed to the initrd.
    pub root: String,
    /// The selected immutable slot.
    pub slot: BootSlot,
    /// The lowercase hexadecimal dm-verity root hash.
    pub root_hash: String,
}

/// Confirms that the command line selects the dedicated recovery environment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryBootIdentity;

/// Reports why a security-relevant command line is not an AOS normal boot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// A scalar field appeared more than once.
    DuplicateField(&'static str),
    /// A required field was absent.
    MissingField(&'static str),
    /// A field had an empty or unsupported value.
    InvalidField {
        /// Kernel command-line field name.
        field: &'static str,
        /// Rejected value, or `<bare>` for a key without `=`.
        value: String,
    },
    /// The selected data and hash devices identify different slots.
    SlotMismatch,
    /// Normal boot included a recovery or interactive-initrd selector.
    ForbiddenField(&'static str),
    /// Recovery included a token outside its exact signed allowlist.
    UnexpectedField(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateField(field) => write!(formatter, "duplicate scalar field `{field}`"),
            Self::MissingField(field) => write!(formatter, "missing required field `{field}`"),
            Self::InvalidField { field, value } => {
                write!(formatter, "invalid `{field}` value `{value}`")
            }
            Self::SlotMismatch => {
                formatter.write_str("verity data and hash devices select different slots")
            }
            Self::ForbiddenField(field) => {
                write!(
                    formatter,
                    "normal boot forbids command-line field `{field}`"
                )
            }
            Self::UnexpectedField(field) => {
                write!(formatter, "recovery forbids command-line field `{field}`")
            }
        }
    }
}

impl Error for ParseError {}

#[derive(Default)]
struct Fields<'a> {
    root: Option<&'a str>,
    root_hash: Option<&'a str>,
    verity_data: Option<&'a str>,
    verity_hash: Option<&'a str>,
    verity_enabled: Option<&'a str>,
}

/// Parses and validates a normal-boot command line.
///
/// Scalar identity fields must be unique even when repeated with the same
/// value. A normal boot must use `/dev/mapper/root`, a canonical lowercase
/// 256-bit hexadecimal root hash, and a matching A/A-hash or B/B-hash
/// partition pair. Recovery and systemd's command-line control surfaces are
/// never accepted in normal mode.
///
/// # Errors
///
/// Returns [`ParseError`] for missing, duplicated, malformed, mismatched, or
/// forbidden security-relevant fields.
pub fn parse_normal(cmdline: &str) -> Result<NormalBootIdentity, ParseError> {
    let mut fields = Fields::default();

    for token in cmdline.split_ascii_whitespace() {
        let (key, value) = match token.split_once('=') {
            Some((key, value)) => (key, value),
            None => (token, "<bare>"),
        };

        if is_forbidden_normal_key(key) {
            return Err(ParseError::ForbiddenField(forbidden_name(key)));
        }

        match key {
            "root" => set_once(&mut fields.root, value, "root")?,
            "roothash" => set_once(&mut fields.root_hash, value, "roothash")?,
            "systemd.verity_root_data" => {
                set_once(&mut fields.verity_data, value, "systemd.verity_root_data")?
            }
            "systemd.verity_root_hash" => {
                set_once(&mut fields.verity_hash, value, "systemd.verity_root_hash")?
            }
            "systemd.verity" => set_once(&mut fields.verity_enabled, value, "systemd.verity")?,
            _ => {}
        }
    }

    let root = required_nonempty(fields.root, "root")?;
    if root != "/dev/mapper/root" {
        return Err(invalid("root", root));
    }
    if required_nonempty(fields.verity_enabled, "systemd.verity")? != "yes" {
        return Err(invalid(
            "systemd.verity",
            fields.verity_enabled.unwrap_or_default(),
        ));
    }

    let root_hash = required_nonempty(fields.root_hash, "roothash")?;
    if root_hash.len() != 64
        || !root_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("roothash", root_hash));
    }

    let data = required_nonempty(fields.verity_data, "systemd.verity_root_data")?;
    let hash = required_nonempty(fields.verity_hash, "systemd.verity_root_hash")?;
    let data_slot = slot_for_data(data).ok_or_else(|| invalid("systemd.verity_root_data", data))?;
    let hash_slot = slot_for_hash(hash).ok_or_else(|| invalid("systemd.verity_root_hash", hash))?;
    if data_slot != hash_slot {
        return Err(ParseError::SlotMismatch);
    }

    Ok(NormalBootIdentity {
        root: root.to_owned(),
        slot: data_slot,
        root_hash: root_hash.to_owned(),
    })
}

/// Parses and validates the dedicated recovery command line.
///
/// Recovery runs entirely from its initrd, so its signed command line is an
/// exact three-field allowlist. Rejecting every additional token prevents a
/// firmware-appended command line from selecting a normal root, an alternate
/// target, a debug shell, or another systemd command-line control surface.
///
/// # Errors
///
/// Returns [`ParseError`] unless each required recovery field appears exactly
/// once with its canonical value and no other token is present.
pub fn parse_recovery(cmdline: &str) -> Result<RecoveryBootIdentity, ParseError> {
    let mut recovery = None;
    let mut target = None;
    let mut luks = None;

    for token in cmdline.split_ascii_whitespace() {
        let (key, value) = match token.split_once('=') {
            Some((key, value)) => (key, value),
            None => (token, "<bare>"),
        };

        match key {
            "aos.recovery" => set_once(&mut recovery, value, "aos.recovery")?,
            "rd.systemd.unit" => set_once(&mut target, value, "rd.systemd.unit")?,
            "rd.luks" => set_once(&mut luks, value, "rd.luks")?,
            _ => return Err(ParseError::UnexpectedField(key.to_owned())),
        }
    }

    let recovery = required_nonempty(recovery, "aos.recovery")?;
    if recovery != "1" {
        return Err(invalid("aos.recovery", recovery));
    }

    let target = required_nonempty(target, "rd.systemd.unit")?;
    if target != "aos-recovery.target" {
        return Err(invalid("rd.systemd.unit", target));
    }

    let luks = required_nonempty(luks, "rd.luks")?;
    if luks != "0" {
        return Err(invalid("rd.luks", luks));
    }

    Ok(RecoveryBootIdentity)
}

fn is_forbidden_normal_key(key: &str) -> bool {
    matches!(
        key,
        "aos.recovery"
            | "rd.luks"
            | "rd.systemd.verity"
            | "SYSTEMD_SULOGIN_FORCE"
            | "systemd.unit"
            | "rd.systemd.unit"
            | "systemd.wants"
            | "rd.systemd.wants"
            | "systemd.debug_shell"
            | "rd.systemd.debug_shell"
            | "systemd.break"
            | "rd.systemd.break"
            | "systemd.run"
            | "rd.systemd.run"
            | "systemd.setenv"
            | "rd.systemd.setenv"
            | "systemd.verity_root_options"
    ) || key.starts_with("systemd.extra-unit.")
        || key.starts_with("systemd.unit-dropin.")
        || key.starts_with("rd.systemd.extra-unit.")
        || key.starts_with("rd.systemd.unit-dropin.")
}

fn forbidden_name(key: &str) -> &'static str {
    match key {
        "aos.recovery" => "aos.recovery",
        "rd.luks" => "rd.luks",
        "rd.systemd.verity" => "rd.systemd.verity",
        "SYSTEMD_SULOGIN_FORCE" => "SYSTEMD_SULOGIN_FORCE",
        "systemd.verity_root_options" => "systemd.verity_root_options",
        key if key.contains("extra-unit") => "systemd.extra-unit.*",
        key if key.contains("unit-dropin") => "systemd.unit-dropin.*",
        _ => "systemd command-line control",
    }
}

fn set_once<'a>(
    destination: &mut Option<&'a str>,
    value: &'a str,
    field: &'static str,
) -> Result<(), ParseError> {
    if destination.replace(value).is_some() {
        return Err(ParseError::DuplicateField(field));
    }
    Ok(())
}

fn required_nonempty<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, ParseError> {
    match value {
        None => Err(ParseError::MissingField(field)),
        Some("") | Some("<bare>") => Err(invalid(field, value.unwrap_or_default())),
        Some(value) => Ok(value),
    }
}

fn invalid(field: &'static str, value: &str) -> ParseError {
    ParseError::InvalidField {
        field,
        value: value.to_owned(),
    }
}

fn slot_for_data(device: &str) -> Option<BootSlot> {
    match device {
        ROOT_A => Some(BootSlot::A),
        ROOT_B => Some(BootSlot::B),
        _ => None,
    }
}

fn slot_for_hash(device: &str) -> Option<BootSlot> {
    match device {
        ROOT_A_HASH => Some(BootSlot::A),
        ROOT_B_HASH => Some(BootSlot::B),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{BootSlot, ParseError, RecoveryBootIdentity, parse_normal, parse_recovery};

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn verity(slot: &str) -> String {
        format!(
            "console=ttyS0 root=/dev/mapper/root ro systemd.verity=yes \
             systemd.verity_root_data=/dev/disk/by-partlabel/root-{slot} \
             systemd.verity_root_hash=/dev/disk/by-partlabel/root-{slot}-hash \
             roothash={HASH}"
        )
    }

    #[test]
    fn accepts_slot_a_and_repeatable_console() {
        let parsed = parse_normal(&format!("console=ttyS0 {} console=tty0", verity("a")));
        assert_eq!(parsed.map(|identity| identity.slot), Ok(BootSlot::A));
    }

    #[test]
    fn accepts_slot_b() {
        let parsed = parse_normal(&verity("b"));
        assert_eq!(parsed.map(|identity| identity.slot), Ok(BootSlot::B));
    }

    #[test]
    fn rejects_nonverity_root_without_verity_fields() {
        assert!(parse_normal("root=/dev/disk/by-partlabel/root-a ro").is_err());
    }

    #[test]
    fn rejects_every_duplicate_scalar_field() {
        let cases = [
            "root=/dev/mapper/root root=/dev/mapper/root",
            "roothash=aa roothash=aa",
            "systemd.verity=yes systemd.verity=yes",
            "systemd.verity_root_data=a systemd.verity_root_data=a",
            "systemd.verity_root_hash=a systemd.verity_root_hash=a",
        ];
        for case in cases {
            assert!(matches!(
                parse_normal(case),
                Err(ParseError::DuplicateField(_))
            ));
        }
    }

    #[test]
    fn rejects_mixed_slot_tuple() {
        let cmdline = verity("a").replace("root-a-hash", "root-b-hash");
        assert_eq!(parse_normal(&cmdline), Err(ParseError::SlotMismatch));
    }

    #[test]
    fn rejects_malformed_root_hash() {
        let cmdline = verity("a").replace(HASH, "xyz");
        assert!(matches!(
            parse_normal(&cmdline),
            Err(ParseError::InvalidField {
                field: "roothash",
                ..
            })
        ));
    }

    #[test]
    fn rejects_noncanonical_uppercase_root_hash() {
        let cmdline = verity("a").replace(HASH, &HASH.to_ascii_uppercase());
        assert!(matches!(
            parse_normal(&cmdline),
            Err(ParseError::InvalidField {
                field: "roothash",
                ..
            })
        ));
    }

    #[test]
    fn rejects_interactive_and_recovery_selectors() {
        for selector in [
            "rd.systemd.unit=emergency.target",
            "systemd.unit=emergency.target",
            "rd.systemd.wants=debug-shell.service",
            "systemd.wants=debug-shell.service",
            "aos.recovery=1",
            "rd.luks=1",
            "rd.systemd.verity=no",
            "SYSTEMD_SULOGIN_FORCE=1",
            "systemd.debug_shell=1",
            "rd.systemd.debug_shell=1",
            "systemd.break=pre-mount",
            "rd.systemd.break=pre-mount",
            "systemd.run=/bin/bash",
            "rd.systemd.run=/bin/bash",
            "systemd.setenv=SYSTEMD_SULOGIN_FORCE=1",
            "systemd.extra-unit.foo.service=/tmp/foo",
            "systemd.unit-dropin.foo.service=bar.conf:/tmp/bar",
            "systemd.verity_root_options=ignore-corruption",
        ] {
            assert!(matches!(
                parse_normal(&format!("{} {selector}", verity("a"))),
                Err(ParseError::ForbiddenField(_))
            ));
        }
    }

    #[test]
    fn accepts_only_the_canonical_recovery_identity() {
        assert_eq!(
            parse_recovery("rd.systemd.unit=aos-recovery.target aos.recovery=1 rd.luks=0"),
            Ok(RecoveryBootIdentity)
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_noncanonical_recovery_fields() {
        for cmdline in [
            "aos.recovery=1 rd.luks=0",
            "rd.systemd.unit=aos-recovery.target aos.recovery=1 aos.recovery=1 rd.luks=0",
            "rd.systemd.unit=emergency.target aos.recovery=1 rd.luks=0",
            "rd.systemd.unit=aos-recovery.target aos.recovery=0 rd.luks=0",
            "rd.systemd.unit=aos-recovery.target aos.recovery=1 rd.luks=1",
        ] {
            assert!(parse_recovery(cmdline).is_err(), "accepted `{cmdline}`");
        }
    }

    #[test]
    fn rejects_every_additional_recovery_token() {
        for appended in [
            "root=/dev/mapper/root",
            "roothash=aa",
            "systemd.verity=yes",
            "systemd.unit=emergency.target",
            "rd.systemd.wants=debug-shell.service",
            "SYSTEMD_SULOGIN_FORCE=1",
            "console=ttyS0",
        ] {
            let cmdline =
                format!("rd.systemd.unit=aos-recovery.target aos.recovery=1 rd.luks=0 {appended}");
            assert!(matches!(
                parse_recovery(&cmdline),
                Err(ParseError::UnexpectedField(_))
            ));
        }
    }
}
