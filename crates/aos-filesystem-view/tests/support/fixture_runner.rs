//! Discovery and exact execution for the two single-thread fixture binaries.
//!
//! Listing emits the libtest `name: test` format without entering a fixture.
//! Both binaries own one non-ignored case; measurement options remain separate.

use std::io::Write;

/// Selects discovery or execution of the binary's single ordinary case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Invocation {
    /// Lists ordinary cases, or only ignored cases when requested.
    List { ignored: bool },
    /// Runs the binary's original fixture operation.
    Run,
}

/// Parses the fixture's supported Cargo and Nextest arguments.
///
/// # Errors
///
/// Returns an error for unsupported options, malformed values, unknown names,
/// or a request to execute ignored cases when none exist.
pub(crate) fn parse(arguments: &[String], case: &str) -> Result<Invocation, String> {
    let mut list = false;
    let mut ignored = false;
    let mut exact = false;
    let mut selected = None;
    let mut arguments = arguments.iter();

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--list" => list = true,
            "--ignored" => ignored = true,
            "--exact" => exact = true,
            "--nocapture" | "--include-ignored" => {}
            "--format" => match arguments.next().map(String::as_str) {
                Some("terse" | "pretty") => {}
                _ => return Err("fixture runner supports only terse or pretty format".to_owned()),
            },
            "--test-threads" => {
                if arguments.next().map(String::as_str) != Some("1") {
                    return Err("fixture runner requires one test thread".to_owned());
                }
            }
            name if !name.starts_with('-') && selected.is_none() => selected = Some(name),
            _ => return Err(format!("unsupported fixture runner argument: {argument}")),
        }
    }

    if selected.is_some_and(|name| name != case) {
        return Err(format!("unknown fixture case; expected {case}"));
    }
    if exact && selected.is_none() {
        return Err("--exact requires a fixture case name".to_owned());
    }
    if list {
        return Ok(Invocation::List { ignored });
    }
    if ignored {
        return Err("fixture has no ignored cases to execute".to_owned());
    }
    Ok(Invocation::Run)
}

/// Writes the single ordinary case in libtest's discovery format.
///
/// # Errors
///
/// Returns an error if writing the listing fails.
pub(crate) fn list(writer: &mut impl Write, case: &str, ignored: bool) -> std::io::Result<()> {
    if !ignored {
        writeln!(writer, "{case}: test")?;
    }
    Ok(())
}

/// Lists the case or invokes its original fixture operation exactly once.
///
/// # Errors
///
/// Propagates listing failures and errors returned by the fixture operation.
pub(crate) fn execute(
    invocation: Invocation,
    case: &str,
    writer: &mut impl Write,
    operation: impl FnOnce() -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    match invocation {
        Invocation::List { ignored } => Ok(list(writer, case, ignored)?),
        Invocation::Run => operation(),
    }
}
