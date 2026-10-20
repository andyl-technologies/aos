//! Runs the production unprivileged AOS sandbox node controller.
//!
//! [`aos_sandbox_services::controller`] selects the fixed listener and HTTP
//! assembly. Protected startup, readiness, capability reporting, and authority
//! gates remain in the session-security runtime and its domain owners. The
//! closed enrollment-prefix image-build commands emit compiled layout
//! DATA and exits before entering that runtime.

use std::process::ExitCode;

fn main() -> ExitCode {
    // Image generation reads only compiled layout DATA. This closed mode
    // enters no process identity, descriptor capture or Controller runtime.
    match enrollment_prefix_mode(std::env::args_os()) {
        Ok(mode @ (EnrollmentPrefixMode::Initial | EnrollmentPrefixMode::Range(_))) => {
            let result = match mode {
                EnrollmentPrefixMode::Range(recipients) => write_enrollment_range_prefix(
                    &mut std::io::stdout().lock(), recipients,
                ),
                _ => write_enrollment_prefix(&mut std::io::stdout().lock()),
            };
            return match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(cause) => {
                    eprintln!("aos-sandboxd: enrollment prefix: {cause}");
                    ExitCode::FAILURE
                }
            };
        }
        Err(cause) => {
            eprintln!("aos-sandboxd: enrollment prefix: {cause}");
            return ExitCode::FAILURE;
        }
        Ok(EnrollmentPrefixMode::Runtime) => {}
    }

    match aos_sandbox_services::controller::run_from_environment() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aos-sandboxd: {error}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum EnrollmentPrefixMode {
    Runtime,
    Initial,
    Range(u64),
}

// Only the complete export grammar selects build-time DATA. No omitted count
// or guessed default can produce a funded range declaration.
fn enrollment_prefix_mode(mut arguments: impl Iterator<Item = std::ffi::OsString>)
    -> Result<EnrollmentPrefixMode, std::io::Error>
{
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidInput,
        "enrollment prefix export requires its exact finite argument grammar");
    let selected = arguments.nth(1);
    let mode = match selected.as_deref() {
        Some(value) if value == std::ffi::OsStr::new("--print-enrollment-prefix") => {
            EnrollmentPrefixMode::Initial
        }
        Some(value) if value == std::ffi::OsStr::new("--print-enrollment-range-prefix") => {
            let encoded = arguments.next().ok_or_else(invalid)?;
            let text = encoded.to_str().ok_or_else(invalid)?;
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            let recipients = text.parse::<u64>().map_err(|_| invalid())?;
            if recipients == 0 {
                return Err(invalid());
            }
            EnrollmentPrefixMode::Range(recipients)
        }
        _ => return Ok(EnrollmentPrefixMode::Runtime),
    };
    if arguments.next().is_some() {
        return Err(invalid());
    }
    Ok(mode)
}

fn write_enrollment_range_prefix(output: &mut impl std::io::Write, recipients: u64)
    -> Result<(), Box<dyn std::error::Error>>
{
    use aos_sandbox_core::ResourceDimension;

    let prefix = aos_sandbox_broker::controller_receiving::ControllerStartupOpeningV1::
        enrollment_range_prefix_receiving_demand_v2(recipients)?;
    write!(output, "{{\"format\":\"aos-controller-enrollment-range-prefix-v2\",\"recipients\":{recipients},\"dimensions\":[")?;
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        if index != 0 {
            write!(output, ",")?;
        }
        write!(output, "[\"{}\",{}]", dimension.as_str(), prefix.get(dimension))?;
    }
    writeln!(output, "]}}")?;
    Ok(())
}

fn write_enrollment_prefix(output: &mut impl std::io::Write)
    -> Result<(), Box<dyn std::error::Error>>
{
    use aos_sandbox_core::ResourceDimension;

    let prefix = aos_sandbox_broker::controller_receiving::ControllerStartupOpeningV1::
        enrollment_prefix_receiving_demand_v1()?;
    write!(output, "{{\"format\":\"aos-controller-enrollment-prefix-v1\",\"dimensions\":[")?;
    for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
        if index != 0 {
            write!(output, ",")?;
        }
        write!(output, "[\"{}\",{}]", dimension.as_str(), prefix.get(dimension))?;
    }
    writeln!(output, "]}}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_mode_is_closed_and_cannot_mix_service_arguments() {
        let args = |values: &[&str]| {
            values.iter().map(|value| std::ffi::OsString::from(*value))
                .collect::<Vec<_>>().into_iter()
        };
        assert_eq!(enrollment_prefix_mode(args(&["aos-sandboxd", "--print-enrollment-prefix"])).unwrap(), EnrollmentPrefixMode::Initial);
        assert!(enrollment_prefix_mode(args(&["aos-sandboxd", "--print-enrollment-prefix", "--operator-recover-only"])).is_err());
        assert_eq!(enrollment_prefix_mode(args(&["aos-sandboxd", "1000", "1000", "--operator-recover-only"])).unwrap(), EnrollmentPrefixMode::Runtime);
        assert_eq!(enrollment_prefix_mode(args(&["aos-sandboxd"])).unwrap(), EnrollmentPrefixMode::Runtime);
        assert_eq!(enrollment_prefix_mode(args(&["aos-sandboxd", "--print-enrollment-range-prefix", "3"])).unwrap(), EnrollmentPrefixMode::Range(3));
        for invalid in ["", "0", "-1", "+1", "18446744073709551616"] {
            assert!(enrollment_prefix_mode(args(&["aos-sandboxd", "--print-enrollment-range-prefix", invalid])).is_err());
        }
        assert!(enrollment_prefix_mode(args(&["aos-sandboxd", "--print-enrollment-range-prefix"])).is_err());
    }

    #[test]
    fn output_uses_the_actual_compiled_supplier_and_complete_resource_registry() {
        let mut encoded = Vec::new();
        write_enrollment_prefix(&mut encoded).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(parsed["format"], "aos-controller-enrollment-prefix-v1");
        let rows = parsed["dimensions"].as_array().unwrap();
        let actual = aos_sandbox_broker::controller_receiving::ControllerStartupOpeningV1::
            enrollment_prefix_receiving_demand_v1().unwrap();
        assert_eq!(rows.len(), aos_sandbox_core::ResourceDimension::COUNT);
        for (row, dimension) in rows.iter().zip(aos_sandbox_core::ResourceDimension::ALL) {
            assert_eq!(row[0], dimension.as_str());
            assert_eq!(row[1], actual.get(dimension));
        }
    }

    #[test]
    fn range_export_uses_the_exact_count_and_compiled_supplier() {
        let recipients = 3;
        let mut encoded = Vec::new();
        write_enrollment_range_prefix(&mut encoded, recipients).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(parsed["format"], "aos-controller-enrollment-range-prefix-v2");
        assert_eq!(parsed["recipients"], recipients);
        let rows = parsed["dimensions"].as_array().unwrap();
        let actual = aos_sandbox_broker::controller_receiving::ControllerStartupOpeningV1::
            enrollment_range_prefix_receiving_demand_v2(recipients).unwrap();
        assert_eq!(rows.len(), aos_sandbox_core::ResourceDimension::COUNT);
        for (row, dimension) in rows.iter().zip(aos_sandbox_core::ResourceDimension::ALL) {
            assert_eq!(row[0], dimension.as_str());
            assert_eq!(row[1], actual.get(dimension));
        }
    }
}
