//! Parses bounded activation-name DATA beside the actual inherited FD owner.

/// Reports malformed activation-name DATA without granting descriptor custody.
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original activation names are malformed")]
pub struct ActivationNamesErrorV1;

/// Parses the existing activation environment under its actual table bound.
///
/// # Errors
/// Rejects mismatched PID, count, non-ASCII/control text or malformed names.
pub fn original_activation_names_v1(maximum: usize) -> Result<Vec<String>, ActivationNamesErrorV1> {
    let count = match std::env::var("LISTEN_FDS") {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|_| ActivationNamesErrorV1)?,
        Err(std::env::VarError::NotPresent) => 0,
        Err(_) => return Err(ActivationNamesErrorV1),
    };
    if count > maximum {
        return Err(ActivationNamesErrorV1);
    }
    if count == 0 {
        if ["LISTEN_PID", "LISTEN_FDNAMES"]
            .iter()
            .any(|name| std::env::var_os(name).is_some())
        {
            return Err(ActivationNamesErrorV1);
        }
        return Ok(Vec::new());
    }
    let pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(ActivationNamesErrorV1)?;
    let names =
        std::env::var("LISTEN_FDNAMES").map_err(|_| ActivationNamesErrorV1)?;
    if pid != std::process::id()
        || names.len() > count * 256
        || !names.is_ascii()
        || names.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ActivationNamesErrorV1);
    }
    let names = names.split(':').map(str::to_owned).collect::<Vec<_>>();
    if names.len() != count || names.iter().any(String::is_empty) {
        return Err(ActivationNamesErrorV1);
    }
    Ok(names)
}
