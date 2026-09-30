//! Closed original startup names shared by the Root and Controller captures.

use super::NormalRootStartupErrorV1;

pub(crate) fn names(maximum: usize) -> Result<Vec<String>, NormalRootStartupErrorV1> {
    let count = match std::env::var("LISTEN_FDS") {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|_| NormalRootStartupErrorV1::Activation)?,
        Err(std::env::VarError::NotPresent) => 0,
        Err(_) => return Err(NormalRootStartupErrorV1::Activation),
    };
    if count > maximum {
        return Err(NormalRootStartupErrorV1::Activation);
    }
    if count == 0 {
        if ["LISTEN_PID", "LISTEN_FDNAMES"]
            .iter()
            .any(|name| std::env::var_os(name).is_some())
        {
            return Err(NormalRootStartupErrorV1::Activation);
        }
        return Ok(Vec::new());
    }
    let pid = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(NormalRootStartupErrorV1::Activation)?;
    let names =
        std::env::var("LISTEN_FDNAMES").map_err(|_| NormalRootStartupErrorV1::Activation)?;
    if pid != std::process::id()
        || names.len() > count * 256
        || !names.is_ascii()
        || names.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(NormalRootStartupErrorV1::Activation);
    }
    let names = names.split(':').map(str::to_owned).collect::<Vec<_>>();
    if names.len() != count || names.iter().any(String::is_empty) {
        return Err(NormalRootStartupErrorV1::Activation);
    }
    Ok(names)
}
