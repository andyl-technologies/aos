//! Bounds inert original checkpoint-file roots against their exact archive roster.
//!
//! These checks never open a source path and never authenticate imported state.
//! A genuine native capture or independently authenticated backend archive must
//! supply the spelling before it can mediate native saved-file relocation.

/// Checks one original supplementary root without consulting the host namespace.
pub(super) fn validate_supplementary_root<'a>(
    root: &str,
    artifacts: impl Iterator<Item = (&'a str, &'a str)>,
) -> Result<(), &'static str> {
    if root.len() > 4096
        || !root.starts_with('/')
        || root.contains('\0')
        || root
            .split('/')
            .skip(1)
            .any(|component| matches!(component, "" | "." | ".."))
    {
        return Err("original supplementary root is not a bounded canonical absolute spelling");
    }
    let basename = root
        .rsplit('/')
        .next()
        .and_then(|component| component.strip_suffix("_files"))
        .filter(|stem| !stem.is_empty())
        .ok_or("original supplementary root lacks its checkpoint directory name")?;

    let mut files = 0usize;
    let mut checkpoints = 0usize;
    let mut supplementary = 0usize;
    for (role, name) in artifacts {
        files += 1;
        if files > 8192 {
            return Err("original image artifact inventory exceeds its finite bound");
        }
        if role != "image" {
            continue;
        }
        let relative = name
            .strip_prefix("image/")
            .ok_or("image reconstruction name omits its explicit role")?;
        if relative.contains('\0') {
            return Err("image reconstruction name contains a native string terminator");
        }
        let mut components = relative.split('/');
        let first = components
            .next()
            .ok_or("image reconstruction name is empty")?;
        if first.is_empty()
            || matches!(first, "." | "..")
            || components
                .clone()
                .any(|component| matches!(component, "" | "." | ".."))
        {
            return Err("image reconstruction name is not a canonical relative spelling");
        }
        if let Some(checkpoint) = first.strip_suffix(".dmtcp") {
            if checkpoint != basename || components.next().is_some() {
                return Err("native checkpoint file differs from its original supplementary root");
            }
            checkpoints += 1;
        }
        if let Some(directory) = first.strip_suffix("_files") {
            if directory != basename || components.next().is_none() {
                return Err("supplementary image roster differs from its original root");
            }
            supplementary += 1;
        } else if components.next().is_some() {
            return Err("nested image artifact lies outside the selected supplementary root");
        }
    }
    if checkpoints != 1 || supplementary == 0 {
        return Err("original checkpoint and complete supplementary artifact roster are absent");
    }
    Ok(())
}

#[cfg(test)]
#[path = "supplementary_tests.rs"]
mod tests;
