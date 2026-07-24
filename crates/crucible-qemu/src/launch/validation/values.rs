//! Parsing helpers for repeated QEMU options and comma-delimited suboptions.

use super::{LaunchProfileError, QemuPreSpawnLaunchValidationError};

pub(super) fn unique_option_value<'a>(
    args: &'a [String],
    option: &'static str,
) -> Result<&'a str, QemuPreSpawnLaunchValidationError> {
    let mut values = option_values(args, option)?;
    match values.len() {
        0 => Err(QemuPreSpawnLaunchValidationError::MissingOption { option }),
        1 => Ok(values.remove(0)),
        _ => Err(QemuPreSpawnLaunchValidationError::DuplicateOption { option }),
    }
}

pub(in crate::launch) fn option_values<'a>(
    args: &'a [String],
    option: &'static str,
) -> Result<Vec<&'a str>, QemuPreSpawnLaunchValidationError> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == option {
            let Some(value) = args.get(index + 1) else {
                return Err(QemuPreSpawnLaunchValidationError::MissingOptionValue { option });
            };
            values.push(value.as_str());
            index += 2;
        } else if let Some(value) = argument
            .strip_prefix(option)
            .and_then(|suffix| suffix.strip_prefix('='))
        {
            values.push(value);
            index += 1;
        } else {
            index += 1;
        }
    }
    Ok(values)
}

pub(super) fn comma_value<'a>(value: &'a str, key: &str) -> Option<&'a str> {
    value.split(',').find_map(|part| {
        part.trim()
            .strip_prefix(key)
            .and_then(|suffix| suffix.strip_prefix('='))
    })
}

pub(in crate::launch) fn unique_comma_value<'a>(
    value: &'a str,
    option: &'static str,
    key: &'static str,
) -> Result<Option<&'a str>, QemuPreSpawnLaunchValidationError> {
    unique_comma_value_any(value, option, &[key], key)
}

pub(super) fn unique_comma_value_any<'a>(
    value: &'a str,
    option: &'static str,
    keys: &[&'static str],
    key_label: &'static str,
) -> Result<Option<&'a str>, QemuPreSpawnLaunchValidationError> {
    let mut matched = None;
    for part in value.split(',') {
        let part = part.trim();
        for key in keys {
            if let Some(sub_value) = part
                .strip_prefix(key)
                .and_then(|suffix| suffix.strip_prefix('='))
                && matched.replace(sub_value).is_some()
            {
                return Err(QemuPreSpawnLaunchValidationError::DuplicateSubOption {
                    option,
                    key: key_label,
                });
            }
        }
    }
    Ok(matched)
}

pub(in crate::launch) fn validate_fixed_text(
    field: &'static str,
    value: &str,
) -> Result<(), LaunchProfileError> {
    if value.is_empty() || value.contains('\n') || value.contains('\0') {
        Err(LaunchProfileError::InvalidFixedText { field })
    } else {
        Ok(())
    }
}
