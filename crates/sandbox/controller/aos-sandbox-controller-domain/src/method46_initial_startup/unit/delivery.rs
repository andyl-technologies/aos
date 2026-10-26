//! Compares credential delivery against the Source-bound immutable unit bytes.
//!
//! The three fixed mappings use canonical external system credential names.
//! Both retained PID1 samples must contain exactly those mappings and no other
//! credential mechanism. This borrowed comparison grants no key provenance,
//! floor decoding, writer or TPM authority; image composition must still bind
//! the selected sources to the normal owners and independent approval purpose.

use aos_systemd_client::{OwnedValue, Value};

use super::super::credentials::NAMES;
use super::Method46InitialStartupClosedV1;

const SIGNATURES: [&str; 6] = ["a(ss)", "a(ss)", "a(say)", "a(say)", "as", "a(ss)"];

fn selected_sources(fragment: &[u8]) -> Result<[&str; 3], Method46InitialStartupClosedV1> {
    let text = std::str::from_utf8(fragment).map_err(|_| Method46InitialStartupClosedV1)?;
    let mut in_service = false;
    let mut seen_service = false;
    let mut sources = [None; 3];

    // The image generator emits simple assignments. Refuse continuation syntax
    // rather than accidentally interpreting only part of a systemd directive.
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if line.ends_with('\\') {
            return Err(Method46InitialStartupClosedV1);
        }
        if line.starts_with('[') {
            in_service = line == "[Service]";
            if in_service && std::mem::replace(&mut seen_service, true) {
                return Err(Method46InitialStartupClosedV1);
            }
            continue;
        }
        if !in_service {
            continue;
        }
        let Some((key, mapping)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "LoadCredential" {
            continue;
        }
        let (name, source) = mapping
            .split_once(':')
            .ok_or(Method46InitialStartupClosedV1)?;
        let index = NAMES
            .iter()
            .position(|expected| *expected == name)
            .ok_or(Method46InitialStartupClosedV1)?;
        let suffix = source
            .strip_prefix("/run/credentials/@system/")
            .ok_or(Method46InitialStartupClosedV1)?;
        if sources[index].is_some()
            || suffix.is_empty()
            || suffix.len() > 255
            || matches!(suffix, "." | "..")
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(Method46InitialStartupClosedV1);
        }
        sources[index] = Some(source);
    }

    let [Some(provision), Some(auth), Some(approval)] = sources else {
        return Err(Method46InitialStartupClosedV1);
    };
    if provision == auth || provision == approval || auth == approval {
        return Err(Method46InitialStartupClosedV1);
    }
    Ok([provision, auth, approval])
}

pub(super) fn require_delivery(
    service_values: &[OwnedValue],
    fragment: &[u8],
) -> Result<(), Method46InitialStartupClosedV1> {
    if service_values.len() != super::service::PROPERTIES.len() {
        return Err(Method46InitialStartupClosedV1);
    }
    let values = &service_values[12..18];
    let sources = selected_sources(fragment)?;
    let mut found = [false; 3];

    for (index, (value, signature)) in values.iter().zip(SIGNATURES).enumerate() {
        if value.value_signature().to_string() != signature {
            return Err(Method46InitialStartupClosedV1);
        }
        let Value::Array(rows) = &**value else {
            return Err(Method46InitialStartupClosedV1);
        };
        if index != 0 {
            if !rows.is_empty() {
                return Err(Method46InitialStartupClosedV1);
            }
            continue;
        }
        if rows.len() != NAMES.len() {
            return Err(Method46InitialStartupClosedV1);
        }
        // PID1's hash-map traversal order is not a protocol guarantee. Require
        // each fixed pair exactly once without sorting or copying credentials.
        for row in rows.inner() {
            let Value::Structure(pair) = row else {
                return Err(Method46InitialStartupClosedV1);
            };
            let [Value::Str(name), Value::Str(source)] = pair.fields() else {
                return Err(Method46InitialStartupClosedV1);
            };
            let slot = NAMES
                .iter()
                .position(|expected| *expected == name.as_str())
                .ok_or(Method46InitialStartupClosedV1)?;
            if std::mem::replace(&mut found[slot], true) || source.as_str() != sources[slot] {
                return Err(Method46InitialStartupClosedV1);
            }
        }
    }
    if found != [true; 3] {
        return Err(Method46InitialStartupClosedV1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn fragment() -> String {
        let mut result = String::from("[Unit]\nDescription=Manual floor\n[Service]\n");
        for (index, name) in NAMES.iter().enumerate() {
            result.push_str(&format!(
                "LoadCredential={name}:/run/credentials/@system/external-{index}\n"
            ));
        }
        result
    }

    fn properties() -> Vec<OwnedValue> {
        let mut values: Vec<OwnedValue> = (0..12).map(|_| false.into()).collect();
        values.extend([
            value(
                NAMES
                    .iter()
                    .enumerate()
                    .map(|(index, name)| {
                        (
                            name.to_string(),
                            format!("/run/credentials/@system/external-{index}"),
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
            value(Vec::<(String, String)>::new()),
            value(Vec::<(String, Vec<u8>)>::new()),
            value(Vec::<(String, Vec<u8>)>::new()),
            value(Vec::<String>::new()),
            value(Vec::<(String, String)>::new()),
        ]);
        values.extend(super::super::confinement::test_properties());
        values
    }

    #[test]
    fn initial_delivery_requires_each_selected_external_pair_once_in_any_order() {
        let fragment = fragment();
        let mut values = properties();
        assert!(require_delivery(&values, fragment.as_bytes()).is_ok());

        values[12] = value(
            NAMES
                .iter()
                .enumerate()
                .rev()
                .map(|(index, name)| {
                    (
                        name.to_string(),
                        format!("/run/credentials/@system/external-{index}"),
                    )
                })
                .collect::<Vec<_>>(),
        );
        assert!(require_delivery(&values, fragment.as_bytes()).is_ok());

        let mut changed_pairs: Vec<(String, String)> = NAMES
            .iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    name.to_string(),
                    format!("/run/credentials/@system/external-{index}"),
                )
            })
            .collect();
        changed_pairs[1].1 = "/run/credentials/@system/other".into();
        values[12] = value(changed_pairs);
        assert!(require_delivery(&values, fragment.as_bytes()).is_err());

        for rows in [
            vec![
                (
                    NAMES[0].to_string(),
                    "/run/credentials/@system/external-0".to_string()
                );
                3
            ],
            vec![
                (
                    "foreign".into(),
                    "/run/credentials/@system/external-0".into()
                );
                3
            ],
            vec![(
                NAMES[0].to_string(),
                "/run/credentials/@system/other".to_string(),
            )],
        ] {
            values[12] = value(rows);
            assert!(require_delivery(&values, fragment.as_bytes()).is_err());
        }
    }

    #[test]
    fn initial_delivery_rejects_alternate_mechanisms_and_empty_wrong_types() {
        let fragment = fragment();
        let alternatives = [
            (
                13,
                value(vec![(NAMES[0].to_string(), "/external".to_string())]),
            ),
            (14, value(vec![(NAMES[0].to_string(), vec![1_u8])])),
            (15, value(vec![(NAMES[0].to_string(), vec![1_u8])])),
            (16, value(vec!["*".to_string()])),
            (17, value(vec![("*".to_string(), "*".to_string())])),
        ];
        for (index, changed) in alternatives {
            let mut values = properties();
            values[index] = changed;
            assert!(require_delivery(&values, fragment.as_bytes()).is_err());
        }
        for index in 12..18 {
            let mut values = properties();
            values[index] = value(Vec::<u64>::new());
            assert!(require_delivery(&values, fragment.as_bytes()).is_err());
        }
        let mut values = properties();
        values.pop();
        assert!(require_delivery(&values, fragment.as_bytes()).is_err());
    }

    #[test]
    fn initial_delivery_refuses_ambiguous_or_foreign_fragment_sources() {
        let original = fragment();
        for changed in [
            original.replace("external-1", "external-0"),
            original.replace("@system/external-1", "@system/../external-1"),
            original.replace("@system/external-1", "@system/."),
            original.replace("/run/credentials/@system/", "/nix/store/"),
            original.replace("LoadCredential=", "# LoadCredential="),
            original.replace("[Service]", "[Unit]"),
            original.replace("external-0", "external-0\\\n"),
            format!("{original}LoadCredential=\n"),
            format!(
                "{original}LoadCredential={}:/run/credentials/@system/extra\n",
                NAMES[0]
            ),
            format!("{original}[Service]\n"),
        ] {
            assert!(selected_sources(changed.as_bytes()).is_err(), "{changed}");
        }
        assert!(selected_sources(&[0xff]).is_err());
    }
}
