//! Compares credential delivery against the Source-bound immutable unit bytes.
//!
//! The fixed mappings use canonical external system credential names.
//! Both retained PID1 samples must contain exactly those mappings and no other
//! credential mechanism. This borrowed comparison grants no key provenance,
//! floor decoding, writer or TPM authority; image composition must still bind
//! the selected sources to the normal owners and independent approval purpose.

use aos_systemd_client::{OwnedValue, Value};

use super::super::credentials::NAMES;
use super::{Method46InitialServiceRoleV1, Method46InitialStartupClosedV1};

const SIGNATURES: [&str; 6] = ["a(ss)", "a(ss)", "a(say)", "a(say)", "as", "a(ss)"];

fn selected_sources(
    fragment: &[u8],
) -> Result<[&str; NAMES.len()], Method46InitialStartupClosedV1> {
    let text = std::str::from_utf8(fragment).map_err(|_| Method46InitialStartupClosedV1)?;
    let mut in_service = false;
    let mut seen_service = false;
    let mut sources = [None; NAMES.len()];

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

    let mut selected = [""; NAMES.len()];
    for (index, source) in sources.into_iter().enumerate() {
        let source = source.ok_or(Method46InitialStartupClosedV1)?;
        if selected[..index].contains(&source) {
            return Err(Method46InitialStartupClosedV1);
        }
        selected[index] = source;
    }
    Ok(selected)
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
    let mut found = [false; NAMES.len()];

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
    if found != [true; NAMES.len()] {
        return Err(Method46InitialStartupClosedV1);
    }
    Ok(())
}

pub(super) fn require_normal_manifest_source(
    role: Method46InitialServiceRoleV1,
    values: &[OwnedValue],
    fragment: &[u8],
) -> Result<(), Method46InitialStartupClosedV1> {
    let expected = selected_sources(fragment)?[3];
    let name = match role {
        Method46InitialServiceRoleV1::ControllerStorageClient => "storage-manifest",
        Method46InitialServiceRoleV1::StorageBroker => "storage-broker-manifest",
    };
    require_named_source(values, name, expected)
}

pub(super) fn require_other_normal_manifest_sources(
    values: &[OwnedValue],
    fragment: &[u8],
) -> Result<(), Method46InitialStartupClosedV1> {
    let sources = selected_sources(fragment)?;
    for (name, expected) in ["host-manifest", "mount-manifest", "network-manifest"]
        .into_iter()
        .zip(&sources[4..])
    {
        require_named_source(values, name, expected)?;
    }
    Ok(())
}

fn require_named_source(
    values: &[OwnedValue],
    name: &str,
    expected: &str,
) -> Result<(), Method46InitialStartupClosedV1> {
    if values.len() != SIGNATURES.len() {
        return Err(Method46InitialStartupClosedV1);
    }
    let mut found = false;
    for (index, (value, signature)) in values.iter().zip(SIGNATURES).enumerate() {
        if value.value_signature().to_string() != signature {
            return Err(Method46InitialStartupClosedV1);
        }
        let Value::Array(rows) = &**value else {
            return Err(Method46InitialStartupClosedV1);
        };
        // The selected normal units use the plain external LoadCredential
        // recipe. Alternate mechanisms cannot shadow this public input.
        if index != 0 {
            if !rows.is_empty() {
                return Err(Method46InitialStartupClosedV1);
            }
            continue;
        }
        for row in rows.inner() {
            let Value::Structure(pair) = row else {
                return Err(Method46InitialStartupClosedV1);
            };
            let [Value::Str(actual), Value::Str(source)] = pair.fields() else {
                return Err(Method46InitialStartupClosedV1);
            };
            if actual.as_str() == name
                && (std::mem::replace(&mut found, true) || source.as_str() != expected)
            {
                return Err(Method46InitialStartupClosedV1);
            }
        }
    }
    if !found {
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
                NAMES.len()
            ],
            vec![
                (
                    "foreign".into(),
                    "/run/credentials/@system/external-0".into()
                );
                NAMES.len()
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
            original.replace("external-3", "external-0"),
            original.replace("external-3", "external-1"),
            original.replace("external-3", "external-2"),
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

    fn normal_properties(rows: Vec<(String, String)>) -> Vec<OwnedValue> {
        let mut values = properties();
        let mut delivery: Vec<_> = values.drain(12..18).collect();
        delivery[0] = value(rows);
        delivery
    }

    fn other_normal_rows() -> Vec<(String, String)> {
        ["host-manifest", "mount-manifest", "network-manifest"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    name.to_owned(),
                    format!("/run/credentials/@system/external-{}", index + 4),
                )
            })
            .collect()
    }

    #[test]
    fn mandatory_endpoint_sources_match_all_original_controller_delivery_rows() {
        let fragment = fragment();
        let mut rows = other_normal_rows();
        rows.push((
            "private-key".into(),
            "/run/credentials/@system/private".into(),
        ));

        for _ in 0..2 {
            assert!(
                require_other_normal_manifest_sources(
                    &normal_properties(rows.clone()),
                    fragment.as_bytes(),
                )
                .is_ok()
            );
            rows.reverse();
        }

        for index in 0..3 {
            let mut missing = other_normal_rows();
            missing.remove(index);
            let mut duplicate = other_normal_rows();
            duplicate.push(duplicate[index].clone());
            let mut replaced = other_normal_rows();
            replaced[index].1 = "/run/credentials/@system/foreign".into();
            let mut wrong_name = other_normal_rows();
            wrong_name[index].0 = "foreign-manifest".into();

            for rows in [missing, duplicate, replaced, wrong_name] {
                assert!(
                    require_other_normal_manifest_sources(
                        &normal_properties(rows),
                        fragment.as_bytes(),
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn mandatory_endpoint_delivery_refuses_alternate_credential_mechanisms() {
        let fragment = fragment();
        for (index, changed) in [
            (
                1,
                value(vec![("host-manifest".to_string(), "/external".to_string())]),
            ),
            (2, value(vec![("mount-manifest".to_string(), vec![1_u8])])),
            (3, value(vec![("network-manifest".to_string(), vec![1_u8])])),
            (4, value(vec!["*".to_string()])),
            (5, value(vec![("*".to_string(), "*".to_string())])),
        ] {
            let mut values = normal_properties(other_normal_rows());
            values[index] = changed;

            assert!(require_other_normal_manifest_sources(&values, fragment.as_bytes()).is_err());
        }
    }

    #[test]
    fn every_fixed_initial_credential_source_must_remain_distinct() {
        let fragment = fragment();
        for source in 0..NAMES.len() {
            for destination in 0..NAMES.len() {
                if source == destination {
                    continue;
                }
                let aliased = fragment.replace(
                    &format!("@system/external-{source}\n"),
                    &format!("@system/external-{destination}\n"),
                );

                assert!(selected_sources(aliased.as_bytes()).is_err());
            }
        }
    }

    #[test]
    fn selected_normal_manifest_source_ignores_row_order_and_unrelated_key_metadata() {
        for (role, name) in [
            (
                Method46InitialServiceRoleV1::ControllerStorageClient,
                "storage-manifest",
            ),
            (
                Method46InitialServiceRoleV1::StorageBroker,
                "storage-broker-manifest",
            ),
        ] {
            let mut rows = vec![
                (
                    "private-signing-key".into(),
                    "/run/credentials/@system/private".into(),
                ),
                (name.into(), "/run/credentials/@system/external-3".into()),
            ];
            assert!(
                require_normal_manifest_source(
                    role,
                    &normal_properties(rows.clone()),
                    fragment().as_bytes()
                )
                .is_ok()
            );
            rows.reverse();
            assert!(
                require_normal_manifest_source(
                    role,
                    &normal_properties(rows),
                    fragment().as_bytes()
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn selected_normal_manifest_rejects_missing_duplicate_substituted_or_shadowed_source() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let expected = (
            "storage-broker-manifest".to_string(),
            "/run/credentials/@system/external-3".to_string(),
        );
        for rows in [
            vec![],
            vec![expected.clone(), expected.clone()],
            vec![("storage-manifest".into(), expected.1.clone())],
            vec![(expected.0.clone(), "/run/credentials/@system/other".into())],
        ] {
            assert!(
                require_normal_manifest_source(
                    role,
                    &normal_properties(rows),
                    fragment().as_bytes()
                )
                .is_err()
            );
        }
        let original = normal_properties(vec![expected]);
        for (index, changed) in [
            (
                1,
                value(vec![("other".to_string(), "/external".to_string())]),
            ),
            (2, value(vec![("other".to_string(), vec![1_u8])])),
            (3, value(vec![("other".to_string(), vec![1_u8])])),
            (4, value(vec!["*".to_string()])),
            (5, value(vec![("*".to_string(), "*".to_string())])),
        ] {
            let mut values = original.clone();
            values[index] = changed;
            assert!(require_normal_manifest_source(role, &values, fragment().as_bytes()).is_err());
        }
        for index in 0..6 {
            let mut values = original.clone();
            values[index] = value(Vec::<u64>::new());
            assert!(require_normal_manifest_source(role, &values, fragment().as_bytes()).is_err());
        }
        assert!(
            require_normal_manifest_source(role, &original[..5], fragment().as_bytes()).is_err()
        );
    }
}
