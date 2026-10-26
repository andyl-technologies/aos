//! Compares credential delivery against the Source-bound immutable unit bytes.
//!
//! The fixed mappings use canonical external system credential names.
//! Both retained PID1 samples must contain exactly those mappings and no other
//! credential mechanism. This borrowed comparison grants no key provenance,
//! floor decoding, writer or TPM authority; image composition must still bind
//! the selected sources to the normal owners and independent approval purpose.

use aos_systemd_client::{OwnedValue, Value};

use super::super::credentials::{NAMES, REQUIRED_CREDENTIAL_SLOTS};
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
        let Some(source) = source else {
            if REQUIRED_CREDENTIAL_SLOTS.contains(&index) {
                return Err(Method46InitialStartupClosedV1);
            }
            continue;
        };
        // ONLINE Controller and owner may deliberately share one public issuer.
        // No other alias is valid, especially approval or private index auth.
        if selected[..index]
            .iter()
            .enumerate()
            .any(|(previous, value)| *value == source && (previous, index) != (9, 15))
        {
            return Err(Method46InitialStartupClosedV1);
        }
        selected[index] = source;
    }
    // The ONLINE issuer is a separate authority key, required exactly when
    // this actual Controller is configured with the Nix endpoint.
    if selected[8].is_empty() != selected[9].is_empty()
        || selected[8].is_empty() != selected[15].is_empty()
    {
        return Err(Method46InitialStartupClosedV1);
    }
    Ok(selected)
}

pub(super) fn selected_credential_roster(
    fragment: &[u8],
) -> Result<[bool; NAMES.len()], Method46InitialStartupClosedV1> {
    Ok(selected_sources(fragment)?.map(|source| !source.is_empty()))
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
        if rows.len() != sources.iter().filter(|source| !source.is_empty()).count() {
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
    if found != sources.map(|source| !source.is_empty()) {
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
    for (name, expected) in [
        "host-manifest",
        "mount-manifest",
        "network-manifest",
        "mount-fuse-manifest",
        "nix-broker-session-manifest-v1",
        "nix-online-floor-issuer-v1",
    ]
    .into_iter()
    .zip(&sources[4..])
    {
        require_source(values, name, (!expected.is_empty()).then_some(*expected))?;
    }
    Ok(())
}

pub(super) fn require_normal_root_public_sources(
    values: &[OwnedValue],
    fragment: &[u8],
) -> Result<(), Method46InitialStartupClosedV1> {
    let sources = selected_sources(fragment)?;
    for (member, expected) in super::super::credentials::METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1
        .into_iter()
        .zip(&sources[10..])
    {
        require_source(
            values,
            member.name(),
            (!expected.is_empty()).then_some(*expected),
        )?;
    }
    Ok(())
}

pub(super) fn nix_owner_selected(fragment: &[u8]) -> Result<bool, Method46InitialStartupClosedV1> {
    Ok(!selected_sources(fragment)?[15].is_empty())
}

pub(super) fn require_normal_nix_owner_source(
    values: &[OwnedValue],
    fragment: &[u8],
) -> Result<(), Method46InitialStartupClosedV1> {
    let expected = selected_sources(fragment)?[15];
    if expected.is_empty() {
        return Err(Method46InitialStartupClosedV1);
    }
    require_named_source(values, "nix-online-floor-issuer-v1", expected)
}

fn require_named_source(
    values: &[OwnedValue],
    name: &str,
    expected: &str,
) -> Result<(), Method46InitialStartupClosedV1> {
    require_source(values, name, Some(expected))
}

fn require_source(
    values: &[OwnedValue],
    name: &str,
    expected: Option<&str>,
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
                && (std::mem::replace(&mut found, true) || Some(source.as_str()) != expected)
            {
                return Err(Method46InitialStartupClosedV1);
            }
        }
    }
    if found != expected.is_some() {
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
        [
            "host-manifest",
            "mount-manifest",
            "network-manifest",
            "mount-fuse-manifest",
            "nix-broker-session-manifest-v1",
            "nix-online-floor-issuer-v1",
        ]
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

        for index in 0..6 {
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
    fn root_public_delivery_requires_both_required_keys_and_exact_optional_presence() {
        use super::super::super::credentials::METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1 as MEMBERS;
        for mask in 0_u8..8 {
            let mut selected = [true; NAMES.len()];
            for (offset, slot) in (12..15).enumerate() {
                selected[slot] = mask & (1 << offset) != 0;
            }
            let fragment = NAMES
                .iter()
                .enumerate()
                .filter(|(index, _)| selected[*index])
                .fold(String::from("[Service]\n"), |mut text, (index, name)| {
                    text.push_str(&format!(
                        "LoadCredential={name}:/run/credentials/@system/external-{index}\n"
                    ));
                    text
                });
            let rows = MEMBERS
                .into_iter()
                .enumerate()
                .filter(|(index, _)| selected[index + 10])
                .map(|(index, member)| {
                    (
                        member.name().to_owned(),
                        format!("/run/credentials/@system/external-{}", index + 10),
                    )
                })
                .collect::<Vec<_>>();

            assert_eq!(
                selected_credential_roster(fragment.as_bytes()).unwrap(),
                selected
            );
            assert!(
                require_normal_root_public_sources(
                    &normal_properties(rows.clone()),
                    fragment.as_bytes()
                )
                .is_ok()
            );

            for (index, member) in MEMBERS.into_iter().enumerate() {
                let mut changed = rows.clone();
                if selected[index + 10] {
                    changed.retain(|(name, _)| name != member.name());
                } else {
                    changed.push((
                        member.name().to_owned(),
                        format!("/run/credentials/@system/external-{}", index + 10),
                    ));
                }
                assert!(
                    require_normal_root_public_sources(
                        &normal_properties(changed),
                        fragment.as_bytes()
                    )
                    .is_err()
                );
            }
            for missing in [10, 11] {
                let incomplete = fragment
                    .lines()
                    .filter(|line| {
                        !line.starts_with(&format!("LoadCredential={}:", NAMES[missing]))
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                assert!(selected_credential_roster(incomplete.as_bytes()).is_err());
            }
        }
    }

    #[test]
    fn root_public_delivery_refuses_duplicate_substituted_and_alternate_sources() {
        use super::super::super::credentials::METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1 as MEMBERS;
        let fragment = fragment();
        let rows = MEMBERS
            .into_iter()
            .enumerate()
            .map(|(index, member)| {
                (
                    member.name().to_owned(),
                    format!("/run/credentials/@system/external-{}", index + 10),
                )
            })
            .collect::<Vec<_>>();
        for index in 0..MEMBERS.len() {
            let mut duplicate = rows.clone();
            duplicate.push(rows[index].clone());
            let mut substituted = rows.clone();
            substituted[index].1.push_str("-substituted");
            for changed in [duplicate, substituted] {
                assert!(
                    require_normal_root_public_sources(
                        &normal_properties(changed),
                        fragment.as_bytes()
                    )
                    .is_err()
                );
            }
        }
        for (index, changed) in [
            (
                1,
                value(vec![(
                    "deployment-public-key".to_owned(),
                    "/external".to_owned(),
                )]),
            ),
            (
                2,
                value(vec![("project-public-key".to_owned(), vec![1_u8])]),
            ),
            (
                3,
                value(vec![("source-hold-public-key".to_owned(), vec![1_u8])]),
            ),
            (4, value(vec!["*".to_owned()])),
            (5, value(vec![("*".to_owned(), "*".to_owned())])),
        ] {
            let mut values = normal_properties(rows.clone());
            values[index] = changed;
            assert!(require_normal_root_public_sources(&values, fragment.as_bytes()).is_err());
        }
    }

    #[test]
    fn only_the_two_online_public_issuer_sources_may_alias() {
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

                assert_eq!(
                    selected_sources(aliased.as_bytes()).is_ok(),
                    matches!((source, destination), (9, 15) | (15, 9)),
                    "source {source} destination {destination}",
                );
            }
        }
    }

    #[test]
    fn configured_nix_requires_its_controller_floor_issuer_source() {
        for missing in [8, 9, 15] {
            let text = fragment();
            let mismatched = text
                .lines()
                .filter(|line| !line.starts_with(&format!("LoadCredential={}:", NAMES[missing])))
                .collect::<Vec<_>>()
                .join("\n");

            assert!(selected_credential_roster(mismatched.as_bytes()).is_err());
            assert!(require_delivery(&properties(), mismatched.as_bytes()).is_err());
        }
    }

    #[test]
    fn nix_owner_delivery_requires_the_actual_selected_source() {
        let fragment = fragment();
        let expected = (
            "nix-online-floor-issuer-v1".to_owned(),
            "/run/credentials/@system/external-15".to_owned(),
        );
        assert!(nix_owner_selected(fragment.as_bytes()).unwrap());
        assert!(
            require_normal_nix_owner_source(
                &normal_properties(vec![expected.clone()]),
                fragment.as_bytes(),
            )
            .is_ok()
        );

        // The same public ONLINE issuer may be delivered to both owners.
        let shared = fragment.replace("@system/external-15\n", "@system/external-9\n");
        assert!(
            require_normal_nix_owner_source(
                &normal_properties(vec![(
                    expected.0.clone(),
                    "/run/credentials/@system/external-9".to_owned()
                )]),
                shared.as_bytes(),
            )
            .is_ok()
        );

        for rows in [
            vec![],
            vec![expected.clone(), expected.clone()],
            vec![(
                expected.0.clone(),
                "/run/credentials/@system/foreign".to_owned(),
            )],
            vec![("foreign-issuer".to_owned(), expected.1.clone())],
        ] {
            assert!(
                require_normal_nix_owner_source(&normal_properties(rows), fragment.as_bytes())
                    .is_err()
            );
        }
        for (index, changed) in [
            (1, value(vec![(expected.0.clone(), expected.1.clone())])),
            (2, value(vec![(expected.0.clone(), vec![1_u8])])),
            (3, value(vec![(expected.0.clone(), vec![1_u8])])),
            (4, value(vec!["*".to_owned()])),
            (5, value(vec![("*".to_owned(), "*".to_owned())])),
        ] {
            let mut values = normal_properties(vec![expected.clone()]);
            values[index] = changed;
            assert!(require_normal_nix_owner_source(&values, fragment.as_bytes()).is_err());
        }
    }

    #[test]
    fn disabled_controller_nix_endpoint_omits_both_online_issuers() {
        let fragment = fragment()
            .lines()
            .filter(|line| {
                ![8, 9, 15]
                    .into_iter()
                    .any(|index| line.starts_with(&format!("LoadCredential={}:", NAMES[index])))
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!nix_owner_selected(fragment.as_bytes()).unwrap());
        assert!(
            require_normal_nix_owner_source(&normal_properties(vec![]), fragment.as_bytes())
                .is_err()
        );
    }

    #[test]
    fn optional_delivery_requires_exact_initial_and_controller_presence() {
        for mount_fuse in [false, true] {
            for nix in [false, true] {
                let mut selected = [true; NAMES.len()];
                selected[7] = mount_fuse;
                selected[8] = nix;
                selected[9] = nix;
                selected[15] = nix;
                let fragment = NAMES
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| selected[*index])
                    .fold(String::from("[Service]\n"), |mut text, (index, name)| {
                        text.push_str(&format!(
                            "LoadCredential={name}:/run/credentials/@system/external-{index}\n"
                        ));
                        text
                    });
                let initial_rows = NAMES
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| selected[*index])
                    .map(|(index, name)| {
                        (
                            name.to_string(),
                            format!("/run/credentials/@system/external-{index}"),
                        )
                    })
                    .collect::<Vec<_>>();
                let normal_rows = other_normal_rows()
                    .into_iter()
                    .enumerate()
                    .filter(|(index, _)| selected[index + 4])
                    .map(|(_, row)| row)
                    .collect::<Vec<_>>();
                let mut values = properties();
                values[12] = value(initial_rows.clone());

                assert_eq!(
                    selected_credential_roster(fragment.as_bytes()).unwrap(),
                    selected
                );
                assert!(require_delivery(&values, fragment.as_bytes()).is_ok());
                assert!(
                    require_other_normal_manifest_sources(
                        &normal_properties(normal_rows.clone()),
                        fragment.as_bytes()
                    )
                    .is_ok()
                );

                for index in 7..10 {
                    let mut changed_initial = initial_rows.clone();
                    let mut changed_normal = normal_rows.clone();
                    let normal_name = other_normal_rows()[index - 4].0.clone();
                    if selected[index] {
                        changed_initial.retain(|(name, _)| name != NAMES[index]);
                        changed_normal.retain(|(name, _)| name != &normal_name);
                    } else {
                        let source = format!("/run/credentials/@system/external-{index}");
                        changed_initial.push((NAMES[index].into(), source.clone()));
                        changed_normal.push((normal_name, source));
                    }
                    values[12] = value(changed_initial);

                    assert!(require_delivery(&values, fragment.as_bytes()).is_err());
                    assert!(
                        require_other_normal_manifest_sources(
                            &normal_properties(changed_normal),
                            fragment.as_bytes()
                        )
                        .is_err()
                    );
                }
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
