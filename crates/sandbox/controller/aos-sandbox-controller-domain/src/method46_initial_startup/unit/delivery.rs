//! Compares credential delivery against the Source-bound immutable unit bytes.
//!
//! The fixed mappings use canonical external system credential names.
//! Both retained PID1 samples must contain exactly those mappings and no other
//! credential mechanism. This borrowed comparison grants no key provenance,
//! floor decoding, writer or TPM authority; image composition must still bind
//! the selected sources to the normal owners and independent approval purpose.

use aos_systemd_client::{OwnedValue, Value};

use super::super::credentials::{
    METHOD46_INITIAL_ROOT_POLICY_PUBLIC_KEY_MEMBERS_V1 as ROOT_POLICY_MEMBERS,
    Method46InitialGenesisPublicPinV1 as GenesisMember,
    Method46InitialOwnerManifestV1 as OwnerManifest,
    Method46InitialPublicPinMemberV1 as PublicMember,
    Method46InitialPublicPinOwnerV1 as PublicOwner, NAMES, REQUIRED_CREDENTIAL_SLOTS,
};
use super::{Method46InitialServiceRoleV1, Method46InitialStartupClosedV1};

const SIGNATURES: [&str; 6] = ["a(ss)", "a(ss)", "a(say)", "a(say)", "as", "a(ss)"];
const ROOT_NOAPPLY_PUBLIC: &str = "root-noapply-floor-public";
const ROOT_NOAPPLY_PRIVATE: &str = "root-noapply-floor-signing";

fn canonical_system_source(source: &str) -> bool {
    source
        .strip_prefix("/run/credentials/@system/")
        .is_some_and(|name| {
            !name.is_empty()
                && name.len() <= 255
                && !matches!(name, "." | "..")
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
}

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
        if sources[index].is_some() || !canonical_system_source(source) {
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
        // Normal owners may share public raw32 policy pins or the two raw48
        // ONLINE issuers. Approval and private index auth cannot alias either.
        if selected[..index]
            .iter()
            .enumerate()
            .any(|(previous, value)| {
                *value == source
                    && !matches!((previous, index), (9, 15) | (27, 29) | (28, 30))
                    && !((16..27).contains(&previous) && (16..27).contains(&index))
                    && !([8, 32, 33, 34].contains(&previous) && [8, 32, 33, 34].contains(&index))
                    && !(previous == 4 && index == 35)
            })
        {
            return Err(Method46InitialStartupClosedV1);
        }
        selected[index] = source;
    }
    // The ONLINE issuer is a separate authority key, required exactly when
    // this actual Controller is configured with the Nix endpoint.
    if selected[8].is_empty() != selected[9].is_empty()
        || selected[8].is_empty() != selected[15].is_empty()
        || selected[8].is_empty() != selected[16].is_empty()
        || selected[20..24]
            .iter()
            .any(|source| source.is_empty() != selected[8].is_empty())
        || selected[32..35]
            .iter()
            .any(|source| source.is_empty() != selected[8].is_empty())
        || selected[27].is_empty() != selected[28].is_empty()
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
    require_owner_manifest_source(values, &sources, OwnerManifest::ControllerNixOnlineClient)?;
    require_policy_public_sources(values, fragment, PublicOwner::Controller)?;
    for member in GenesisMember::CONTROLLER {
        let expected = sources[member.slot()];
        require_source(
            values,
            member.name(),
            (!expected.is_empty()).then_some(expected),
        )?;
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
    for (index, member) in ROOT_POLICY_MEMBERS.into_iter().enumerate() {
        let expected = sources[24 + index];
        require_source(
            values,
            member.name(),
            (!expected.is_empty()).then_some(expected),
        )?;
    }
    for member in GenesisMember::ROOT {
        let expected = sources[member.slot()];
        require_source(
            values,
            member.name(),
            (!expected.is_empty()).then_some(expected),
        )?;
    }
    let public = sources[31];
    require_source(
        values,
        ROOT_NOAPPLY_PUBLIC,
        (!public.is_empty()).then_some(public),
    )?;
    if public.is_empty() {
        require_source(values, ROOT_NOAPPLY_PRIVATE, None)?;
    } else {
        // Compare only the native source name. The initializer never opens or
        // decodes Root's private credential. Root's paid signer binds its key
        // to the public copy before either finite signing purpose can run.
        let Value::Array(rows) = &**values.first().ok_or(Method46InitialStartupClosedV1)? else {
            return Err(Method46InitialStartupClosedV1);
        };
        let mut private = None;
        for row in rows.inner() {
            let Value::Structure(pair) = row else {
                return Err(Method46InitialStartupClosedV1);
            };
            let [Value::Str(name), Value::Str(source)] = pair.fields() else {
                return Err(Method46InitialStartupClosedV1);
            };
            if name.as_str() == ROOT_NOAPPLY_PRIVATE && private.replace(source.as_str()).is_some() {
                return Err(Method46InitialStartupClosedV1);
            }
        }
        let private = private.ok_or(Method46InitialStartupClosedV1)?;
        if private == public || !canonical_system_source(private) {
            return Err(Method46InitialStartupClosedV1);
        }
        require_named_source(values, ROOT_NOAPPLY_PRIVATE, private)?;
    }

    Ok(())
}

pub(super) fn require_normal_host_public_sources(
    values: &[OwnedValue],
    fragment: &[u8],
) -> Result<(), Method46InitialStartupClosedV1> {
    // Root receives this public source from the existing Host credential option.
    // The native Host sample must agree independently; Nix evaluation alone
    // cannot establish the live manager's actual credential configuration.
    let sources = selected_sources(fragment)?;
    require_owner_manifest_source(values, &sources, OwnerManifest::HostControllerBroker)?;
    let expected = sources[31];
    require_source(
        values,
        ROOT_NOAPPLY_PUBLIC,
        (!expected.is_empty()).then_some(expected),
    )
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
    require_named_source(values, "nix-online-floor-issuer-v1", expected)?;
    let sources = selected_sources(fragment)?;
    for member in OwnerManifest::NIX_OWNER {
        require_owner_manifest_source(values, &sources, member)?;
    }
    require_policy_public_sources(values, fragment, PublicOwner::NixBroker)
}

fn require_owner_manifest_source(
    values: &[OwnedValue],
    sources: &[&str; NAMES.len()],
    member: OwnerManifest,
) -> Result<(), Method46InitialStartupClosedV1> {
    let expected = sources[member.slot()];
    require_source(
        values,
        member.name(),
        (!expected.is_empty()).then_some(expected),
    )
}

fn require_policy_public_sources(
    values: &[OwnedValue],
    fragment: &[u8],
    owner: PublicOwner,
) -> Result<(), Method46InitialStartupClosedV1> {
    let sources = selected_sources(fragment)?;
    for member in PublicMember::ALL {
        let expected = sources[member.slot(owner)];
        require_source(
            values,
            member.name(),
            (!expected.is_empty()).then_some(expected),
        )?;
    }
    Ok(())
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
        let mut rows = [
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
        .collect::<Vec<_>>();
        rows.extend(owner_manifest_rows([
            OwnerManifest::ControllerNixOnlineClient,
        ]));
        rows.extend(policy_rows(PublicOwner::Controller));
        rows.extend(GenesisMember::CONTROLLER.into_iter().map(|member| {
            (
                member.name().to_owned(),
                format!("/run/credentials/@system/external-{}", member.slot()),
            )
        }));
        rows
    }

    fn root_extra_rows(selected: &[bool; NAMES.len()]) -> Vec<(String, String)> {
        let mut rows: Vec<_> = ROOT_POLICY_MEMBERS
            .into_iter()
            .enumerate()
            .map(|(index, member)| (member.name(), 24 + index))
            .chain(
                GenesisMember::ROOT
                    .into_iter()
                    .map(|member| (member.name(), member.slot())),
            )
            .chain([(ROOT_NOAPPLY_PUBLIC, 31)])
            .filter(|(_, slot)| selected[*slot])
            .map(|(name, slot)| {
                (
                    name.to_owned(),
                    format!("/run/credentials/@system/external-{slot}"),
                )
            })
            .collect();
        if selected[31] {
            rows.push((
                ROOT_NOAPPLY_PRIVATE.to_owned(),
                "/run/credentials/@system/private-root-noapply".to_owned(),
            ));
        }
        rows
    }

    fn policy_rows(owner: PublicOwner) -> Vec<(String, String)> {
        PublicMember::ALL
            .into_iter()
            .map(|member| {
                (
                    member.name().to_owned(),
                    format!("/run/credentials/@system/external-{}", member.slot(owner)),
                )
            })
            .collect()
    }

    fn owner_manifest_rows(
        members: impl IntoIterator<Item = OwnerManifest>,
    ) -> Vec<(String, String)> {
        members
            .into_iter()
            .map(|member| {
                (
                    member.name().to_owned(),
                    format!("/run/credentials/@system/external-{}", member.slot()),
                )
            })
            .collect()
    }

    fn nix_owner_rows() -> Vec<(String, String)> {
        let mut rows = vec![(
            "nix-online-floor-issuer-v1".to_owned(),
            "/run/credentials/@system/external-15".to_owned(),
        )];
        rows.extend(owner_manifest_rows(OwnerManifest::NIX_OWNER));
        rows.extend(policy_rows(PublicOwner::NixBroker));
        rows
    }

    #[test]
    fn owner_manifest_delivery_rejects_missing_duplicate_substituted_and_alternate_sources() {
        for member in OwnerManifest::ALL {
            let (rows, check): (
                _,
                fn(&[OwnedValue], &[u8]) -> Result<(), Method46InitialStartupClosedV1>,
            ) = match member {
                OwnerManifest::NixOwnerCatalog | OwnerManifest::NixOwnerOnlineBroker => {
                    (nix_owner_rows(), require_normal_nix_owner_source)
                }
                OwnerManifest::ControllerNixOnlineClient => {
                    (other_normal_rows(), require_other_normal_manifest_sources)
                }
                OwnerManifest::HostControllerBroker => {
                    let mut rows = owner_manifest_rows([member]);
                    rows.push((
                        ROOT_NOAPPLY_PUBLIC.to_owned(),
                        "/run/credentials/@system/external-31".to_owned(),
                    ));
                    (rows, require_normal_host_public_sources)
                }
            };
            let fragment = fragment();
            assert!(check(&normal_properties(rows.clone()), fragment.as_bytes()).is_ok());
            let index = rows
                .iter()
                .position(|(name, _)| name == member.name())
                .unwrap();
            let row = rows[index].clone();

            let mut missing = rows.clone();
            missing.remove(index);
            let mut duplicate = rows.clone();
            duplicate.push(row.clone());
            let mut substituted = rows.clone();
            substituted[index].1 = "/run/credentials/@system/foreign".to_owned();
            for changed in [missing, duplicate, substituted.clone()] {
                assert!(
                    check(&normal_properties(changed), fragment.as_bytes()).is_err(),
                    "{member:?}"
                );
            }

            // External copies need not share a source. The genuine initial
            // selection must instead match that owner's actual delivery.
            let changed_fragment = fragment.replace(
                &format!("@system/external-{}\n", member.slot()),
                "@system/foreign\n",
            );
            assert!(check(&normal_properties(substituted), changed_fragment.as_bytes()).is_ok());
            for (index, alternate) in [
                (1, value(vec![row.clone()])),
                (2, value(vec![(row.0.clone(), vec![1_u8])])),
                (3, value(vec![(row.0.clone(), vec![1_u8])])),
                (4, value(vec!["*".to_owned()])),
                (5, value(vec![("*".to_owned(), "*".to_owned())])),
            ] {
                let mut properties = normal_properties(rows.clone());
                properties[index] = alternate;
                assert!(
                    check(&properties, fragment.as_bytes()).is_err(),
                    "{member:?}"
                );
            }
        }
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

        for index in 0..12 {
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
            let mut rows = MEMBERS
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
            rows.extend(root_extra_rows(&selected));

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
        let mut rows = MEMBERS
            .into_iter()
            .enumerate()
            .map(|(index, member)| {
                (
                    member.name().to_owned(),
                    format!("/run/credentials/@system/external-{}", index + 10),
                )
            })
            .collect::<Vec<_>>();
        rows.extend(root_extra_rows(&[true; NAMES.len()]));
        for index in 0..rows.len() {
            let mut duplicate = rows.clone();
            duplicate.push(rows[index].clone());
            let mut substituted = rows.clone();
            if rows[index].0 == ROOT_NOAPPLY_PRIVATE {
                substituted[index].1 = "/foreign/private-source".to_owned();
            } else {
                substituted[index].1.push_str("-substituted");
            }
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
    fn host_noapply_pin_requires_exact_source_or_compared_absence() {
        let fragment = fragment();
        let without_pin = fragment
            .lines()
            .filter(|line| !line.starts_with(&format!("LoadCredential={}:", NAMES[31])))
            .collect::<Vec<_>>()
            .join("\n");
        let row = (
            ROOT_NOAPPLY_PUBLIC.to_owned(),
            "/run/credentials/@system/external-31".to_owned(),
        );

        for present in [false, true] {
            let selected = if present { &fragment } else { &without_pin };
            for delivered in [false, true] {
                let mut rows = owner_manifest_rows([OwnerManifest::HostControllerBroker]);
                if delivered {
                    rows.push(row.clone());
                }
                assert_eq!(
                    require_normal_host_public_sources(
                        &normal_properties(rows),
                        selected.as_bytes(),
                    )
                    .is_ok(),
                    present == delivered
                );
            }
            let duplicate = normal_properties(vec![row.clone(), row.clone()]);
            assert!(require_normal_host_public_sources(&duplicate, selected.as_bytes()).is_err());
            let substituted = normal_properties(vec![(
                ROOT_NOAPPLY_PUBLIC.to_owned(),
                "/run/credentials/@system/foreign-pin".to_owned(),
            )]);
            assert!(require_normal_host_public_sources(&substituted, selected.as_bytes()).is_err());
            for (index, alternate) in [
                (1, value(vec![row.clone()])),
                (2, value(vec![(ROOT_NOAPPLY_PUBLIC.to_owned(), vec![1_u8])])),
                (3, value(vec![(ROOT_NOAPPLY_PUBLIC.to_owned(), vec![1_u8])])),
                (4, value(vec!["*".to_owned()])),
                (5, value(vec![("*".to_owned(), "*".to_owned())])),
            ] {
                let mut rows = owner_manifest_rows([OwnerManifest::HostControllerBroker]);
                if present {
                    rows.push(row.clone());
                }
                let mut properties = normal_properties(rows);
                properties[index] = alternate;
                assert!(
                    require_normal_host_public_sources(&properties, selected.as_bytes()).is_err()
                );
            }
        }
    }

    #[test]
    fn root_noapply_delivery_requires_both_names_or_their_compared_absence() {
        use super::super::super::credentials::METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1 as MEMBERS;
        let fragment = fragment();
        let mut rows = MEMBERS
            .into_iter()
            .enumerate()
            .map(|(index, member)| {
                (
                    member.name().to_owned(),
                    format!("/run/credentials/@system/external-{}", index + 10),
                )
            })
            .collect::<Vec<_>>();
        rows.extend(root_extra_rows(&[true; NAMES.len()]));
        let without_pin = fragment
            .lines()
            .filter(|line| !line.starts_with(&format!("LoadCredential={}:", NAMES[31])))
            .collect::<Vec<_>>()
            .join("\n");

        for present in [false, true] {
            let selected = if present { &fragment } else { &without_pin };
            for public in [false, true] {
                for private in [false, true] {
                    let mut changed = rows.clone();
                    changed.retain(|(name, _)| {
                        (public || name != ROOT_NOAPPLY_PUBLIC)
                            && (private || name != ROOT_NOAPPLY_PRIVATE)
                    });
                    assert_eq!(
                        require_normal_root_public_sources(
                            &normal_properties(changed),
                            selected.as_bytes(),
                        )
                        .is_ok(),
                        public == present && private == present
                    );
                }
            }
        }

        for source in [
            "/run/credentials/@system/external-31",
            "/foreign/seed",
            "/run/credentials/@system/..",
        ] {
            let mut changed = rows.clone();
            changed
                .iter_mut()
                .find(|(name, _)| name == ROOT_NOAPPLY_PRIVATE)
                .unwrap()
                .1 = source.to_owned();
            assert!(
                require_normal_root_public_sources(
                    &normal_properties(changed),
                    fragment.as_bytes(),
                )
                .is_err()
            );
        }
        // The initial job never chooses the private source. A different valid
        // native source is allowed; Root itself must compare its actual bytes.
        rows.iter_mut()
            .find(|(name, _)| name == ROOT_NOAPPLY_PRIVATE)
            .unwrap()
            .1 = "/run/credentials/@system/another-private-root-source".to_owned();
        assert!(
            require_normal_root_public_sources(&normal_properties(rows), fragment.as_bytes(),)
                .is_ok()
        );
    }

    #[test]
    fn only_normal_public_pins_with_the_same_format_may_alias() {
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
                    matches!(
                        (source, destination),
                        (9, 15) | (15, 9) | (27, 29) | (29, 27) | (28, 30) | (30, 28)
                    ) || ((16..27).contains(&source) && (16..27).contains(&destination))
                        || ([8, 32, 33, 34].contains(&source)
                            && [8, 32, 33, 34].contains(&destination))
                        || matches!((source, destination), (4, 35) | (35, 4)),
                    "source {source} destination {destination}",
                );
            }
        }
    }

    #[test]
    fn root_policy_and_genesis_delivery_requires_exact_selected_presence() {
        use super::super::super::credentials::METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1 as MEMBERS;
        for mask in 0_u8..16 {
            let mut selected = [true; NAMES.len()];
            for (offset, slot) in (24..27).enumerate() {
                selected[slot] = mask & (1 << offset) != 0;
            }
            selected[27] = mask & 8 != 0;
            selected[28] = selected[27];
            let fragment = NAMES
                .iter()
                .enumerate()
                .filter(|(slot, _)| selected[*slot])
                .fold(String::from("[Service]\n"), |mut text, (slot, name)| {
                    text.push_str(&format!(
                        "LoadCredential={name}:/run/credentials/@system/external-{slot}\n"
                    ));
                    text
                });
            let mut rows = MEMBERS
                .into_iter()
                .enumerate()
                .map(|(index, member)| {
                    (
                        member.name().to_owned(),
                        format!("/run/credentials/@system/external-{}", index + 10),
                    )
                })
                .collect::<Vec<_>>();
            rows.extend(root_extra_rows(&selected));

            assert!(
                require_normal_root_public_sources(
                    &normal_properties(rows.clone()),
                    fragment.as_bytes()
                )
                .is_ok()
            );

            for (name, slot) in ROOT_POLICY_MEMBERS
                .into_iter()
                .enumerate()
                .map(|(index, member)| (member.name(), 24 + index))
                .chain(
                    GenesisMember::ROOT
                        .into_iter()
                        .map(|member| (member.name(), member.slot())),
                )
            {
                let mut changed = rows.clone();
                if selected[slot] {
                    changed.retain(|(actual, _)| actual != name);
                } else {
                    changed.push((
                        name.to_owned(),
                        format!("/run/credentials/@system/external-{slot}"),
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
        }
        for missing in [27, 28] {
            let mismatched = fragment()
                .lines()
                .filter(|line| !line.starts_with(&format!("LoadCredential={}:", NAMES[missing])))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(selected_credential_roster(mismatched.as_bytes()).is_err());
        }
    }

    #[test]
    fn configured_nix_requires_its_controller_floor_issuer_source() {
        for missing in [8, 9, 15, 16, 20, 21, 22, 23, 32, 33, 34] {
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
                &normal_properties(nix_owner_rows()),
                fragment.as_bytes(),
            )
            .is_ok()
        );

        // The same public ONLINE issuer may be delivered to both owners.
        let shared = fragment.replace("@system/external-15\n", "@system/external-9\n");
        let mut shared_rows = nix_owner_rows();
        shared_rows[0].1 = "/run/credentials/@system/external-9".to_owned();
        assert!(
            require_normal_nix_owner_source(&normal_properties(shared_rows), shared.as_bytes(),)
                .is_ok()
        );

        for index in 0..nix_owner_rows().len() {
            let mut missing = nix_owner_rows();
            missing.remove(index);
            let mut duplicate = nix_owner_rows();
            duplicate.push(duplicate[index].clone());
            let mut substituted = nix_owner_rows();
            substituted[index].1 = "/run/credentials/@system/foreign".to_owned();
            let mut renamed = nix_owner_rows();
            renamed[index].0 = "foreign-public-pin".to_owned();
            for rows in [missing, duplicate, substituted, renamed] {
                assert!(
                    require_normal_nix_owner_source(&normal_properties(rows), fragment.as_bytes())
                        .is_err()
                );
            }
        }
        for (index, changed) in [
            (1, value(vec![(expected.0.clone(), expected.1.clone())])),
            (2, value(vec![(expected.0.clone(), vec![1_u8])])),
            (3, value(vec![(expected.0.clone(), vec![1_u8])])),
            (4, value(vec!["*".to_owned()])),
            (5, value(vec![("*".to_owned(), "*".to_owned())])),
        ] {
            let mut values = normal_properties(nix_owner_rows());
            values[index] = changed;
            assert!(require_normal_nix_owner_source(&values, fragment.as_bytes()).is_err());
        }
    }

    #[test]
    fn disabled_controller_nix_endpoint_omits_both_online_issuers() {
        let fragment = fragment()
            .lines()
            .filter(|line| {
                ![8, 9, 15, 16, 20, 21, 22, 23, 32, 33, 34]
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
                selected[16] = nix;
                selected[20..24].fill(nix);
                selected[32..35].fill(nix);
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
                    .filter(|(name, _)| match name.as_str() {
                        "mount-fuse-manifest" => mount_fuse,
                        "nix-broker-session-manifest-v1"
                        | "nix-online-floor-issuer-v1"
                        | "nix-recipe-issuer-v2"
                        | "nix-online-client-manifest" => nix,
                        _ => true,
                    })
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
