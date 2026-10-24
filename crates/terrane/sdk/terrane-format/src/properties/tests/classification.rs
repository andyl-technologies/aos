//! Checks typed classifier requirements through the public property APIs.

use super::*;

#[test]
fn required_attrs_structured_classification_rejects_invalid_inline_and_side_values() {
    let requirements = names(&["elf", "shebang"]);
    let map = [Property {
        name: "classify",
        value: &requirements,
    }];
    let policy = resolve(
        &[RootLayer {
            properties: &map,
            overrides: &[],
        }],
        defaults(),
    )
    .expect("classification policy");
    let sources = [Domain::Public];
    let elf_magic = text("elf");
    let shebang_magic = text("shebang");
    let valid_elf = [0xa5, 1, 0x18, 32, 2, 0x18, 62, 3, 2, 4, 0xf6, 5, 0x80];
    let valid_shebang = [0xa2, 1, 0x65, b'/', b't', b'o', b'o', b'l', 2, 0xf6];
    let invalid_class = [0xa5, 1, 16, 2, 0x18, 62, 3, 2, 4, 0xf6, 5, 0x80];
    let relative_interpreter = [0xa2, 1, 0x64, b't', b'o', b'o', b'l', 2, 0xf6];
    let mut trailing_elf = valid_elf.to_vec();
    trailing_elf.push(0xf6);

    for (case, magic, name, value) in [
        ("null ELF", elf_magic.as_slice(), "class.elf", &[0xf6][..]),
        (
            "invalid ELF class",
            elf_magic.as_slice(),
            "class.elf",
            &invalid_class[..],
        ),
        (
            "ELF with shebang schema",
            elf_magic.as_slice(),
            "class.elf",
            &valid_shebang[..],
        ),
        (
            "ELF trailing bytes",
            elf_magic.as_slice(),
            "class.elf",
            trailing_elf.as_slice(),
        ),
        (
            "null shebang",
            shebang_magic.as_slice(),
            "class.shebang",
            &[0xf6][..],
        ),
        (
            "relative interpreter",
            shebang_magic.as_slice(),
            "class.shebang",
            &relative_interpreter[..],
        ),
        (
            "shebang with ELF schema",
            shebang_magic.as_slice(),
            "class.shebang",
            &valid_elf[..],
        ),
    ] {
        for side in [false, true] {
            let mut entry = file();
            entry.attrs.push(Attribute {
                name: "class.magic",
                value: magic,
            });
            let detail = Attribute { name, value };
            let derived = if side {
                vec![DerivedAttribute {
                    object: [7; 32],
                    attribute: detail,
                }]
            } else {
                entry.attrs.push(detail);
                Vec::new()
            };
            let change = EntryChange {
                entry: &entry,
                properties: &policy,
                reference_domains: &sources,
                graft_properties: None,
            };

            assert_eq!(
                validate_commit(&[change], &derived),
                Err(Error::InvalidValue),
                "{case}, side={side}"
            );
            assert_eq!(
                completeness(&[(&entry, &policy)], PropertyName::Classify, &derived, &[]),
                Err(Error::InvalidValue),
                "{case}, side={side}"
            );
        }
    }
}

#[test]
fn required_attrs_structured_classification_accepts_valid_values_and_nonmatching_magic() {
    use crate::derived::{AttrRecord, AttributeName, AttributeValue};

    let requirements = names(&["elf", "shebang"]);
    let map = [Property {
        name: "classify",
        value: &requirements,
    }];
    let sources = [Domain::Public];
    let elf = [0xa5, 1, 0x18, 32, 2, 0x18, 62, 3, 2, 4, 0xf6, 5, 0x80];
    let shebang = [0xa2, 1, 0x65, b'/', b't', b'o', b'o', b'l', 2, 0xf6];

    for selection in [
        selected::Selection::Legacy,
        selected::Selection::Active,
        selected::Selection::Recorded(
            semantics::RecordedContext::new(2, 3, &["index-gaps"]).expect("recorded context"),
        ),
    ] {
        let policy = selection
            .resolve(
                &[RootLayer {
                    properties: &map,
                    overrides: &[],
                }],
                defaults(),
            )
            .expect("selected classifier policy");
        for (magic_name, name, bytes) in [
            ("elf", AttributeName::Elf, &elf[..]),
            ("shebang", AttributeName::Shebang, &shebang[..]),
        ] {
            let magic = text(magic_name);
            let value = AttributeValue::decode(name, bytes).expect("registered detail schema");
            let record = AttrRecord::new([7; 32], value, [9; 32]);
            let record = AttrRecord::decode(&record.encode().expect("canonical side carrier"))
                .expect("decode actual side carrier");
            assert_eq!(record.value.encode().expect("carrier value"), bytes);
            let detail = record.value.encode().expect("side detail");

            for side in [false, true] {
                let mut entry = file();
                entry.attrs.push(Attribute {
                    name: "class.magic",
                    value: &magic,
                });
                let attribute = Attribute {
                    name: name.as_str(),
                    value: &detail,
                };
                let derived = if side {
                    vec![DerivedAttribute {
                        object: record.object,
                        attribute,
                    }]
                } else {
                    entry.attrs.push(attribute);
                    Vec::new()
                };

                validate_commit(
                    &[EntryChange {
                        entry: &entry,
                        properties: &policy,
                        reference_domains: &sources,
                        graft_properties: None,
                    }],
                    &derived,
                )
                .expect("valid required classification");
                assert_eq!(
                    completeness(&[(&entry, &policy)], PropertyName::Classify, &derived, &[])
                        .expect("valid completeness"),
                    Completeness {
                        complete: 1,
                        incomplete: 0
                    }
                );
            }
        }

        let magic = text("text");
        let mut entry = file();
        entry.attrs.push(Attribute {
            name: "class.magic",
            value: &magic,
        });
        validate_commit(
            &[EntryChange {
                entry: &entry,
                properties: &policy,
                reference_domains: &sources,
                graft_properties: None,
            }],
            &[],
        )
        .expect("nonmatching magic needs no detail");
        assert_eq!(
            completeness(&[(&entry, &policy)], PropertyName::Classify, &[], &[])
                .expect("nonmatching completeness")
                .complete,
            1
        );
    }
}

#[test]
fn required_attrs_completeness_rejects_nonrequirement_properties_without_files() {
    let policy = resolve(&[], defaults()).expect("default policy");
    let mut directory = file();
    directory.kind = EntryKind::Directory { mode: 0o755 };

    for property in [
        PropertyName::Store,
        PropertyName::Domain,
        PropertyName::IndexRoots,
    ] {
        assert_eq!(
            completeness(&[], property, &[], &[]),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            completeness(&[(&directory, &policy)], property, &[], &[]),
            Err(Error::InvalidValue)
        );
    }
    for property in [
        PropertyName::Hashes,
        PropertyName::Classify,
        PropertyName::Index,
        PropertyName::StrictAttrs,
    ] {
        assert_eq!(
            completeness(&[], property, &[], &[]),
            Ok(Completeness::default())
        );
    }
}
