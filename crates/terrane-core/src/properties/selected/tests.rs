//! Checks explicit selected structural bindings without manufacturing authority.

use super::*;
use alloc::vec;

fn defaults() -> Defaults<'static> {
    Defaults {
        store: "authority",
        private_domain: "private:test",
        home: "local",
    }
}

fn binding(byte: u8) -> alloc::vec::Vec<u8> {
    let mut value = alloc::vec::Vec::new();
    crate::cbor::write_map(&mut value, 1);
    crate::cbor::write_text(&mut value, "uid");
    crate::cbor::write_text(&mut value, &alloc::format!("{byte:02x}").repeat(32));
    IndexRoots::decode_value(&value)
        .unwrap_or_else(|error| panic!("canonical fixture index value: {error:?}"))
        .encode_binding()
        .unwrap_or_else(|error| panic!("canonical fixture index binding: {error:?}"))
}

#[test]
fn selected_active_binding_is_owner_local_and_ordinary_overrides_remain_effective() {
    let a = binding(1);
    let b = binding(2);
    let ancestor = [Property {
        name: "index-roots",
        value: &a,
    }];
    let own = [Property {
        name: "index-roots",
        value: &b,
    }];
    let layers = [
        RootLayer {
            properties: &ancestor,
            overrides: &[],
        },
        RootLayer {
            properties: &[],
            overrides: &[],
        },
    ];
    let effective = Selection::Active
        .resolve(&layers, defaults())
        .unwrap_or_else(|error| panic!("active inherited fixture policy: {error:?}"));
    assert!(effective.active_index_roots().is_none());
    let ordinary_override = [Property {
        name: "domain",
        value: b"\x66public",
    }];
    let layers = [RootLayer {
        properties: &own,
        overrides: &ordinary_override,
    }];
    let effective = Selection::Active
        .resolve(&layers, defaults())
        .unwrap_or_else(|error| panic!("active owner fixture policy: {error:?}"));
    assert_eq!(
        effective
            .active_index_roots()
            .unwrap_or_else(|| panic!("active owner fixture retains its index binding"))
            .get("uid"),
        IndexRoots::decode_binding(&b)
            .unwrap_or_else(|error| panic!("canonical expected index binding: {error:?}"))
            .get("uid")
    );
    assert_eq!(
        effective.get(PropertyName::Domain),
        Some(&Value::Text("public"))
    );
    assert!(Selection::Legacy.resolve(&layers, defaults()).is_err());
    let forbidden = [RootLayer {
        properties: &ancestor,
        overrides: &own,
    }];
    assert_eq!(
        Selection::Active.resolve(&forbidden, defaults()),
        Err(Error::InvalidValue)
    );
}

#[test]
fn selected_active_namespace_rejects_gap_and_inherited_or_malformed_pointer() {
    let value = binding(1);
    let mut inherited = value.clone();
    assert_eq!(inherited.last(), Some(&0xf4));
    let inherit_flag = inherited
        .last_mut()
        .unwrap_or_else(|| panic!("canonical fixture binding contains its inherit flag"));
    *inherit_flag = 0xf5;
    for (name, value, expected) in [
        ("index-gaps", value.as_slice(), Error::InvalidValue),
        ("index-roots", inherited.as_slice(), Error::InvalidValue),
        (
            "index-roots",
            &[0xff],
            Error::Cbor(crate::cbor::Error::Unsupported),
        ),
    ] {
        let properties = vec![Property { name, value }];
        let result = Selection::Active.resolve(
            &[RootLayer {
                properties: &properties,
                overrides: &[],
            }],
            defaults(),
        );
        assert_eq!(result, Err(expected));
    }
}
