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
        .unwrap()
        .encode_binding()
        .unwrap()
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
    let effective = Selection::Active.resolve(&layers, defaults()).unwrap();
    assert!(effective.active_index_roots().is_none());
    let ordinary_override = [Property {
        name: "domain",
        value: b"\x66public",
    }];
    let layers = [RootLayer {
        properties: &own,
        overrides: &ordinary_override,
    }];
    let effective = Selection::Active.resolve(&layers, defaults()).unwrap();
    assert_eq!(
        effective.active_index_roots().unwrap().get("uid"),
        IndexRoots::decode_binding(&b).unwrap().get("uid")
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
    *inherited.last_mut().unwrap() = 0xf5;
    for (name, value) in [
        ("index-gaps", value.as_slice()),
        ("index-roots", inherited.as_slice()),
        ("index-roots", &[0xff]),
    ] {
        let properties = vec![Property { name, value }];
        let result = Selection::Active.resolve(
            &[RootLayer {
                properties: &properties,
                overrides: &[],
            }],
            defaults(),
        );
        assert_eq!(result, Err(Error::InvalidValue));
    }
}
