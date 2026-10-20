//! Constructs local/remote original-control unions and complete nested imports.
//!
//! ```text
//! local = [1, id, root, domain, dev, ino, coord_dev, coord_ino, control]
//! remote = [2, id, domain, remote_binding, control]
//! import = [1 | 2, registration, bootstrap, association]
//! ```

use super::{
    bindings,
    wire::{self, Value, a, b, bytes, s, u},
};
use terrane_format::gc::publication::evidence::*;

/// Constructs every registered local original field as inert data.
pub(super) fn local() -> LocalOriginalRegistration {
    LocalOriginalRegistration {
        original_id: [1; 32],
        root: b"/r".to_vec(),
        domain: "public".into(),
        root_device: 1,
        root_inode: 2,
        coordination_device: 3,
        coordination_inode: 4,
        control: b"/c".to_vec(),
    }
}

/// Constructs a public physical union without obtaining original authority.
pub(super) fn physical(kind: &str) -> PhysicalRegistration {
    if kind == "local" {
        PhysicalRegistration::Local(local())
    } else {
        PhysicalRegistration::Remote(RemoteOriginalRegistration {
            original_id: [1; 32],
            domain: "public".into(),
            binding: bindings::model(kind),
            control: b"original/\0".to_vec(),
        })
    }
}

/// Constructs primitive fields for each physical alternative independently.
pub(super) fn physical_wire(kind: &str) -> Value {
    if kind == "local" {
        a(vec![
            u(1),
            b(1, 32),
            bytes(b"/r"),
            s("public"),
            u(1),
            u(2),
            u(3),
            u(4),
            bytes(b"/c"),
        ])
    } else {
        a(vec![
            u(2),
            b(1, 32),
            s("public"),
            bindings::primitive(kind),
            bytes(b"original/\0"),
        ])
    }
}

/// Constructs ordered grants, including repeated principals and zero/all verbs.
pub(super) fn acl() -> AuthorityAcl {
    vec![
        AuthorityGrant {
            principal: "principal".into(),
            verbs: 0,
        },
        AuthorityGrant {
            principal: "principal".into(),
            verbs: 31,
        },
        AuthorityGrant {
            principal: "group".into(),
            verbs: 2,
        },
    ]
}

/// Constructs primitive ordered grant tuples.
pub(super) fn acl_wire() -> Value {
    a(vec![
        a(vec![s("principal"), u(0)]),
        a(vec![s("principal"), u(31)]),
        a(vec![s("group"), u(2)]),
    ])
}

/// Constructs all public bootstrap fields independently.
pub(super) fn bootstrap(empty: bool) -> OriginalBootstrap {
    OriginalBootstrap {
        original_id: [1; 32],
        ref_name: super::publication::NAME.into(),
        epoch: 3,
        acl: if empty { vec![] } else { acl() },
    }
}

/// Constructs primitive bootstrap fields independently.
pub(super) fn bootstrap_wire(empty: bool) -> Value {
    a(vec![
        u(1),
        b(1, 32),
        s(super::publication::NAME),
        u(3),
        if empty { a(vec![]) } else { acl_wire() },
    ])
}

/// Constructs every ordinary claimed signed-commit association field.
pub(super) fn association() -> OriginalAssociation {
    OriginalAssociation {
        commit: [2; 32],
        original_id: [1; 32],
        ref_name: super::publication::NAME.into(),
        epoch: 3,
    }
}

/// Constructs primitive association fields independently.
pub(super) fn association_wire() -> Value {
    a(vec![
        u(1),
        b(2, 32),
        b(1, 32),
        s(super::publication::NAME),
        u(3),
    ])
}

/// Constructs a complete typed import, preserving registered version selection.
pub(super) fn imported(kind: &str, version: u64) -> OriginalImport {
    OriginalImport {
        version: if version == 1 {
            ImportVersion::LocalV1
        } else {
            ImportVersion::PhysicalV2
        },
        registration: physical(kind),
        bootstrap: bootstrap(false),
        association: association(),
    }
}

/// Constructs primitive import fields without invoking an import codec.
pub(super) fn import_wire(kind: &str, version: u64) -> Value {
    a(vec![
        u(version),
        physical_wire(kind),
        bootstrap_wire(false),
        association_wire(),
    ])
}

/// Constructs sorted opaque historical issuer keys with both retirement states.
pub(super) fn issuers() -> Vec<IssuerRow> {
    vec![
        IssuerRow {
            issuer: "issuer".into(),
            key_id: "a".into(),
            public_key: [5; 32],
            retired_at: None,
        },
        IssuerRow {
            issuer: "issuer".into(),
            key_id: "b".into(),
            public_key: [6; 32],
            retired_at: Some(0),
        },
    ]
}

/// Constructs primitive issuer rows independently.
pub(super) fn issuers_wire() -> Value {
    a(vec![
        a(vec![s("issuer"), s("a"), b(5, 32), Value::Null]),
        a(vec![s("issuer"), s("b"), b(6, 32), u(0)]),
    ])
}

/// Constructs complete opaque repository roles with open and closed intervals.
pub(super) fn disclosures() -> Vec<DisclosureRow> {
    vec![
        DisclosureRow {
            repository: "01".repeat(32),
            domain: "public".into(),
            public_key: [7; 32],
            not_before: 0,
            not_after: None,
        },
        DisclosureRow {
            repository: "01".repeat(32),
            domain: "public".into(),
            public_key: [8; 32],
            not_before: 1,
            not_after: Some(2),
        },
    ]
}

/// Constructs primitive disclosure rows independently.
pub(super) fn disclosures_wire() -> Value {
    a(vec![
        a(vec![
            s("01".repeat(32)),
            s("public"),
            b(7, 32),
            u(0),
            Value::Null,
        ]),
        a(vec![s("01".repeat(32)), s("public"), b(8, 32), u(1), u(2)]),
    ])
}

/// Checks complete control models, raw import relationships and nested records.
///
/// # Panics
/// Panics if primitive, reference, owning wire or complete field comparisons fail.
pub(super) fn check_models() {
    let local = local();
    wire::check(
        "control-local-registration",
        local.clone(),
        physical_wire("local"),
        local.encode(),
        LocalOriginalRegistration::decode,
    );
    for kind in ["local", "s3", "gcs"] {
        let model = physical(kind);
        wire::check(
            &format!("control-physical-{kind}"),
            model.clone(),
            physical_wire(kind),
            model.encode(),
            PhysicalRegistration::decode,
        );
    }
    for empty in [true, false] {
        let model = bootstrap(empty);
        wire::check(
            if empty {
                "control-bootstrap-empty"
            } else {
                "control-bootstrap-full"
            },
            model.clone(),
            bootstrap_wire(empty),
            model.encode(),
            OriginalBootstrap::decode,
        );
    }
    let model = association();
    wire::check(
        "control-association",
        model.clone(),
        association_wire(),
        model.encode(),
        OriginalAssociation::decode,
    );
    for (kind, version) in [("local", 1), ("local", 2), ("s3", 2), ("gcs", 2)] {
        let label = format!("{kind}-v{version}");
        let model = imported(kind, version);
        let input = import_wire(kind, version);
        let digest = wire::raw(&input);
        wire::check(
            &format!("control-import-{label}"),
            model.clone(),
            input,
            model.encode(),
            OriginalImport::decode,
        );
        let model = OriginalImportBinding {
            commit: [2; 32],
            source: [1; 32],
            destination: [15; 32],
            import_digest: digest,
        };
        let input = a(vec![u(1), b(2, 32), b(1, 32), b(15, 32), bytes(digest)]);
        wire::check(
            &format!("control-import-binding-{label}"),
            model.clone(),
            input,
            model.encode(),
            OriginalImportBinding::decode,
        );
        let model = OriginalImportTrust {
            import_digest: digest,
            source: [1; 32],
            destination: [15; 32],
            issuers: issuers(),
            disclosures: disclosures(),
        };
        let input = a(vec![
            u(1),
            bytes(digest),
            b(1, 32),
            b(15, 32),
            issuers_wire(),
            disclosures_wire(),
        ]);
        wire::check(
            &format!("control-import-trust-{label}"),
            model.clone(),
            input,
            model.encode(),
            OriginalImportTrust::decode,
        );
    }
    for (index, model) in issuers().into_iter().enumerate() {
        let input = issuers_wire().array_mut()[index].clone();
        wire::check(
            &format!("control-issuer-{index}"),
            model.clone(),
            input,
            model.encode(),
            IssuerRow::decode,
        );
    }
    for (index, model) in disclosures().into_iter().enumerate() {
        let input = disclosures_wire().array_mut()[index].clone();
        wire::check(
            &format!("control-disclosure-{index}"),
            model.clone(),
            input,
            model.encode(),
            DisclosureRow::decode,
        );
    }
}
