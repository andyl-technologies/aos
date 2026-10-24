//! Constructs every backend-binding/activation alternative as ordinary fields.
//!
//! ```text
//! binding = [0, root, dev, ino, coord_dev, coord_ino]
//!         / [1, provider, [endpoint, bucket, prefix, nonce], [key, nonce]]
//! ```

use super::wire::{self, Value, a, b, bytes, m, s, u};
use terrane_format::gc::publication::{
    Activation, BackendBinding, BackendRegistration, RemoteProvider,
};

/// Constructs complete public binding fields without backend I/O or authority.
pub(super) fn model(kind: &str) -> BackendBinding {
    if kind == "local" {
        BackendBinding::Local {
            root: b"/a".to_vec(),
            root_device: 1,
            root_inode: 2,
            coordination_device: 3,
            coordination_inode: 4,
        }
    } else {
        BackendBinding::Remote {
            provider: if kind == "s3" {
                RemoteProvider::S3
            } else {
                RemoteProvider::Gcs
            },
            endpoint: "https://endpoint/É".into(),
            bucket: "bucket".into(),
            prefix: if kind == "s3" {
                vec![]
            } else {
                b"p/\xff".to_vec()
            },
            resource_nonce: [3; 32],
            coordination_key: b"coord/\0".to_vec(),
            coordination_nonce: [4; 32],
        }
    }
}

/// Constructs primitive binding fields separately from the public model.
pub(super) fn primitive(kind: &str) -> Value {
    if kind == "local" {
        a(vec![u(0), bytes(b"/a"), u(1), u(2), u(3), u(4)])
    } else {
        a(vec![
            u(1),
            s(kind),
            a(vec![
                s("https://endpoint/É"),
                s("bucket"),
                bytes(if kind == "s3" {
                    vec![]
                } else {
                    b"p/\xff".to_vec()
                }),
                b(3, 32),
            ]),
            a(vec![bytes(b"coord/\0"), b(4, 32)]),
        ])
    }
}

/// Checks all provider/activation alternatives against independent wires.
///
/// # Panics
/// Panics if a complete field or wire comparison fails.
pub(super) fn check_models() {
    for kind in ["local", "s3", "gcs"] {
        let binding = model(kind);
        wire::check(
            &format!("control-binding-{kind}"),
            binding.clone(),
            primitive(kind),
            binding.encode(),
            BackendBinding::decode,
        );
        for (label, activation, genesis) in [
            ("pending-null", Activation::Pending, None),
            ("pending-digest", Activation::Pending, Some([14; 32])),
            ("active", Activation::Active, Some([14; 32])),
        ] {
            let expected = BackendRegistration {
                binding: model(kind),
                activation,
                genesis,
            };
            let input = m(vec![
                (0, u(1)),
                (1, primitive(kind)),
                (2, u(u64::from(activation == Activation::Active))),
                (
                    3,
                    if genesis.is_some() {
                        b(14, 32)
                    } else {
                        Value::Null
                    },
                ),
            ]);
            wire::check(
                &format!("control-registration-{kind}-{label}"),
                expected.clone(),
                input,
                expected.encode(),
                BackendRegistration::decode,
            );
        }
    }
    let local = BackendBinding::Local {
        root: b"/".to_vec(),
        root_device: 0,
        root_inode: 23,
        coordination_device: 24,
        coordination_inode: u64::MAX,
    };
    wire::check(
        "control-binding-local-bounds",
        local.clone(),
        a(vec![u(0), bytes(b"/"), u(0), u(23), u(24), u(u64::MAX)]),
        local.encode(),
        BackendBinding::decode,
    );

    let remote = BackendBinding::Remote {
        provider: RemoteProvider::Gcs,
        endpoint: "é".repeat(2048),
        bucket: "b".repeat(4096),
        prefix: vec![0; 4096],
        resource_nonce: [3; 32],
        coordination_key: vec![0; 4096],
        coordination_nonce: [4; 32],
    };
    wire::check(
        "control-binding-remote-bounds",
        remote.clone(),
        a(vec![
            u(1),
            s("gcs"),
            a(vec![
                s("é".repeat(2048)),
                s("b".repeat(4096)),
                bytes(vec![0; 4096]),
                b(3, 32),
            ]),
            a(vec![bytes(vec![0; 4096]), b(4, 32)]),
        ]),
        remote.encode(),
        BackendBinding::decode,
    );
}
