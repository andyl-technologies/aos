//! Generates the `aos.hub.v1` message structs with `prost-build`.
//!
//! Unlike the sibling `aos-proto` crate (which runs `connectrpc-build` to emit
//! `buffa`-based types plus the ConnectRPC client/server), this crate generates
//! **only the message structs** — plain `prost` structs with `serde` derives —
//! so they compile to `wasm32-unknown-unknown` with no `connectrpc`/`buffa`/
//! `hyper`/`tokio` runtime. They are the Connect-JSON wire types shared by the
//! native hub, the Cloudflare Worker, and `aos-remote` (RFC-0004 Phase 5).
//!
//! The `.proto` source lives in `aos-proto`; this build reads it in place via a
//! workspace-relative path and re-runs whenever it changes.

fn main() {
    // Workspace-relative: the `.proto` schema is owned by the `aos-proto` crate.
    let proto_root = "../aos-proto/src/proto";
    let proto = format!("{proto_root}/aos/hub/v1/hub.proto");

    let mut config = prost_build::Config::new();
    // The structs are serialized as Connect-JSON request/response bodies; the
    // `prost` binary codec is incidental (unused on the wire).
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    // Canonical proto3-JSON field naming: a proto `org_slug` is `orgSlug` on the
    // wire. This is the Connect-JSON contract (what the old connectrpc server
    // emitted and what `aos hub`/`apm` + stock Connect clients expect), and since
    // the hub handlers, the Worker, and the `aos-remote` client all share these
    // structs, both ends stay consistent. RFC-0004 Phase 5.
    config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");
    // Tolerate absent fields on decode — a Connect-JSON request need not carry
    // every optional field, and responses evolve additively.
    // `default` is a message-container attribute. Applying it to every type
    // also reaches generated oneof enums, where serde rejects it.
    config.message_attribute(".", "#[serde(default)]");
    // Proto oneofs are fields in generated Rust, but canonical proto JSON
    // exposes the selected alternative directly inside its message. Flatten
    // `SurfaceRef.target` so the wire shape is
    // `{ "registrySlug": "acme/main" }`, not a Rust-internal `target` wrapper.
    config.field_attribute(".aos.hub.v1.SurfaceRef.target", "#[serde(flatten)]");

    config
        .compile_protos(&[&proto], &[proto_root])
        .expect("prost-build: failed to compile aos/hub/v1/hub.proto");

    println!("cargo:rerun-if-changed={proto}");
}
