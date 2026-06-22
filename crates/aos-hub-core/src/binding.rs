//! Storage-binding kinds and the per-runtime capability model (RFC-0004).
//!
//! A *storage binding* is a per-org named storage backend that a managed
//! registry or cache roots its surface on. The on-disk/wire form of a binding's
//! backend type is a short string in the `kind` column of `storage_bindings`;
//! this module gives that string a typed face ([`BindingKind`]) and pins the
//! authoritative set of strings (`local_fs`, `s3`, `r2`).
//!
//! # The capability model
//!
//! Not every binding kind makes sense in every place the hub runs. The hub is
//! deployed two ways, and each has a different storage substrate:
//!
//! - The **native** `aos-hub` binary can serve a surface from the local
//!   filesystem (`local_fs`) — a directory on the host.
//! - The **Worker** runtime (`wasm32-unknown-unknown` on Cloudflare) has no
//!   filesystem, so `local_fs` is meaningless there; its built-in object store
//!   is the deployment's R2 bucket, used automatically as the default storage
//!   (not a custom binding).
//!
//! Both runtimes can serve an **external, S3-compatible object store** (`s3` or
//! `r2`) — Amazon S3, Cloudflare R2 via its S3 API, MinIO, and so on. There is
//! no runtime-specific SDK involved: the shared
//! [`S3Surface`](crate::s3surface::S3Surface) mints SigV4-presigned URLs (pure,
//! `wasm`-clean signing) and each runtime makes a plain HTTP request to them, so
//! `s3`/`r2` bindings work identically on the native hub and the Worker.
//!
//! [`RuntimeKind`] models the one real split — the local filesystem. The
//! capability set that matters is always the **serving** runtime's: the Worker
//! rejects a `local_fs` binding, regardless of which surface (CLI, WebUI, or RPC)
//! the binding was authored through. Enforcement lives in the serving process
//! (the `create_binding` RPC and the WebUI handler call [`RuntimeKind::current`]);
//! the shared database layer and the offline CLI only validate that a kind is
//! *known*.
//!
//! ```text
//!                 local_fs   s3   r2
//!   native           ok      ok   ok
//!   worker           --      ok   ok
//! ```

/// A storage backend kind a binding can target.
///
/// The string form (see [`BindingKind::as_str`]) is the value persisted in the
/// `storage_bindings.kind` column and carried on the wire in the proto
/// `Binding`/`CreateBindingRequest` messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingKind {
    /// A directory on the host filesystem (native runtime only).
    LocalFs,
    /// An Amazon S3 bucket/prefix.
    S3,
    /// A Cloudflare R2 bucket/prefix (Worker runtime only).
    R2,
}

impl BindingKind {
    /// Every binding kind, in a stable order.
    ///
    /// Used to drive exhaustive UI/validation listings.
    pub const ALL: [BindingKind; 3] = [BindingKind::LocalFs, BindingKind::S3, BindingKind::R2];

    /// Parses a wire/storage kind string into a [`BindingKind`].
    ///
    /// Recognizes exactly `"local_fs"`, `"s3"`, and `"r2"`; any other input
    /// (including differing case or surrounding whitespace) yields `None`.
    pub fn parse(s: &str) -> Option<BindingKind> {
        match s {
            "local_fs" => Some(BindingKind::LocalFs),
            "s3" => Some(BindingKind::S3),
            "r2" => Some(BindingKind::R2),
            _ => None,
        }
    }

    /// Returns the canonical wire/storage string for this kind.
    ///
    /// This is the value written to `storage_bindings.kind` and round-trips
    /// through [`BindingKind::parse`].
    pub fn as_str(&self) -> &'static str {
        match self {
            BindingKind::LocalFs => "local_fs",
            BindingKind::S3 => "s3",
            BindingKind::R2 => "r2",
        }
    }

    /// Returns a human-facing label for this kind, for UI display.
    pub fn label(&self) -> &'static str {
        match self {
            BindingKind::LocalFs => "local filesystem",
            BindingKind::S3 => "Amazon S3",
            BindingKind::R2 => "Cloudflare R2",
        }
    }

    /// Reports whether this kind targets an external S3-compatible object store
    /// (`s3`/`r2`) and therefore needs origin configuration — an endpoint URL and
    /// (for a private binding) credentials.
    ///
    /// [`LocalFs`](BindingKind::LocalFs) returns `false` (a host path is all it
    /// needs); [`S3`](BindingKind::S3) and [`R2`](BindingKind::R2) return `true`.
    /// The WebUI uses this to decide whether to show the endpoint/credentials
    /// fields, and the provisioner to decide whether to require and seal them.
    pub fn requires_origin_config(&self) -> bool {
        matches!(self, BindingKind::S3 | BindingKind::R2)
    }
}

/// The runtime the hub is being served from.
///
/// Determines which [`BindingKind`]s are usable; see the [module
/// docs](self#the-capability-model).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeKind {
    /// The native `aos-hub` binary, with a host filesystem.
    Native,
    /// The Cloudflare Worker (`wasm32-unknown-unknown`), with R2 object storage.
    Worker,
}

impl RuntimeKind {
    /// Returns the runtime this code is compiled for.
    ///
    /// Resolves to [`RuntimeKind::Worker`] when compiled for
    /// `wasm32-unknown-unknown` and [`RuntimeKind::Native`] otherwise. Because
    /// the determination is by `cfg`, the result reflects the actual serving
    /// process and is safe to gate capability enforcement on.
    pub fn current() -> RuntimeKind {
        #[cfg(target_arch = "wasm32")]
        {
            RuntimeKind::Worker
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            RuntimeKind::Native
        }
    }

    /// Returns the short name of this runtime (`"native"` or `"worker"`).
    pub fn name(&self) -> &'static str {
        match self {
            RuntimeKind::Native => "native",
            RuntimeKind::Worker => "worker",
        }
    }

    /// Returns the binding kinds supported on this runtime.
    ///
    /// The native runtime supports all three (`local_fs`, `s3`, `r2`); the Worker
    /// runtime supports `s3` and `r2` but not `local_fs` (it has no filesystem).
    /// External `s3`/`r2` bindings are served via presigned URLs, so neither
    /// needs a runtime-specific object-store SDK.
    pub fn supported_binding_kinds(&self) -> &'static [BindingKind] {
        match self {
            RuntimeKind::Native => &[BindingKind::LocalFs, BindingKind::S3, BindingKind::R2],
            RuntimeKind::Worker => &[BindingKind::S3, BindingKind::R2],
        }
    }

    /// Reports whether `kind` is usable on this runtime.
    pub fn supports(&self, kind: BindingKind) -> bool {
        self.supported_binding_kinds().contains(&kind)
    }

    /// Returns the binding kinds an operator can create on this runtime — the
    /// kinds the WebUI offers in the create-binding form.
    ///
    /// Every [supported](Self::supports) kind is creatable: `local_fs` on the
    /// [`Native`](RuntimeKind::Native) hub, and `s3`/`r2` on both runtimes (an
    /// external object store reached via presigned URLs). This is *in addition*
    /// to the deployment's zero-config default storage, which needs no binding at
    /// all.
    pub fn creatable_binding_kinds(&self) -> Vec<BindingKind> {
        self.supported_binding_kinds().to_vec()
    }

    /// Returns a human-facing description of this runtime's *default* storage —
    /// the backend new registries use automatically, with no binding.
    ///
    /// The [`Worker`](RuntimeKind::Worker) serves from its deployment R2 bucket;
    /// the [`Native`](RuntimeKind::Native) hub from its configured default
    /// storage root.
    pub fn default_storage_label(&self) -> &'static str {
        match self {
            RuntimeKind::Native => "this deployment's default storage",
            RuntimeKind::Worker => "Cloudflare R2 (this deployment)",
        }
    }

    /// Returns the backend kind string of this runtime's default storage —
    /// `local_fs` for the native hub's default storage root, `r2` for the
    /// Worker's deployment bucket.
    ///
    /// Used to render the always-present default storage as a row in the
    /// bindings table, alongside any custom bindings.
    pub fn default_storage_kind(&self) -> &'static str {
        match self {
            RuntimeKind::Native => "local_fs",
            RuntimeKind::Worker => "r2",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips_through_as_str() {
        for kind in BindingKind::ALL {
            assert_eq!(BindingKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn parse_rejects_unknown_and_non_canonical() {
        assert_eq!(BindingKind::parse(""), None);
        assert_eq!(BindingKind::parse("LOCAL_FS"), None);
        assert_eq!(BindingKind::parse(" s3"), None);
        assert_eq!(BindingKind::parse("gcs"), None);
    }

    #[test]
    fn only_object_stores_require_origin_config() {
        assert!(!BindingKind::LocalFs.requires_origin_config());
        assert!(BindingKind::S3.requires_origin_config());
        assert!(BindingKind::R2.requires_origin_config());
    }

    #[test]
    fn creatable_kinds_equal_supported_kinds() {
        // Native can create all three; the Worker can create the two object-store
        // kinds (no filesystem).
        assert_eq!(
            RuntimeKind::Native.creatable_binding_kinds(),
            vec![BindingKind::LocalFs, BindingKind::S3, BindingKind::R2]
        );
        assert_eq!(
            RuntimeKind::Worker.creatable_binding_kinds(),
            vec![BindingKind::S3, BindingKind::R2]
        );
        // Every creatable kind is supported by its runtime.
        for rt in [RuntimeKind::Native, RuntimeKind::Worker] {
            for kind in rt.creatable_binding_kinds() {
                assert!(rt.supports(kind));
            }
        }
    }

    #[test]
    fn all_lists_each_kind_once() {
        assert_eq!(BindingKind::ALL.len(), 3);
        assert!(BindingKind::ALL.contains(&BindingKind::LocalFs));
        assert!(BindingKind::ALL.contains(&BindingKind::S3));
        assert!(BindingKind::ALL.contains(&BindingKind::R2));
    }

    #[test]
    fn each_kind_has_a_label() {
        for kind in BindingKind::ALL {
            assert!(!kind.label().is_empty());
        }
    }

    #[test]
    fn runtime_names_are_distinct() {
        assert_eq!(RuntimeKind::Native.name(), "native");
        assert_eq!(RuntimeKind::Worker.name(), "worker");
    }

    #[test]
    fn native_supports_all_kinds() {
        let rt = RuntimeKind::Native;
        assert!(rt.supports(BindingKind::LocalFs));
        assert!(rt.supports(BindingKind::S3));
        assert!(rt.supports(BindingKind::R2));
    }

    #[test]
    fn worker_supports_object_stores_only() {
        let rt = RuntimeKind::Worker;
        assert!(rt.supports(BindingKind::R2));
        assert!(rt.supports(BindingKind::S3));
        assert!(!rt.supports(BindingKind::LocalFs));
    }

    #[test]
    fn supported_kinds_match_supports() {
        for rt in [RuntimeKind::Native, RuntimeKind::Worker] {
            for kind in BindingKind::ALL {
                assert_eq!(
                    rt.supports(kind),
                    rt.supported_binding_kinds().contains(&kind)
                );
            }
        }
    }

    #[test]
    fn current_reflects_compile_target() {
        let rt = RuntimeKind::current();
        #[cfg(target_arch = "wasm32")]
        assert_eq!(rt, RuntimeKind::Worker);
        #[cfg(not(target_arch = "wasm32"))]
        assert_eq!(rt, RuntimeKind::Native);
    }
}
