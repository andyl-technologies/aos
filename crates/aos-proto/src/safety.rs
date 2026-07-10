//! Unsafe-discipline manifest for generated Buffa protocol witnesses.
//!
//! Buffa 0.3 emits unsafe implementations for its sealed default-instance
//! witness traits. The implementations contain no unsafe blocks; their safety
//! contract is owned by the generator and Buffa runtime. The crate root keeps
//! the exception on one private generated module while this manifest pins the
//! exact generated operation count and accepted trait families.

/// Crate-level lint required outside the generated protocol module.
pub const PROTO_UNSAFE_CRATE_LINT: &str = "#![deny(unsafe_code)]";

/// Scoped lint exception required on the generated protocol module.
pub const PROTO_GENERATED_UNSAFE_ALLOW: &str = "#[allow(unsafe_code)]";

/// Generated witness implementations that Buffa marks unsafe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtoGeneratedUnsafeOperation {
    /// Publishes a process-lifetime default owned message instance.
    OwnedDefaultInstance,
    /// Publishes a process-lifetime default borrowed message view.
    DefaultViewInstance,
    /// Associates a borrowed message view with its process-lifetime form.
    ViewLifetimeWitness,
}

/// Standing controls for the generated protocol unsafe exception.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtoUnsafeDiscipline {
    crate_lint: &'static str,
    generated_allow: &'static str,
    generator_owned_only: bool,
    second_reviewer_required: bool,
    operations: &'static [ProtoGeneratedUnsafeOperation],
}

impl ProtoUnsafeDiscipline {
    /// Creates the standing generated-protocol unsafe manifest.
    pub const fn new(
        crate_lint: &'static str,
        generated_allow: &'static str,
        generator_owned_only: bool,
        second_reviewer_required: bool,
        operations: &'static [ProtoGeneratedUnsafeOperation],
    ) -> Self {
        Self {
            crate_lint,
            generated_allow,
            generator_owned_only,
            second_reviewer_required,
            operations,
        }
    }

    /// Returns the lint required for hand-written protocol code.
    pub const fn crate_lint(self) -> &'static str {
        self.crate_lint
    }

    /// Returns the single scoped exception accepted for generated code.
    pub const fn generated_allow(self) -> &'static str {
        self.generated_allow
    }

    /// Returns whether every accepted unsafe operation must be generator-owned.
    pub const fn generator_owned_only(self) -> bool {
        self.generator_owned_only
    }

    /// Returns whether generator or unsafe-inventory changes require a second reviewer.
    pub const fn second_reviewer_required(self) -> bool {
        self.second_reviewer_required
    }

    /// Returns the generated unsafe operation classes accepted by this crate.
    pub const fn operations(self) -> &'static [ProtoGeneratedUnsafeOperation] {
        self.operations
    }
}

const PROTO_GENERATED_UNSAFE_OPERATIONS: &[ProtoGeneratedUnsafeOperation] = &[
    ProtoGeneratedUnsafeOperation::OwnedDefaultInstance,
    ProtoGeneratedUnsafeOperation::DefaultViewInstance,
    ProtoGeneratedUnsafeOperation::ViewLifetimeWitness,
];

/// Returns the standing unsafe-discipline manifest for `aos-proto`.
pub const fn proto_unsafe_discipline() -> ProtoUnsafeDiscipline {
    ProtoUnsafeDiscipline::new(
        PROTO_UNSAFE_CRATE_LINT,
        PROTO_GENERATED_UNSAFE_ALLOW,
        true,
        true,
        PROTO_GENERATED_UNSAFE_OPERATIONS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATED_SOURCES: &[(&str, &str, usize)] = &[
        (
            "aos.auth.v1.auth.rs",
            include_str!(concat!(env!("OUT_DIR"), "/aos.auth.v1.auth.rs")),
            6,
        ),
        (
            "aos.build.v1.build.rs",
            include_str!(concat!(env!("OUT_DIR"), "/aos.build.v1.build.rs")),
            9,
        ),
        (
            "aos.cache.v1.cache.rs",
            include_str!(concat!(env!("OUT_DIR"), "/aos.cache.v1.cache.rs")),
            36,
        ),
        (
            "aos.gc.v1.gc.rs",
            include_str!(concat!(env!("OUT_DIR"), "/aos.gc.v1.gc.rs")),
            9,
        ),
    ];

    #[test]
    fn discipline_manifest_names_required_controls() {
        let discipline = proto_unsafe_discipline();

        assert_eq!(discipline.crate_lint(), PROTO_UNSAFE_CRATE_LINT);
        assert_eq!(discipline.generated_allow(), PROTO_GENERATED_UNSAFE_ALLOW);
        assert!(discipline.generator_owned_only());
        assert!(discipline.second_reviewer_required());
        assert_eq!(discipline.operations(), PROTO_GENERATED_UNSAFE_OPERATIONS);
    }

    #[test]
    fn crate_root_confines_generated_unsafe_exception() {
        let crate_root = include_str!("lib.rs");

        assert!(crate_root.contains(PROTO_UNSAFE_CRATE_LINT));
        assert_eq!(crate_root.matches(PROTO_GENERATED_UNSAFE_ALLOW).count(), 1);
    }

    #[test]
    fn generated_unsafe_witness_inventory_is_pinned() {
        for (path, source, expected_count) in GENERATED_SOURCES {
            let unsafe_lines: Vec<_> = source
                .lines()
                .filter(|line| {
                    line.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                        .any(|token| token == "unsafe")
                })
                .collect();

            assert_eq!(
                unsafe_lines.len(),
                *expected_count,
                "{path} generated unsafe inventory changed"
            );
            for line in unsafe_lines {
                let line = line.trim_start();
                assert!(
                    line.starts_with("unsafe impl ::buffa::DefaultInstance for ")
                        || line.starts_with("unsafe impl ::buffa::DefaultViewInstance for ")
                        || line.starts_with("unsafe impl<'a> ::buffa::HasDefaultViewInstance for "),
                    "{path} contains an unreviewed generated unsafe operation: {line}"
                );
            }
        }
    }
}
