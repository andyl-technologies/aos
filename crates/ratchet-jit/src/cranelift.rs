//! Cranelift dependency pin metadata for the safe JIT precursor.
//!
//! This module records the Cranelift codegen version that the current CLIF
//! signature and body-lowering slices are validated against. It is metadata
//! only: it does not construct a JIT module, allocate executable memory, or
//! register runtime symbols.

/// The exact `cranelift-codegen` crate version required by this JIT slice.
pub const PINNED_CRANELIFT_CODEGEN_VERSION: &str = "0.127.4";

/// The `cranelift-codegen` crate version linked into this build.
pub const ACTIVE_CRANELIFT_CODEGEN_VERSION: &str = cranelift_codegen::VERSION;

/// The Cranelift dependency pin visible to JIT setup code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JitCraneliftDependencyPin {
    codegen_version: &'static str,
}

impl JitCraneliftDependencyPin {
    /// Creates dependency-pin metadata from an exact Cranelift codegen version.
    pub const fn new(codegen_version: &'static str) -> Self {
        Self { codegen_version }
    }

    /// Returns the pinned `cranelift-codegen` crate version.
    pub const fn codegen_version(self) -> &'static str {
        self.codegen_version
    }
}

/// Returns the Cranelift dependency pin for this build.
pub const fn jit_cranelift_dependency_pin() -> JitCraneliftDependencyPin {
    JitCraneliftDependencyPin::new(PINNED_CRANELIFT_CODEGEN_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_cranelift_codegen_version_matches_pin() {
        assert_eq!(
            ACTIVE_CRANELIFT_CODEGEN_VERSION,
            PINNED_CRANELIFT_CODEGEN_VERSION
        );
    }

    #[test]
    fn dependency_pin_exposes_exact_codegen_version() {
        let pin = jit_cranelift_dependency_pin();

        assert_eq!(pin.codegen_version(), PINNED_CRANELIFT_CODEGEN_VERSION);
    }
}
