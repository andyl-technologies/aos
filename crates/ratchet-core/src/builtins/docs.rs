//! Short user-facing documentation values attached to builtin declarations.

/// Short user-facing documentation for a builtin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuiltinDocs {
    pub(super) summary: &'static str,
}

impl BuiltinDocs {
    /// Returns the one-line summary for the builtin.
    #[allow(dead_code)]
    pub const fn summary(&self) -> &'static str {
        self.summary
    }
}

#[cfg(any(test, feature = "test-util"))]
pub(super) static TEST_BUILTIN_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Test builtin declaration.",
};

pub(super) static APPEND_CONTEXT_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns a string with reflected string context appended.",
};

pub(super) static ADD_ERROR_CONTEXT_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Adds a diagnostic context message to errors from an expression.",
};

pub(super) static CURRENT_SYSTEM_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the configured target system when available.",
};

pub(super) static HASH_FILE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the hex digest of a file's contents.",
};

pub(super) static GET_ENV_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns a configured environment variable or an empty string.",
};

pub(super) static GENERIC_CLOSURE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Computes the transitive closure of keyed attribute sets.",
};

pub(super) static FETCHURL_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Fetches a URL as a fixed-output store path.",
};

pub(super) static FETCH_GIT_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Fetches a pinned Git repository as a recursive fixed-output store path.",
};

pub(super) static FETCH_TARBALL_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Fetches and unpacks a tarball as a recursive fixed-output store path.",
};

pub(super) static FETCH_TREE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Fetches supported typed tree inputs as fixed-output store paths.",
};

pub(super) static FLAKE_REF_TO_STRING_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Converts flake-reference attrs to URL syntax.",
};

pub(super) static PARSE_FLAKE_REF_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Parses flake-reference URL syntax into attrs.",
};

pub(super) static LANG_VERSION_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the pinned Nix language version.",
};

pub(super) static NIX_VERSION_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the pinned C++ Nix version string.",
};

pub(super) static NIX_PATH_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the configured Nix search path entries.",
};

pub(super) static PATH_EXISTS_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns whether a path exists at evaluation time.",
};

pub(super) static PLACEHOLDER_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the Nix placeholder string for a derivation output.",
};

pub(super) static READ_DIR_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns an attribute set describing a directory's entries.",
};

pub(super) static READ_FILE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the contents of a file as a string.",
};

pub(super) static READ_FILE_TYPE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the filesystem type of a path.",
};

pub(super) static STORE_DIR_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns the configured Nix store directory.",
};

pub(super) static STORE_PATH_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Returns a store path as a context-carrying string.",
};

pub(super) static TO_PATH_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Coerces an absolute path-like value to a normalized string.",
};

pub(super) static TRY_EVAL_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Evaluates an expression to WHNF and reports catchable failures.",
};

pub(super) static TRACE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Prints a value to stderr and returns the second argument.",
};

pub(super) static TRACE_VERBOSE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Conditionally prints a value to stderr and returns the second argument.",
};

pub(super) static WARN_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Prints a warning to stderr and returns the second argument.",
};
