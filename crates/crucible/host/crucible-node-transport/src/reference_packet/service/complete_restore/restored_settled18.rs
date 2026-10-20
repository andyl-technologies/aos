//! Names the explicit complete-state successors beside unchanged edition17.
//!
//! These identities distinguish the actual new Source once/first-proof and full
//! pending-state semantics. They advertise no implementation, negotiate no
//! feature and supply no decoder, live scope or native admission. A complete
//! defining contract and paired producer/reader must precede any advertisement.
//!
//! ```text
//! enclosing semantic18 = {schema, ancestry, node: Node18, source: Source18}
//! Source18 = {schema: source-restored-settled-state/18, ..., once: Once18}
//! Complete18 seventh bank = source-private.semantic-spend/18
//! ```
//!
//! The independently versioned native import17 domains and private wrapper9 do
//! not change merely because one of these component references is selected.

/// Names the separately declared successor recapture selection.
pub const RESTORED_SETTLED_RECAPTURE18_FEATURE: &str =
    "source-owned.packet-restored-settled-recapture/18";

/// Names the successor full immutable recapture definition.
pub const RESTORED_SETTLED_RECAPTURE18_CONTRACT_SCHEMA: &str =
    "source-owned.packet-restored-settled-recapture-contract/18";

/// Names the complete outer semantic component, including its embedded Node18.
pub const RESTORED_SETTLED_SEMANTIC18_SCHEMA: &str =
    "source-private.semantic-state-restored-settled/18";

/// Names the full immutable outer semantic body media.
pub const RESTORED_SETTLED_SEMANTIC18_MEDIA: &str =
    "application/vnd.source-owned.packet-semantic-custody.v18+json";

/// Names the inner Source object, distinct from the complete semantic body.
pub const RESTORED_SETTLED_SOURCE18_SCHEMA: &str =
    "source-private.source-restored-settled-state/18";

/// Names the separate new-family Source once and progress record.
pub const RESTORED_SETTLED_ONCE18_SCHEMA: &str = "source-private.source-restored-once/18";

/// Names the independently authenticated new-family first-observation record.
pub const RESTORED_SETTLED_FIRST_OBSERVATION18_SCHEMA: &str =
    "source-private.source-restored-first-observation-state/18";

/// Names the explicit full-state Node root with its actual twenty-five fields.
pub const RESTORED_SETTLED_NODE18_SCHEMA: &str = "source-owned.packet-restored-node-history/18";

/// Names the complete logical semantic-spend projection grammar.
pub const RESTORED_SETTLED_SEMANTIC_SPEND18_SCHEMA: &str = "source-private.semantic-spend/18";

/// Names the seventh body's distinct complete-state media.
pub const RESTORED_SETTLED_SEMANTIC_SPEND18_MEDIA: &str =
    "application/vnd.source-owned.packet-semantic-spend.v18+json";

/// Names a capture prefix enclosing actual successor Source and Node bodies.
pub const RESTORED_SETTLED_CAPTURE_PREFIX18_SCHEMA: &str =
    "source-private.source-restored-settled-capture-prefix/18";

/// Names the final journal whose semantic role requires the successor body.
pub const RESTORED_SETTLED_JOURNAL18_SCHEMA: &str =
    "source-private.source-restored-settled-journal/18";

/// Names the changed Source birth binding for the explicit import18 recipe.
pub const NATIVE_IMPORT18_SOURCE_BINDING_SCHEMA: &str =
    "source-owned.packet-canonical-ack-source-binding/18";

/// Names the changed private boot carrying that same import18 recipe.
pub const NATIVE_IMPORT18_PRIVATE_BOOT_SCHEMA: &str =
    "source-owned.packet-canonical-ack-private-boot/18";
