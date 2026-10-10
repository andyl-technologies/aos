//! Separates ordinary writer measurements from current publication authority.
//!
//! Initial construction, full preparation, verification, export and completion
//! are reported independently of affected-range incremental maintenance.

use terrane_core::identity::Digest;
use terrane_core::indexing::{completion, incremental, lookup, maintenance};

use super::IndexGraftValidationWork;
use crate::guard::history::completion::indexes::IndexInputReads;
use crate::indexing::{Loading, Reconstruction};

/// Reports a required owner/name whose binding remains incomplete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexBindingGap {
    /// Actual final immutable namespace owner.
    pub owner: Digest,
    /// Registered attribute whose owner-local binding is absent.
    pub attribute: String,
    /// Absolute occurrences whose independently resolved requirements need it.
    pub paths: Vec<Vec<u8>>,
}

/// Reports one actual owner/name construction or maintenance operation.
#[derive(Clone, Debug)]
pub struct IndexOperationWork {
    /// Independently selected previous owner, when a valid index was retained.
    pub old_owner: Option<Digest>,
    /// Final completed immutable owner, never the detached index identity.
    pub owner: Digest,
    /// Registered inline attribute selected by this operation.
    pub attribute: String,
    /// Independently governed occurrences sharing this exact operation.
    pub paths: Vec<Vec<u8>>,
    /// Old overlay acquisition, charged only to its first owner/name operation.
    pub old_loading: Option<Loading>,
    /// Old retained/staged/store calls, charged once per exact owner/name.
    pub old_inputs: Option<IndexInputReads>,
    /// Complete old namespace reconstruction, separate from maintenance.
    pub old_reconstruction: Option<Reconstruction>,
    /// Full old source validation, separate from maintenance.
    pub old_source: Option<incremental::PreparationWork>,
    /// Full new source validation, separate from maintenance.
    pub new_source: incremental::PreparationWork,
    /// Independent old I/P/G verification and retained canonical preparation.
    pub old_index: Option<maintenance::PreparationWork>,
    /// Independent verification of an explicitly supplied replacement binding.
    pub supplied_index: Option<lookup::Preparation>,
    /// Supplied relationship dispatch, charged once per exact owner/name.
    pub supplied_inputs: Option<IndexInputReads>,
    /// Supplied relationship acquisition, charged once per exact owner/name.
    pub supplied_loading: Option<Loading>,
    /// Complete separately supplied namespace reconstruction.
    pub supplied_reconstruction: Option<Reconstruction>,
    /// Actual affected-range Existing-mode work; absent for initialization.
    pub update: Option<maintenance::UpdateWork>,
    /// Actual resynchronization B from Existing-mode work; absent for initialization.
    pub boundary: Option<usize>,
    /// Explicit full initial construction, never incremental maintenance.
    pub initialization: Option<maintenance::ConstructionWork>,
    /// Full reachable closure materialization for independent completion checks.
    /// Initialization also moves these owned bytes into the output.
    pub export: maintenance::ExportWork,
    /// Bounded emitted-byte selection/copying for Existing maintenance.
    /// Initialization uses its explicit full export and leaves this absent.
    pub publication: Option<maintenance::PublicationWork>,
    /// Ordered identities selected from this operation's actual emitted nodes.
    /// Existing maintenance visits and copies exactly `len()` 32-byte identities
    /// into this evidence; that additional bounded pass is maintenance work.
    /// Initialization leaves this empty and reports its explicit full export.
    pub publication_nodes: Vec<Digest>,
    /// Actual independently checked completed-owner association.
    pub association: completion::Association,
}

/// Reports graft-handle preparation and retained physical slot cardinalities.
///
/// Addresses are shared from complete independent canonical validation. Handle
/// preparation does not traverse namespace entries again. Actual validation
/// capture visits and copies are reported separately in
/// [`IndexPublicationWork::graft_validation`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IndexGraftPreparationWork {
    /// Distinct immutable owner plans whose validated handles were checked.
    pub owners: usize,
    /// Independently resolved namespace occurrences represented by those owners.
    pub owner_occurrences: usize,
    /// Additional top-level containing-entry visits during handle preparation.
    pub entry_visits: usize,
    /// Additional entry-value visits during handle preparation.
    pub nested_entry_visits: usize,
    /// Retained physical Tree target slots in the immutable owners.
    pub graft_slots: usize,
    /// Tree target slots multiplied by their actual containing-owner occurrences.
    pub graft_occurrences: usize,
}

/// Reports affected containing-entry selection and replacement operations.
///
/// Counts describe executed lookup and edit events, not complete CPU work, index
/// delta or boundary work. Repeated Tree slots remain separate address links;
/// overlapping links select one containing entry for the actual batched edit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IndexGraftPropagationWork {
    /// Completed distinct owners whose final immutable root changed.
    pub changed_targets: usize,
    /// Reverse address lookups submitted for changed immutable targets.
    pub target_lookups: usize,
    /// Physical reverse address links visited by those lookups.
    pub address_links: usize,
    /// Visited links multiplied by their actual containing-owner occurrences.
    pub affected_occurrences: usize,
    /// Distinct containing owner/key pairs selected for replacement.
    pub selected_entries: usize,
    /// Actual keyed reads of selected containing entries.
    pub entry_lookups: usize,
    /// Selected entry values inspected, including Conflict candidates and bases.
    pub nested_entry_visits: usize,
    /// Replacement-map lookups for Tree slots in those selected entry values.
    pub replacement_lookups: usize,
    /// Tree slots whose immutable target was actually replaced.
    pub replaced_graft_slots: usize,
    /// Top-level containing entries changed in actual batched edits.
    pub edited_entries: usize,
}

/// Reports actual index preparation without certifying current coverage or authority.
///
/// These fields cover the index writer's actual input loading, reconstruction,
/// relationship validation, source preparation, maintenance and completion.
/// They do not measure all candidate admission, historical/current authority,
/// immutable publication, protected control I/O or native physical reads.
#[derive(Clone, Debug, Default)]
pub struct IndexPublicationWork {
    /// Candidate namespace acquisition through retained and staged input bytes.
    pub namespace_loading: Option<Loading>,
    /// Distinguishes candidate overlay returns from real store GET calls.
    pub namespace_inputs: Option<IndexInputReads>,
    /// Full canonical candidate reconstruction, separate from incremental work.
    pub namespace_reconstruction: Option<Reconstruction>,
    /// Address capture within complete independent canonical namespace validation.
    /// These visits and copies are separate from incremental maintenance.
    pub graft_validation: Option<IndexGraftValidationWork>,
    /// Validated handle checks and retained slot counts, without an entry rescan.
    pub graft_preparation: Option<IndexGraftPreparationWork>,
    /// Actual affected-entry lookups and replacements, separate from index delta and B.
    pub graft_propagation: IndexGraftPropagationWork,
    /// Actual independent owner/name operations, including repeated old contexts.
    pub operations: Vec<IndexOperationWork>,
    /// Required absent bindings, which remain explicit incomplete coverage.
    pub gaps: Vec<IndexBindingGap>,
    /// Canonical owner completion work, separate from incremental maintenance.
    pub completion: Vec<completion::Work>,
    /// Actual containing-root edits propagating completed graft identities.
    pub propagation: Vec<terrane_core::tree_builder::Work>,
    /// Output map insertions requested, including repeated immutable identities.
    /// This counts requests, not comparisons inside the native BTreeMap.
    pub output_node_insertions: usize,
    /// Canonical payload bytes moved into the output by those insertion requests.
    /// Repeated insertions are charged repeatedly, rather than deduplicated.
    pub output_bytes: usize,
    /// Bytes copied to prepare those output payloads, before moving them.
    /// Includes emitted index, owner-completion and containing-root bytes;
    /// explicit initialization moves its full export without another byte copy.
    /// Index publication copies are also detailed per operation, not extra work.
    pub output_bytes_copied: usize,
}
