//! Separates first ancestry, captured source and freshly owned restoration scope.
//!
//! Native verifier output is inert. An opaque context is created only after the
//! authenticated Runtime7 object, complete journal roster and both producer and
//! consumer nodes agree under their actual inactive owning runtime. This context
//! grants no input, readiness, capture or native execution permission.

use super::*;
use crate::node_scheduling::SchedulingSnapshot;
use crate::node_state::VerifiedStateContent;

#[path = "restoration_scope.rs"]
mod scope_validation;

/// Pairs an exact captured owner with its independently authenticated fresh owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalLineageOwnerMapping {
    /// Retains the actual source-capture incarnation without relabeling it.
    pub source: OwnerIdentity,
    /// Names actual newly owned target custody.
    pub target: OwnerIdentity,
}

/// Enumerates complete original native permission and input knowledge for one node.
///
/// Each vector is strictly sorted. These fields are claims until core compares
/// them with the signed source and this actual node validates its own journals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalLineageJournal {
    /// Names the original logical component preserved by this selected codec.
    pub node: Id,
    /// Enumerates every recorded operation, including failures and acknowledgements.
    pub operations: Vec<Id>,
    /// Enumerates original outstanding native operations separately from completions.
    pub pending_operations: Vec<Id>,
    /// Enumerates original native acknowledgements separately from held output.
    pub acknowledged_operations: Vec<Id>,
    /// Enumerates every original accepted or uncertain input-staging identity.
    pub input_stages: Vec<Id>,
}

/// Carries inert installed coordinator7 and native/tape verification results.
///
/// No public constructor of a live lineage association accepts this record.
/// Matching labels, hashes or owner mappings alone never authenticate native state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginalLineageNativeScope {
    /// Selects the distinct complete lineage coordinator, exactly edition seven.
    pub coordinator_schema: u16,
    /// Binds the exact independently authenticated signed Runtime7 object.
    pub source_record: ContentRef,
    /// Preserves actual capture-time scope independently of first-sealed input scope.
    pub source_capture: SavedRuntimeActivation,
    /// Names the genuine proposed fresh complete-world activation.
    pub target: ActivationRecord,
    /// Enumerates complete source-to-target owner mapping in source-owner order.
    pub owners: Vec<OriginalLineageOwnerMapping>,
    /// Preserves every first-sealed input scope in signed input-roster order.
    pub first_scopes: Vec<SavedOriginalInputScope>,
    /// Enumerates every original component journal in canonical node order.
    pub journals: Vec<OriginalLineageJournal>,
    /// Retains fresh current ACKs for each original acknowledged input stage.
    ///
    /// Actual owning adapters must validate these independently against original
    /// input journals; the original ACK remains separately in Runtime7.
    pub input_acknowledgements: Vec<crate::node_scheduling::NativeInputAcknowledgement>,
    /// Names the authentic installed native/tape scope proof retained by its owner.
    pub proof: ContentRef,
}

/// Declares independent finite decoded-body and encoded-record restoration credits.
#[derive(Clone, Copy, Debug)]
pub struct OriginalLineageRestorationLimits {
    /// Bounds original body roles, bytes and declared dependency edges.
    pub lineage: OriginalInputLineageLimits,
    /// Bounds the complete canonical Runtime7 record before decoding.
    pub maximum_record_bytes: usize,
}

/// Retains an authenticated restoration context beneath one inactive owning runtime.
///
/// Its fields and constructor are private; the source content is borrowed from
/// the authenticated typed archive. It cannot be serialized, cloned into another
/// runtime, or used as a native permission or source-class qualification.
pub struct OriginalLineageRestoration<'a> {
    authority: Rc<()>,
    source: ContentRef,
    scheduling: crucible_node_contract::HashRef,
    record: OriginalLineageRuntimeRecord,
    scope: OriginalLineageNativeScope,
    content: &'a VerifiedStateContent,
    limits: OriginalLineageRestorationLimits,
}

impl OriginalLineageRestoration<'_> {
    /// Borrows the exact authenticated source record identity.
    pub fn source_record(&self) -> &ContentRef {
        &self.source
    }

    /// Borrows immutable first-sealed input scopes and source-capture history.
    pub fn record(&self) -> &OriginalLineageRuntimeRecord {
        &self.record
    }

    /// Borrows the independently checked actual fresh target activation.
    pub fn target(&self) -> &ActivationRecord {
        &self.scope.target
    }

    /// Borrows fresh input ACKs independently checked against original native journals.
    ///
    /// These remain inert evidence until this context's owning runtime installs
    /// them beneath its actually published target world.
    pub fn input_acknowledgements(&self) -> &[crate::node_scheduling::NativeInputAcknowledgement] {
        &self.scope.input_acknowledgements
    }

    pub(crate) fn validate_original_scheduler(
        &self,
        scheduling: &SchedulingSnapshot,
    ) -> Result<(), RuntimeError> {
        if scheduling
            .continuation_hash()
            .map_err(|_| RuntimeError::InvalidReceipt)?
            != self.scheduling
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        Ok(())
    }

    /// Borrows authenticated original bytes only by their complete typed reference.
    pub fn original_body(&self, reference: &ContentRef) -> Option<&[u8]> {
        self.content.get(reference)
    }

    /// Checks this same runtime's continued native custody without executing work.
    ///
    /// This is a read-only gate. It never installs a lineage seal or reissues an
    /// input, even when authentic original input ACK and output bytes are retained.
    ///
    /// # Errors
    /// Refuses a different runtime/target, changed node snapshot or unavailable
    /// actual producer and consumer native journals.
    pub fn validate_current(&self, runtime: &NodeRuntime) -> Result<(), RuntimeError> {
        if !Rc::ptr_eq(&self.authority, &runtime.authority)
            || runtime.barrier.record() != &self.scope.target
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        validate_nodes(
            runtime,
            &self.source,
            &self.record,
            &self.scope,
            self.content,
        )
    }
}

impl NodeRuntime {
    /// Arms fresh readiness only after actual whole-runtime lineage context checks.
    ///
    /// Every node receives the same opaque context under its original owning
    /// runtime. Failed callbacks retain the complete world in quarantine. This
    /// publishes no world and installs no operation/input permission.
    ///
    /// # Errors
    /// Refuses foreign or changed context, unsupported actual node codecs,
    /// failed journal admission or ordinary readiness validation.
    pub fn arm_original_lineage_restoration(
        &mut self,
        context: &OriginalLineageRestoration<'_>,
    ) -> Result<(), RuntimeError> {
        context.validate_current(self)?;
        if self.activated || !self.operations.is_empty() || !self.input_batches.is_empty() {
            return Err(RuntimeError::ForeignAuthority);
        }
        let admitted = (|| -> Result<(), RuntimeError> {
            for (node_id, node) in &mut self.nodes {
                let snapshot = self
                    .snapshots
                    .get(node_id)
                    .ok_or(RuntimeError::UnknownNode)?;
                snapshot.validate_current(node.as_ref())?;
                node.admit_original_lineage_restoration(context)
                    .map_err(|_| RuntimeError::InvalidReceipt)?;
                snapshot.validate_current(node.as_ref())?;
            }
            context.validate_current(self)
        })();
        if let Err(error) = admitted {
            // Earlier nodes may already have retained admission markers. Any
            // later callback/snapshot refusal contains the complete owning world.
            let route = NodeRoute {
                node: context.target().activation_id.clone(),
                owners: context.target().owners.clone(),
            };
            self.contain_roster(&route);
            return Err(error);
        }
        self.arm_all()
    }

    /// Authenticates a selected Runtime7 source beneath inactive fresh native custody.
    ///
    /// Foreign targets and finite source extents are checked before decoding or
    /// native callbacks. The installed verifier must authenticate coordinator7
    /// and the complete native/tape source relationship; each actual owning node
    /// then independently checks its original journals before a context is formed.
    /// Default native implementations refuse. No lineage or Ready is installed.
    ///
    /// # Errors
    /// Refuses active/populated runtimes, malformed or foreign source/target/cut,
    /// incomplete first-source/journal mappings, missing bodies, finite credits or
    /// unavailable producer and consumer native continuation validation.
    pub fn prepare_original_lineage_restoration<'a>(
        &self,
        source: &ContentRef,
        content: &'a VerifiedStateContent,
        scheduling: &SchedulingSnapshot,
        target: &ActivationRecord,
        verifier: &mut dyn NativeRuntimeContinuationVerifier,
        limits: OriginalLineageRestorationLimits,
    ) -> Result<OriginalLineageRestoration<'a>, RuntimeError> {
        let maximum_record_bytes = limits.maximum_record_bytes;

        // Target identity is actual local custody, not an expected caller label.
        if self.activated
            || !self.operations.is_empty()
            || !self.input_batches.is_empty()
            || self.terminal.is_some()
            || self.condition_stop.is_some()
            || self.barrier.record() != target
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        source
            .validate()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if source.media_type != "application/vnd.crucible.runtime-original-lineage+json;version=7" {
            return Err(RuntimeError::InvalidReceipt);
        }
        let extent =
            usize::try_from(source.length.get()).map_err(|_| RuntimeError::ResourceLimit)?;
        if extent > maximum_record_bytes {
            return Err(RuntimeError::ResourceLimit);
        }
        let bytes = content.get(source).ok_or(RuntimeError::InvalidReceipt)?;
        let value = canonical::parse_json(bytes, maximum_record_bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        if canonical::canonical_json(&value).map_err(|_| RuntimeError::InvalidReceipt)? != bytes {
            return Err(RuntimeError::InvalidReceipt);
        }
        let record: OriginalLineageRuntimeRecord =
            serde_json::from_value(value).map_err(|_| RuntimeError::InvalidReceipt)?;
        record.validate_original_bodies(content, limits.lineage, maximum_record_bytes)?;
        scope_validation::validate_source(self, &record, scheduling, target)?;
        let scope = verifier.verify_original_lineage_scope(
            source,
            &record,
            scheduling,
            target,
            self.limits,
        )?;
        scope_validation::validate_native_scope(self, source, &record, target, &scope)?;
        // A scope proof does not substitute for either endpoint's actual journals.
        validate_nodes(self, source, &record, &scope, content)?;
        Ok(OriginalLineageRestoration {
            authority: Rc::clone(&self.authority),
            source: source.clone(),
            scheduling: scheduling
                .continuation_hash()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            record,
            scope,
            content,
            limits,
        })
    }
}

fn validate_nodes(
    runtime: &NodeRuntime,
    source: &ContentRef,
    record: &OriginalLineageRuntimeRecord,
    scope: &OriginalLineageNativeScope,
    content: &VerifiedStateContent,
) -> Result<(), RuntimeError> {
    for (node_id, snapshot) in &runtime.snapshots {
        let node = runtime
            .nodes
            .get(node_id)
            .ok_or(RuntimeError::UnknownNode)?;
        snapshot.validate_current(node.as_ref())?;
        node.validate_original_lineage_restoration(source, record, scope, content)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        snapshot.validate_current(node.as_ref())?;
    }
    Ok(())
}

#[path = "restoration_install.rs"]
mod install;
