//! Terminal lowered-module IR and source-storage accounting.
//!
//! `AOS_NIX_MODULE_IR_SOURCE_CENSUS=1` enables a default-off census after
//! evaluation has completed. The report walks append-only module metadata once;
//! it does not instrument node reads or alter evaluator behavior.

use std::collections::HashMap;

use serde_json::{Value as CensusJsonValue, json};

use super::*;

const CENSUS_ENV: &str = "AOS_NIX_MODULE_IR_SOURCE_CENSUS";

#[derive(Debug, Default)]
struct DuplicateCounts {
    groups: usize,
    entries: usize,
}

impl DuplicateCounts {
    fn from_frequencies<K>(frequencies: &HashMap<K, usize>) -> Self {
        frequencies
            .values()
            .copied()
            .filter(|count| *count > 1)
            .fold(Self::default(), |mut totals, count| {
                totals.groups = totals.groups.saturating_add(1);
                totals.entries = totals.entries.saturating_add(count.saturating_sub(1));
                totals
            })
    }

    fn json(&self) -> CensusJsonValue {
        json!({"groups": self.groups, "entries_beyond_first": self.entries})
    }
}

#[derive(Debug, Default)]
struct ModuleIrSourceCensus {
    module_count: usize,
    module_capacity: usize,
    node_len: usize,
    node_capacity: usize,
    node_bytes: usize,
    child_len: usize,
    child_capacity: usize,
    child_bytes: usize,
    facts_node_count: usize,
    facts_expr_bytes: usize,
    facts_try_eval_bytes: usize,
    facts_assembly_eager_bytes: usize,
    facts_structurally_total_bytes: usize,
    facts_capture_plan_lane_bytes: usize,
    facts_capture_slot_bytes: usize,
    facts_flat_capture_access_lane_bytes: usize,
    facts_lambda_summary_lane_bytes: usize,
    facts_lambda_formal_bytes: usize,
    facts_lambda_attr_value_bytes: usize,
    facts_lambda_attr_key_bytes: usize,
    symbol_bytes: usize,
    frame_count: usize,
    frame_lane_bytes: usize,
    frame_capture_bytes: usize,
    with_chain_count: usize,
    with_chain_lane_bytes: usize,
    with_chain_scope_bytes: usize,
    attr_path_count: usize,
    attr_path_lane_bytes: usize,
    attr_path_segment_bytes: usize,
    binding_count: usize,
    binding_bytes: usize,
    shape_count: usize,
    shape_lane_bytes: usize,
    shape_key_bytes: usize,
    ir_total_bytes: usize,
    source_count: usize,
    source_name_len: usize,
    source_name_capacity_bytes: usize,
    source_raw_len: usize,
    source_raw_capacity_bytes: usize,
    line_starts_initialized_count: usize,
    line_starts_len: usize,
    line_starts_bytes: usize,
    path_base_count: usize,
    path_base_len: usize,
    path_base_capacity_bytes: usize,
    source_digests: HashMap<[u8; 32], usize>,
    path_bases: HashMap<Vec<u8>, usize>,
    source_digest_path_bases: HashMap<([u8; 32], Vec<u8>), usize>,
}

impl ModuleIrSourceCensus {
    fn collect(evaluator: &TreeWalk) -> Self {
        let mut census = Self {
            module_count: evaluator.modules.len(),
            module_capacity: evaluator.modules.capacity(),
            ..Self::default()
        };
        for module in &evaluator.modules {
            census.add_ir(&module.ir);
            census.add_source(
                module.source.as_ref(),
                module
                    .path_literal_base
                    .as_ref()
                    .map(|base| (base.as_slice(), base.capacity())),
            );
        }
        census
    }

    fn add_ir(&mut self, ir: &Ir) {
        self.node_len = self.node_len.saturating_add(ir.arena.nodes().len());
        self.node_capacity = self.node_capacity.saturating_add(ir.arena.node_capacity());
        self.node_bytes = self.node_bytes.saturating_add(
            ir.arena
                .node_capacity()
                .saturating_mul(std::mem::size_of::<IrNode>()),
        );
        self.child_len = self.child_len.saturating_add(ir.arena.child_pool().len());
        self.child_capacity = self
            .child_capacity
            .saturating_add(ir.arena.child_capacity());
        self.child_bytes = self.child_bytes.saturating_add(
            ir.arena
                .child_capacity()
                .saturating_mul(std::mem::size_of::<IrId>()),
        );

        let facts = ir.facts.storage_components();
        self.facts_node_count = self.facts_node_count.saturating_add(facts.node_count);
        self.facts_expr_bytes = self.facts_expr_bytes.saturating_add(facts.expr_facts_bytes);
        self.facts_try_eval_bytes = self
            .facts_try_eval_bytes
            .saturating_add(facts.try_eval_barrier_bytes);
        self.facts_assembly_eager_bytes = self
            .facts_assembly_eager_bytes
            .saturating_add(facts.assembly_eager_bytes);
        self.facts_structurally_total_bytes = self
            .facts_structurally_total_bytes
            .saturating_add(facts.structurally_total_bytes);
        self.facts_capture_plan_lane_bytes = self
            .facts_capture_plan_lane_bytes
            .saturating_add(facts.capture_plan_lane_bytes);
        self.facts_capture_slot_bytes = self
            .facts_capture_slot_bytes
            .saturating_add(facts.capture_slot_bytes);
        self.facts_flat_capture_access_lane_bytes = self
            .facts_flat_capture_access_lane_bytes
            .saturating_add(facts.flat_capture_access_lane_bytes);
        self.facts_lambda_summary_lane_bytes = self
            .facts_lambda_summary_lane_bytes
            .saturating_add(facts.lambda_call_summary_lane_bytes);
        self.facts_lambda_formal_bytes = self
            .facts_lambda_formal_bytes
            .saturating_add(facts.lambda_formal_summary_bytes);
        self.facts_lambda_attr_value_bytes = self
            .facts_lambda_attr_value_bytes
            .saturating_add(facts.lambda_attr_value_summary_bytes);
        self.facts_lambda_attr_key_bytes = self
            .facts_lambda_attr_key_bytes
            .saturating_add(facts.lambda_attr_key_bytes);

        self.symbol_bytes = self
            .symbol_bytes
            .saturating_add(ir.symbols.resident_bytes());
        self.frame_count = self.frame_count.saturating_add(ir.frames.len());
        self.frame_lane_bytes = self
            .frame_lane_bytes
            .saturating_add(std::mem::size_of_val(&*ir.frames));
        self.frame_capture_bytes = self.frame_capture_bytes.saturating_add(
            ir.frames
                .iter()
                .map(|frame| std::mem::size_of_val(&*frame.captures))
                .sum::<usize>(),
        );
        self.with_chain_count = self.with_chain_count.saturating_add(ir.with_chains.len());
        self.with_chain_lane_bytes = self
            .with_chain_lane_bytes
            .saturating_add(std::mem::size_of_val(&*ir.with_chains));
        self.with_chain_scope_bytes = self.with_chain_scope_bytes.saturating_add(
            ir.with_chains
                .iter()
                .map(|chain| std::mem::size_of_val(&*chain.scopes))
                .sum::<usize>(),
        );
        self.attr_path_count = self.attr_path_count.saturating_add(ir.attr_paths.len());
        self.attr_path_lane_bytes = self
            .attr_path_lane_bytes
            .saturating_add(std::mem::size_of_val(&*ir.attr_paths));
        self.attr_path_segment_bytes = self.attr_path_segment_bytes.saturating_add(
            ir.attr_paths
                .iter()
                .map(|path| std::mem::size_of_val(&**path))
                .sum::<usize>(),
        );
        self.binding_count = self.binding_count.saturating_add(ir.bindings.len());
        self.binding_bytes = self
            .binding_bytes
            .saturating_add(std::mem::size_of_val(&*ir.bindings));
        self.shape_count = self.shape_count.saturating_add(ir.shapes.len());
        self.shape_lane_bytes = self
            .shape_lane_bytes
            .saturating_add(std::mem::size_of_val(&*ir.shapes));
        self.shape_key_bytes = self.shape_key_bytes.saturating_add(
            ir.shapes
                .iter()
                .map(|shape| std::mem::size_of_val(&*shape.keys))
                .sum::<usize>(),
        );
        self.ir_total_bytes = self.ir_total_bytes.saturating_add(ir.resident_bytes());
    }

    fn add_source(&mut self, source: Option<&ModuleSource>, path_base: Option<(&[u8], usize)>) {
        let digest = source.map(|source| {
            self.source_count = self.source_count.saturating_add(1);
            self.source_name_len = self.source_name_len.saturating_add(source.name.len());
            self.source_name_capacity_bytes = self
                .source_name_capacity_bytes
                .saturating_add(source.name.capacity());
            self.source_raw_len = self.source_raw_len.saturating_add(source.bytes.len());
            self.source_raw_capacity_bytes = self
                .source_raw_capacity_bytes
                .saturating_add(source.bytes.capacity());
            if let Some((len, bytes)) = source.initialized_line_starts_storage() {
                self.line_starts_initialized_count =
                    self.line_starts_initialized_count.saturating_add(1);
                self.line_starts_len = self.line_starts_len.saturating_add(len);
                self.line_starts_bytes = self.line_starts_bytes.saturating_add(bytes);
            }
            let digest = *blake3::hash(&source.bytes).as_bytes();
            *self.source_digests.entry(digest).or_default() += 1;
            digest
        });

        if let Some((path_base, path_base_capacity)) = path_base {
            self.path_base_count = self.path_base_count.saturating_add(1);
            self.path_base_len = self.path_base_len.saturating_add(path_base.len());
            self.path_base_capacity_bytes = self
                .path_base_capacity_bytes
                .saturating_add(path_base_capacity);
            *self.path_bases.entry(path_base.to_vec()).or_default() += 1;
            if let Some(digest) = digest {
                *self
                    .source_digest_path_bases
                    .entry((digest, path_base.to_vec()))
                    .or_default() += 1;
            }
        }
    }

    fn facts_total_bytes(&self) -> usize {
        self.facts_expr_bytes
            .saturating_add(self.facts_try_eval_bytes)
            .saturating_add(self.facts_assembly_eager_bytes)
            .saturating_add(self.facts_structurally_total_bytes)
            .saturating_add(self.facts_capture_plan_lane_bytes)
            .saturating_add(self.facts_capture_slot_bytes)
            .saturating_add(self.facts_flat_capture_access_lane_bytes)
            .saturating_add(self.facts_lambda_summary_lane_bytes)
            .saturating_add(self.facts_lambda_formal_bytes)
            .saturating_add(self.facts_lambda_attr_value_bytes)
            .saturating_add(self.facts_lambda_attr_key_bytes)
    }

    fn ir_component_bytes(&self) -> usize {
        self.node_bytes
            .saturating_add(self.child_bytes)
            .saturating_add(self.facts_total_bytes())
            .saturating_add(self.symbol_bytes)
            .saturating_add(self.frame_lane_bytes)
            .saturating_add(self.frame_capture_bytes)
            .saturating_add(self.with_chain_lane_bytes)
            .saturating_add(self.with_chain_scope_bytes)
            .saturating_add(self.attr_path_lane_bytes)
            .saturating_add(self.attr_path_segment_bytes)
            .saturating_add(self.binding_bytes)
            .saturating_add(self.shape_lane_bytes)
            .saturating_add(self.shape_key_bytes)
    }

    fn source_component_bytes(&self) -> usize {
        self.source_name_capacity_bytes
            .saturating_add(self.source_raw_capacity_bytes)
            .saturating_add(self.line_starts_bytes)
            .saturating_add(self.path_base_capacity_bytes)
    }

    fn json(&self) -> CensusJsonValue {
        let digest_duplicates = DuplicateCounts::from_frequencies(&self.source_digests);
        let path_base_duplicates = DuplicateCounts::from_frequencies(&self.path_bases);
        let pair_duplicates = DuplicateCounts::from_frequencies(&self.source_digest_path_bases);
        json!({
            "modules": {
                "len": self.module_count,
                "capacity": self.module_capacity,
                "table_bytes": self.module_capacity.saturating_mul(std::mem::size_of::<TreeWalkModule>())
            },
            "ir": {
                "total_bytes": self.ir_total_bytes,
                "component_bytes": self.ir_component_bytes(),
                "components_reconcile": self.ir_component_bytes() == self.ir_total_bytes,
                "nodes": {"len": self.node_len, "capacity": self.node_capacity, "bytes": self.node_bytes},
                "children": {"len": self.child_len, "capacity": self.child_capacity, "bytes": self.child_bytes},
                "facts": {
                    "node_count": self.facts_node_count,
                    "expr_bytes": self.facts_expr_bytes,
                    "try_eval_barrier_bytes": self.facts_try_eval_bytes,
                    "assembly_eager_bytes": self.facts_assembly_eager_bytes,
                    "structurally_total_bytes": self.facts_structurally_total_bytes,
                    "capture_plan_lane_bytes": self.facts_capture_plan_lane_bytes,
                    "capture_slot_bytes": self.facts_capture_slot_bytes,
                    "flat_capture_access_lane_bytes": self.facts_flat_capture_access_lane_bytes,
                    "lambda_summary_lane_bytes": self.facts_lambda_summary_lane_bytes,
                    "lambda_formal_bytes": self.facts_lambda_formal_bytes,
                    "lambda_attr_value_bytes": self.facts_lambda_attr_value_bytes,
                    "lambda_attr_key_bytes": self.facts_lambda_attr_key_bytes,
                    "total_bytes": self.facts_total_bytes()
                },
                "symbols_bytes": self.symbol_bytes,
                "frames": {"len": self.frame_count, "lane_bytes": self.frame_lane_bytes, "capture_bytes": self.frame_capture_bytes},
                "with_chains": {"len": self.with_chain_count, "lane_bytes": self.with_chain_lane_bytes, "scope_bytes": self.with_chain_scope_bytes},
                "attr_paths": {"len": self.attr_path_count, "lane_bytes": self.attr_path_lane_bytes, "segment_bytes": self.attr_path_segment_bytes},
                "bindings": {"len": self.binding_count, "bytes": self.binding_bytes},
                "shapes": {"len": self.shape_count, "lane_bytes": self.shape_lane_bytes, "key_bytes": self.shape_key_bytes}
            },
            "source": {
                "count": self.source_count,
                "total_bytes": self.source_component_bytes(),
                "name": {"len": self.source_name_len, "capacity_bytes": self.source_name_capacity_bytes},
                "raw": {"len": self.source_raw_len, "capacity_bytes": self.source_raw_capacity_bytes},
                "line_starts": {"initialized_sources": self.line_starts_initialized_count, "len": self.line_starts_len, "bytes": self.line_starts_bytes},
                "path_base": {"count": self.path_base_count, "len": self.path_base_len, "capacity_bytes": self.path_base_capacity_bytes}
            },
            "duplicates": {
                "source_digest": digest_duplicates.json(),
                "path_base": path_base_duplicates.json(),
                "source_digest_path_base": pair_duplicates.json()
            }
        })
    }
}

/// Emits the default-off terminal module IR and source component census.
pub(super) fn emit_module_ir_source_census(evaluator: &TreeWalk) {
    if !std::env::var(CENSUS_ENV).is_ok_and(|value| value == "1") {
        return;
    }
    eprintln!(
        "aos_nix_module_ir_source_census {}",
        ModuleIrSourceCensus::collect(evaluator).json()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{EffectClass, IrFacts, IrWithChain};

    fn fixture_ir() -> Ir {
        let nodes = vec![IrNode::new(
            IrKind::Int,
            Span::new(0, 1),
            EffectClass::pure(),
            IrData::Int(1),
        )];
        let arena = IrArena::from_raw_parts(nodes, vec![IrId::new(0), IrId::new(0)]);
        Ir {
            root: IrId::new(0),
            facts: IrFacts::conservative(arena.nodes().len()),
            arena,
            symbols: SymbolTable::new(),
            frames: vec![crate::compile::FrameInfo {
                slot_count: 1,
                captures: vec![crate::compile::Upvalue { depth: 0, slot: 0 }].into_boxed_slice(),
                rec: false,
                has_with: false,
            }]
            .into_boxed_slice(),
            with_chains: vec![IrWithChain::new(vec![IrId::new(0)].into_boxed_slice())]
                .into_boxed_slice(),
            attr_paths: vec![vec![IrAttrPathSegment::Dynamic(IrId::new(0))].into_boxed_slice()]
                .into_boxed_slice(),
            bindings: Vec::new().into_boxed_slice(),
            shapes: Vec::new().into_boxed_slice(),
        }
    }

    #[test]
    fn component_report_is_strict_json_and_counts_nested_storage_and_duplicates() {
        let ir = fixture_ir();
        let first = ModuleSource::new(b"one.nix".to_vec(), b"1\n".to_vec());
        let second = ModuleSource::new(b"two.nix".to_vec(), b"1\n".to_vec());
        let path_base = b"/fixture".to_vec();
        assert_eq!(first.line_column_at_offset(0), Some((1, 1)));
        let mut census = ModuleIrSourceCensus {
            module_count: 2,
            module_capacity: 4,
            ..ModuleIrSourceCensus::default()
        };
        census.add_ir(&ir);
        census.add_source(
            Some(&first),
            Some((path_base.as_slice(), path_base.capacity())),
        );
        census.add_source(
            Some(&second),
            Some((path_base.as_slice(), path_base.capacity())),
        );

        let encoded = serde_json::to_string(&census.json()).expect("census serializes");
        let report: CensusJsonValue =
            serde_json::from_str(&encoded).expect("report is strict JSON");
        assert_eq!(report["modules"]["len"], 2);
        assert_eq!(report["ir"]["nodes"]["len"], 1);
        assert_eq!(report["ir"]["children"]["len"], 2);
        assert_eq!(report["ir"]["components_reconcile"], true);
        assert_eq!(
            report["ir"]["frames"]["capture_bytes"],
            std::mem::size_of::<crate::compile::Upvalue>()
        );
        assert_eq!(report["source"]["line_starts"]["initialized_sources"], 1);
        assert_eq!(
            report["duplicates"]["source_digest"]["entries_beyond_first"],
            1
        );
        assert_eq!(report["duplicates"]["source_digest_path_base"]["groups"], 1);
    }
}
