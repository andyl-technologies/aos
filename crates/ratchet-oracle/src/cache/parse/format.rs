//! Top-level binary serializers for parse-cache artifacts.
//!
//! Each artifact is a little-endian byte stream that begins with an 8-byte
//! magic and a `u32` version, followed by section counts and section payloads:
//!
//! ```text
//! resolved.bin: "AOSNIXRS" version root
//!               node_count child_count frame_count node_frame_count
//!               with_chain_count inherit_resolution_count node_inherit_count
//!               <nodes> <children> <frames> <node_frames>
//!               <with_chains> <inherit_resolutions> <node_inherits>
//! ir.bin:       "AOSNIXIR" version root
//!               node_count child_count frame_count with_chain_count
//!               attr_path_count binding_count shape_count
//!               <nodes> <children> <frames> <with_chains>
//!               <attr_paths> <bindings> <shapes>
//! symbols.bin:  "AOSNIXSY" version symbol_count <len-prefixed symbol bytes>
//! facts.bin:    "AOSNIXFT" version analysis_version ir_fingerprint fact_count
//!               <strictness/cardinality/escape tags + flag byte>
//!               capture_plan_count
//!               <node_id plan_tag [reason | slot_count <depth slot>*]>
//!               flat_capture_access_count
//!               <read_node_id allocation_site_id capture_index>
//!               lambda_summary_count <lambda summaries>
//! ```
//!
//! The per-node `facts.bin` flag byte packs the boolean fact bits: bit 0 is
//! the `tryEval` barrier, bit 1 the eager-assembly license, and bit 2 the
//! structural-totality proof (written by analysis version 7 producers).
//!
//! The capture-plan section exists only in sidecars whose `analysis_version`
//! is 4 or newer. Each entry names an allocation-site node id, a plan tag
//! (`0` = flat capture followed by a `(depth, slot)` coordinate list, `1` =
//! shared chain followed by a reason tag). Version 3 and older sidecars end
//! after the per-node records and decode with no capture plans.
//! Analysis version 5 appends the constant flat-capture access table; version
//! 4 sidecars end after capture plans and decode with no rewritten accesses.
//! Analysis version 7 appends the sparse lambda-summary table.
//!
//! Per-element encoders and the [`BinaryReader`] live in the sibling
//! [`mod@codec`] module; structural validation of decoded artifacts lives in
//! [`mod@validate`].

use super::*;

pub(super) fn encode_resolved_ir(resolved: &ResolvedAst) -> Result<Vec<u8>, ParseCacheError> {
    let mut out = Vec::new();
    out.extend_from_slice(RESOLVED_MAGIC);
    write_u32(&mut out, ARTIFACT_VERSION);
    write_u32(&mut out, resolved.root.as_u32());
    write_len(&mut out, resolved.arena.nodes().len(), "node count")?;
    write_len(&mut out, resolved.arena.child_pool().len(), "child count")?;
    write_len(&mut out, resolved.scopes.frames().len(), "frame count")?;
    write_len(
        &mut out,
        resolved.scopes.node_frames().len(),
        "node-frame count",
    )?;
    write_len(
        &mut out,
        resolved.scopes.with_chains().len(),
        "with-chain count",
    )?;
    write_len(
        &mut out,
        resolved.scopes.inherit_resolutions().len(),
        "inherit-resolution count",
    )?;
    write_len(
        &mut out,
        resolved.scopes.node_inherits().len(),
        "node-inherit count",
    )?;

    for node in resolved.arena.nodes() {
        encode_node(&mut out, *node);
    }
    for child in resolved.arena.child_pool() {
        write_u32(&mut out, child.as_u32());
    }
    for frame in resolved.scopes.frames() {
        encode_frame(&mut out, frame)?;
    }
    for frame in resolved.scopes.node_frames() {
        encode_option_u32(&mut out, frame.map(FrameId::as_u32));
    }
    for chain in resolved.scopes.with_chains() {
        write_len(&mut out, chain.scopes.len(), "with-chain scope count")?;
        for scope in chain.scopes.as_ref() {
            write_u32(&mut out, scope.as_u32());
        }
    }
    for inherit in resolved.scopes.inherit_resolutions() {
        encode_option_u32(&mut out, inherit.from.map(NodeId::as_u32));
        write_len(&mut out, inherit.sources.len(), "inherit source count")?;
        for source in inherit.sources.as_ref() {
            write_u32(&mut out, source.target.as_u32());
            write_u32(&mut out, source.source.as_u32());
        }
    }
    for inherit in resolved.scopes.node_inherits() {
        encode_option_u32(&mut out, inherit.map(InheritGroupId::as_u32));
    }
    Ok(out)
}

pub(super) fn decode_resolved_ir(
    bytes: &[u8],
    symbols: SymbolTable,
) -> Result<ResolvedAst, String> {
    let mut reader = BinaryReader::new(bytes);
    reader.expect_magic(RESOLVED_MAGIC)?;
    let version = reader.read_u32()?;
    if version != ARTIFACT_VERSION {
        return Err(format!("unsupported IR artifact version {version}"));
    }
    let root = NodeId::new(reader.read_u32()?);
    let node_count = reader.read_len("node count")?;
    let child_count = reader.read_len("child count")?;
    let frame_count = reader.read_len("frame count")?;
    let node_frame_count = reader.read_len("node-frame count")?;
    let with_chain_count = reader.read_len("with-chain count")?;
    let inherit_resolution_count = reader.read_len("inherit-resolution count")?;
    let node_inherit_count = reader.read_len("node-inherit count")?;

    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        nodes.push(decode_node(&mut reader)?);
    }
    let mut children = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        children.push(NodeId::new(reader.read_u32()?));
    }
    let mut frames = Vec::with_capacity(frame_count);
    for _ in 0..frame_count {
        frames.push(decode_frame(&mut reader)?);
    }
    let mut node_frames = Vec::with_capacity(node_frame_count);
    for _ in 0..node_frame_count {
        node_frames.push(reader.read_option_u32()?.map(FrameId::new));
    }
    let mut with_chains = Vec::with_capacity(with_chain_count);
    for _ in 0..with_chain_count {
        let scope_count = reader.read_len("with-chain scope count")?;
        let mut scopes = Vec::with_capacity(scope_count);
        for _ in 0..scope_count {
            scopes.push(NodeId::new(reader.read_u32()?));
        }
        with_chains.push(WithChain {
            scopes: scopes.into_boxed_slice(),
        });
    }
    let mut inherit_resolutions = Vec::with_capacity(inherit_resolution_count);
    for _ in 0..inherit_resolution_count {
        let from = reader.read_option_u32()?.map(NodeId::new);
        let source_count = reader.read_len("inherit source count")?;
        let mut sources = Vec::with_capacity(source_count);
        for _ in 0..source_count {
            sources.push(InheritSource {
                target: Symbol::new(reader.read_u32()?),
                source: NodeId::new(reader.read_u32()?),
            });
        }
        inherit_resolutions.push(InheritResolution {
            from,
            sources: sources.into_boxed_slice(),
        });
    }
    let mut node_inherits = Vec::with_capacity(node_inherit_count);
    for _ in 0..node_inherit_count {
        node_inherits.push(reader.read_option_u32()?.map(InheritGroupId::new));
    }
    reader.expect_eof()?;

    if node_frames.len() != nodes.len() {
        return Err("node-frame side table length does not match node count".to_owned());
    }
    if node_inherits.len() != nodes.len() {
        return Err("node-inherit side table length does not match node count".to_owned());
    }

    let resolved = ResolvedAst {
        root,
        arena: AstArena::from_raw_parts(nodes, children),
        symbols,
        scopes: ScopeTables::from_raw_parts(
            frames,
            node_frames,
            with_chains,
            inherit_resolutions,
            node_inherits,
        ),
    };
    validate_resolved_artifact(&resolved)?;
    Ok(resolved)
}

pub(super) fn encode_lowered_ir(ir: &Ir) -> Result<Vec<u8>, ParseCacheError> {
    let mut out = Vec::new();
    out.extend_from_slice(IR_MAGIC);
    write_u32(&mut out, ARTIFACT_VERSION);
    write_u32(&mut out, ir.root.as_u32());
    write_len(&mut out, ir.arena.nodes().len(), "IR node count")?;
    write_len(&mut out, ir.arena.child_pool().len(), "IR child count")?;
    write_len(&mut out, ir.frames.len(), "IR frame count")?;
    write_len(&mut out, ir.with_chains.len(), "IR with-chain count")?;
    write_len(&mut out, ir.attr_paths.len(), "IR attr-path count")?;
    write_len(&mut out, ir.bindings.len(), "IR binding count")?;
    write_len(&mut out, ir.shapes.len(), "IR shape count")?;

    for node in ir.arena.nodes() {
        encode_ir_node(&mut out, *node);
    }
    for child in ir.arena.child_pool() {
        write_u32(&mut out, child.as_u32());
    }
    for frame in ir.frames.as_ref() {
        encode_frame(&mut out, frame)?;
    }
    for chain in ir.with_chains.as_ref() {
        write_len(&mut out, chain.scopes.len(), "IR with-chain scope count")?;
        for scope in chain.scopes.as_ref() {
            write_u32(&mut out, scope.as_u32());
        }
    }
    for path in ir.attr_paths.as_ref() {
        write_len(&mut out, path.len(), "IR attr-path segment count")?;
        for segment in path.as_ref() {
            encode_ir_attr_path_segment(&mut out, *segment);
        }
    }
    for binding in ir.bindings.as_ref() {
        encode_ir_attr_path_segment(&mut out, binding.key);
        encode_option_span(&mut out, binding.position);
        write_u32(&mut out, binding.value.as_u32());
    }
    for shape in ir.shapes.as_ref() {
        write_len(&mut out, shape.keys.len(), "IR shape key count")?;
        for key in shape.keys.as_ref() {
            write_u32(&mut out, key.as_u32());
        }
    }
    Ok(out)
}

pub(super) fn encode_ir_facts(
    facts: &IrFacts,
    ir_fingerprint: LoweredIrFingerprint,
    analysis_version: u32,
) -> Result<Vec<u8>, ParseCacheError> {
    let mut out = Vec::new();
    out.extend_from_slice(FACTS_MAGIC);
    write_u32(&mut out, ARTIFACT_VERSION);
    write_u32(&mut out, analysis_version);
    out.extend_from_slice(&ir_fingerprint.as_durable_hash().as_bytes());
    write_len(&mut out, facts.len(), "IR fact count")?;
    for (index, fact) in facts.as_slice().iter().enumerate() {
        encode_expr_facts(&mut out, *fact);
        let id = IrId::new(index as u32);
        out.push(node_fact_flags(facts, id));
    }
    // The capture-plan section is part of the version-4 layout; placeholder
    // sidecars stamped with older analysis versions (notably the version-0
    // conservative tables) keep the pre-4 byte stream so their readers'
    // version-gated decoding sees exactly the sections the stamp promises.
    if analysis_version >= 4 {
        encode_capture_plans(&mut out, facts)?;
    }
    if analysis_version >= 5 {
        encode_flat_capture_accesses(&mut out, facts)?;
    }
    if analysis_version >= 7 {
        encode_lambda_call_summaries(&mut out, facts)?;
    }
    Ok(out)
}

/// Plan tag for [`CapturePlan::Flat`] entries.
const CAPTURE_PLAN_FLAT: u8 = 0;

/// Plan tag for [`CapturePlan::SharedChain`] entries.
const CAPTURE_PLAN_SHARED_CHAIN: u8 = 1;

fn encode_capture_plans(out: &mut Vec<u8>, facts: &IrFacts) -> Result<(), ParseCacheError> {
    let planned = facts
        .capture_plans()
        .iter()
        .filter(|plan| plan.is_some())
        .count();
    write_len(out, planned, "IR capture plan count")?;
    for (index, plan) in facts.capture_plans().iter().enumerate() {
        let Some(plan) = plan else {
            continue;
        };
        write_u32(out, index as u32);
        match plan {
            CapturePlan::Flat(slots) => {
                out.push(CAPTURE_PLAN_FLAT);
                write_len(out, slots.len(), "IR capture plan slot count")?;
                for slot in slots.as_ref() {
                    out.extend_from_slice(&slot.depth.to_le_bytes());
                    out.extend_from_slice(&slot.slot.to_le_bytes());
                }
            }
            CapturePlan::SharedChain(reason) => {
                out.push(CAPTURE_PLAN_SHARED_CHAIN);
                out.push(shared_chain_reason_tag(*reason));
            }
        }
    }
    Ok(())
}

fn shared_chain_reason_tag(reason: SharedChainReason) -> u8 {
    match reason {
        SharedChainReason::TooManyFreeVars => 0,
        SharedChainReason::DynamicScope => 1,
        SharedChainReason::CoordinateOverflow => 2,
    }
}

fn decode_shared_chain_reason(tag: u8) -> Result<SharedChainReason, String> {
    match tag {
        0 => Ok(SharedChainReason::TooManyFreeVars),
        1 => Ok(SharedChainReason::DynamicScope),
        2 => Ok(SharedChainReason::CoordinateOverflow),
        tag => Err(format!("invalid capture plan shared-chain reason tag {tag}")),
    }
}

fn decode_capture_plans(
    reader: &mut BinaryReader<'_>,
    facts: &mut IrFacts,
    expected_node_count: usize,
) -> Result<(), String> {
    let plan_count = reader.read_len("IR capture plan count")?;
    for _ in 0..plan_count {
        let index = reader.read_u32()? as usize;
        if index >= expected_node_count {
            return Err(format!(
                "IR capture plan node id {index} exceeds node count {expected_node_count}"
            ));
        }
        let plan = match reader.read_u8()? {
            CAPTURE_PLAN_FLAT => {
                let slot_count = reader.read_len("IR capture plan slot count")?;
                let mut slots = Vec::with_capacity(slot_count);
                for _ in 0..slot_count {
                    slots.push(Upvalue {
                        depth: reader.read_u16()?,
                        slot: reader.read_u16()?,
                    });
                }
                CapturePlan::Flat(slots.into_boxed_slice())
            }
            CAPTURE_PLAN_SHARED_CHAIN => {
                CapturePlan::SharedChain(decode_shared_chain_reason(reader.read_u8()?)?)
            }
            tag => return Err(format!("invalid capture plan tag {tag}")),
        };
        facts.set_capture_plan(IrId::new(index as u32), Some(plan));
    }
    Ok(())
}

fn encode_flat_capture_accesses(
    out: &mut Vec<u8>,
    facts: &IrFacts,
) -> Result<(), ParseCacheError> {
    let access_count = facts
        .flat_capture_accesses()
        .iter()
        .filter(|access| access.is_some())
        .count();
    write_len(out, access_count, "IR flat capture access count")?;
    for (index, access) in facts.flat_capture_accesses().iter().enumerate() {
        let Some(access) = access else {
            continue;
        };
        write_u32(out, index as u32);
        write_u32(out, access.site.as_u32());
        out.extend_from_slice(&access.index.to_le_bytes());
    }
    Ok(())
}

fn decode_flat_capture_accesses(
    reader: &mut BinaryReader<'_>,
    facts: &mut IrFacts,
    expected_node_count: usize,
) -> Result<(), String> {
    let access_count = reader.read_len("IR flat capture access count")?;
    for _ in 0..access_count {
        let read_index = reader.read_u32()? as usize;
        let site_index = reader.read_u32()? as usize;
        let capture_index = reader.read_u16()?;
        if read_index >= expected_node_count {
            return Err(format!(
                "IR flat capture read node id {read_index} exceeds node count {expected_node_count}"
            ));
        }
        if site_index >= expected_node_count {
            return Err(format!(
                "IR flat capture site node id {site_index} exceeds node count {expected_node_count}"
            ));
        }
        let site = IrId::new(site_index as u32);
        let Some(CapturePlan::Flat(slots)) = facts.capture_plan(site) else {
            return Err(format!(
                "IR flat capture access site {site_index} has no flat capture plan"
            ));
        };
        if usize::from(capture_index) >= slots.len() {
            return Err(format!(
                "IR flat capture index {capture_index} exceeds site {site_index} width {}",
                slots.len()
            ));
        }
        facts.set_flat_capture_access(
            IrId::new(read_index as u32),
            Some(FlatCaptureAccess {
                site,
                index: capture_index,
            }),
        );
    }
    Ok(())
}

/// Bit 0 of the per-node flag byte: `tryEval` barrier.
const FACT_FLAG_TRY_EVAL_BARRIER: u8 = 1 << 0;

/// Bit 1 of the per-node flag byte: eager-assembly license.
const FACT_FLAG_ASSEMBLY_EAGER: u8 = 1 << 1;

/// Bit 2 of the per-node flag byte: structural-totality proof.
const FACT_FLAG_STRUCTURALLY_TOTAL: u8 = 1 << 2;

/// Packs one node's boolean fact bits into the per-node flag byte.
///
/// Sidecars produced before analysis version 3 only ever wrote bit 0, so
/// they decode unchanged (with the eager-assembly bit absent).
fn node_fact_flags(facts: &IrFacts, id: IrId) -> u8 {
    let mut flags = 0;
    if facts.try_eval_barrier(id) {
        flags |= FACT_FLAG_TRY_EVAL_BARRIER;
    }
    if facts.assembly_eager(id) {
        flags |= FACT_FLAG_ASSEMBLY_EAGER;
    }
    if facts.structurally_total(id) {
        flags |= FACT_FLAG_STRUCTURALLY_TOTAL;
    }
    flags
}

/// Decodes a `facts.bin` sidecar, returning the fact table and the analysis
/// version recorded by its producer.
///
/// Callers decide what the version admits: any structurally valid sidecar may
/// hydrate in-memory facts, but only a sidecar recording the current
/// [`crate::compile::IR_ANALYSIS_VERSION`] proves the analysis pipeline
/// already ran for this artifact.
pub(super) fn decode_ir_facts(
    bytes: &[u8],
    expected_node_count: usize,
    expected_ir_fingerprint: LoweredIrFingerprint,
) -> Result<(IrFacts, u32), String> {
    let mut reader = BinaryReader::new(bytes);
    reader.expect_magic(FACTS_MAGIC)?;
    let version = reader.read_u32()?;
    if version != ARTIFACT_VERSION {
        return Err(format!("unsupported IR facts artifact version {version}"));
    }
    let analysis_version = reader.read_u32()?;
    let actual_ir_fingerprint = reader.read_array::<32>()?;
    if actual_ir_fingerprint != expected_ir_fingerprint.as_durable_hash().as_bytes() {
        return Err("IR facts artifact fingerprint does not match lowered IR artifact".to_owned());
    }
    let fact_count = reader.read_len("IR fact count")?;
    if fact_count != expected_node_count {
        return Err(format!(
            "IR fact count {fact_count} does not match node count {expected_node_count}"
        ));
    }

    let mut facts = IrFacts::conservative(expected_node_count);
    for index in 0..fact_count {
        let id = IrId::new(index as u32);
        let fact = decode_expr_facts(&mut reader)?;
        *facts
            .get_mut(id)
            .ok_or_else(|| "IR fact index out of range".to_owned())? = fact;
        let flags = decode_node_fact_flags(reader.read_u8()?)?;
        facts.set_try_eval_barrier(id, flags & FACT_FLAG_TRY_EVAL_BARRIER != 0);
        facts.set_assembly_eager(id, flags & FACT_FLAG_ASSEMBLY_EAGER != 0);
        facts.set_structurally_total(id, flags & FACT_FLAG_STRUCTURALLY_TOTAL != 0);
    }
    // The capture-plan section was introduced by analysis version 4; older
    // sidecars end after the per-node records and hydrate with no plans.
    if analysis_version >= 4 {
        decode_capture_plans(&mut reader, &mut facts, expected_node_count)?;
    }
    if analysis_version >= 5 {
        decode_flat_capture_accesses(&mut reader, &mut facts, expected_node_count)?;
    }
    if analysis_version >= 7 {
        decode_lambda_call_summaries(&mut reader, &mut facts, expected_node_count)?;
    }
    reader.expect_eof()?;
    Ok((facts, analysis_version))
}

fn encode_expr_facts(out: &mut Vec<u8>, facts: ExprFacts) {
    out.push(strictness_tag(facts.strictness));
    out.push(cardinality_tag(facts.cardinality));
    out.push(escape_tag(facts.escape));
}

fn decode_expr_facts(reader: &mut BinaryReader<'_>) -> Result<ExprFacts, String> {
    Ok(ExprFacts {
        strictness: decode_strictness(reader.read_u8()?)?,
        cardinality: decode_cardinality(reader.read_u8()?)?,
        escape: decode_escape(reader.read_u8()?)?,
    })
}

fn strictness_tag(strictness: Strictness) -> u8 {
    match strictness {
        Strictness::Unknown => 0,
        Strictness::Demanded => 1,
        Strictness::DemandedBeforeEffect => 2,
    }
}

fn decode_strictness(tag: u8) -> Result<Strictness, String> {
    match tag {
        0 => Ok(Strictness::Unknown),
        1 => Ok(Strictness::Demanded),
        2 => Ok(Strictness::DemandedBeforeEffect),
        tag => Err(format!("invalid strictness fact tag {tag}")),
    }
}

fn decode_node_fact_flags(flags: u8) -> Result<u8, String> {
    if flags
        & !(FACT_FLAG_TRY_EVAL_BARRIER | FACT_FLAG_ASSEMBLY_EAGER | FACT_FLAG_STRUCTURALLY_TOTAL)
        != 0
    {
        return Err(format!("invalid node fact flag byte {flags}"));
    }
    Ok(flags)
}

fn encode_lambda_call_summaries(out: &mut Vec<u8>, facts: &IrFacts) -> Result<(), ParseCacheError> {
    write_len(
        out,
        facts.lambda_call_summaries().len(),
        "lambda call summary count",
    )?;
    for summary in facts.lambda_call_summaries() {
        write_u32(out, summary.pattern.as_u32());
        encode_lambda_demand(out, summary.argument_demand);
        out.push(escape_tag(summary.argument_escape));
        write_len(out, summary.formals.len(), "lambda formal summary count")?;
        for formal in &summary.formals {
            encode_lambda_demand(out, formal.demand);
            out.push(escape_tag(formal.escape));
        }
        write_len(
            out,
            summary.attr_values.len(),
            "lambda attribute-value summary count",
        )?;
        for attr in &summary.attr_values {
            out.push(match attr.keys {
                LambdaAttrKeys::Only(_) => 0,
                LambdaAttrKeys::AllExcept(_) => 1,
            });
            write_len(out, attr.keys.symbols().len(), "lambda attribute key count")?;
            for symbol in attr.keys.symbols() {
                write_u32(out, symbol.as_u32());
            }
            encode_lambda_demand(out, attr.demand);
            out.push(escape_tag(attr.escape));
        }
    }
    Ok(())
}

fn encode_lambda_demand(out: &mut Vec<u8>, demand: LambdaDemand) {
    let (mode, level) = match demand {
        LambdaDemand::Unconditional(level) => (0, level),
        LambdaDemand::IfResultForced(level) => (1, level),
    };
    out.push(mode);
    out.push(strictness_tag(level));
}

fn decode_lambda_call_summaries(
    reader: &mut BinaryReader<'_>,
    facts: &mut IrFacts,
    node_count: usize,
) -> Result<(), String> {
    let count = reader.read_len("lambda call summary count")?;
    let mut summaries = Vec::new();
    summaries
        .try_reserve_exact(count)
        .map_err(|_| format!("lambda call summary count {count} is too large"))?;
    for _ in 0..count {
        let pattern = IrId::new(reader.read_u32()?);
        if pattern.index() >= node_count {
            return Err(format!(
                "lambda call summary pattern {pattern:?} is out of range"
            ));
        }
        let argument_demand = decode_lambda_demand(reader)?;
        let argument_escape = decode_escape(reader.read_u8()?)?;
        let formal_count = reader.read_len("lambda formal summary count")?;
        let mut formals = Vec::new();
        formals
            .try_reserve_exact(formal_count)
            .map_err(|_| format!("lambda formal summary count {formal_count} is too large"))?;
        for _ in 0..formal_count {
            formals.push(LambdaFormalSummary {
                demand: decode_lambda_demand(reader)?,
                escape: decode_escape(reader.read_u8()?)?,
            });
        }
        let attr_count = reader.read_len("lambda attribute-value summary count")?;
        let mut attr_values = Vec::new();
        attr_values
            .try_reserve_exact(attr_count)
            .map_err(|_| format!("lambda attribute-value count {attr_count} is too large"))?;
        for _ in 0..attr_count {
            let key_mode = reader.read_u8()?;
            let key_count = reader.read_len("lambda attribute key count")?;
            let mut keys = Vec::new();
            keys.try_reserve_exact(key_count)
                .map_err(|_| format!("lambda attribute key count {key_count} is too large"))?;
            for _ in 0..key_count {
                keys.push(Symbol::new(reader.read_u32()?));
            }
            let keys = match key_mode {
                0 => LambdaAttrKeys::Only(keys.into_boxed_slice()),
                1 => LambdaAttrKeys::AllExcept(keys.into_boxed_slice()),
                tag => return Err(format!("invalid lambda attribute key-set tag {tag}")),
            };
            attr_values.push(LambdaAttrValueSummary {
                keys,
                demand: decode_lambda_demand(reader)?,
                escape: decode_escape(reader.read_u8()?)?,
            });
        }
        summaries.push(LambdaCallSummary {
            pattern,
            argument_demand,
            argument_escape,
            formals: formals.into_boxed_slice(),
            attr_values: attr_values.into_boxed_slice(),
        });
    }
    facts.set_lambda_call_summaries(summaries);
    Ok(())
}

fn decode_lambda_demand(reader: &mut BinaryReader<'_>) -> Result<LambdaDemand, String> {
    let mode = reader.read_u8()?;
    let level = decode_strictness(reader.read_u8()?)?;
    match mode {
        0 => Ok(LambdaDemand::Unconditional(level)),
        1 => Ok(LambdaDemand::IfResultForced(level)),
        tag => Err(format!("invalid lambda demand mode tag {tag}")),
    }
}

fn cardinality_tag(cardinality: Cardinality) -> u8 {
    match cardinality {
        Cardinality::Absent => 0,
        Cardinality::Once => 1,
        Cardinality::Many => 2,
    }
}

fn decode_cardinality(tag: u8) -> Result<Cardinality, String> {
    match tag {
        0 => Ok(Cardinality::Absent),
        1 => Ok(Cardinality::Once),
        2 => Ok(Cardinality::Many),
        tag => Err(format!("invalid cardinality fact tag {tag}")),
    }
}

fn escape_tag(escape: Escape) -> u8 {
    match escape {
        Escape::NoEscape => 0,
        Escape::Escapes => 1,
    }
}

fn decode_escape(tag: u8) -> Result<Escape, String> {
    match tag {
        0 => Ok(Escape::NoEscape),
        1 => Ok(Escape::Escapes),
        tag => Err(format!("invalid escape fact tag {tag}")),
    }
}

pub(super) fn decode_lowered_ir(bytes: &[u8], symbols: SymbolTable) -> Result<Ir, String> {
    let mut reader = BinaryReader::new(bytes);
    reader.expect_magic(IR_MAGIC)?;
    let version = reader.read_u32()?;
    if version != ARTIFACT_VERSION {
        return Err(format!("unsupported lowered IR artifact version {version}"));
    }
    let root = IrId::new(reader.read_u32()?);
    let node_count = reader.read_len("IR node count")?;
    let child_count = reader.read_len("IR child count")?;
    let frame_count = reader.read_len("IR frame count")?;
    let with_chain_count = reader.read_len("IR with-chain count")?;
    let attr_path_count = reader.read_len("IR attr-path count")?;
    let binding_count = reader.read_len("IR binding count")?;
    let shape_count = reader.read_len("IR shape count")?;

    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        nodes.push(decode_ir_node(&mut reader)?);
    }
    let mut children = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        children.push(IrId::new(reader.read_u32()?));
    }
    let mut frames = Vec::with_capacity(frame_count);
    for _ in 0..frame_count {
        frames.push(decode_frame(&mut reader)?);
    }
    let mut with_chains = Vec::with_capacity(with_chain_count);
    for _ in 0..with_chain_count {
        let scope_count = reader.read_len("IR with-chain scope count")?;
        let mut scopes = Vec::with_capacity(scope_count);
        for _ in 0..scope_count {
            scopes.push(IrId::new(reader.read_u32()?));
        }
        with_chains.push(IrWithChain::new(scopes.into_boxed_slice()));
    }
    let mut attr_paths = Vec::with_capacity(attr_path_count);
    for _ in 0..attr_path_count {
        let segment_count = reader.read_len("IR attr-path segment count")?;
        let mut segments = Vec::with_capacity(segment_count);
        for _ in 0..segment_count {
            segments.push(decode_ir_attr_path_segment(&mut reader)?);
        }
        attr_paths.push(segments.into_boxed_slice());
    }
    let mut bindings = Vec::with_capacity(binding_count);
    for _ in 0..binding_count {
        let key = decode_ir_attr_path_segment(&mut reader)?;
        let position = reader.read_option_span()?;
        let value = IrId::new(reader.read_u32()?);
        bindings.push(IrBinding {
            key,
            position,
            value,
        });
    }
    let mut shapes = Vec::with_capacity(shape_count);
    for _ in 0..shape_count {
        let key_count = reader.read_len("IR shape key count")?;
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            keys.push(Symbol::new(reader.read_u32()?));
        }
        shapes.push(IrShape::new(keys.into_boxed_slice()));
    }
    reader.expect_eof()?;

    let ir = Ir {
        root,
        arena: IrArena::from_raw_parts(nodes, children),
        facts: IrFacts::conservative(node_count),
        symbols,
        frames: frames.into_boxed_slice(),
        with_chains: with_chains.into_boxed_slice(),
        attr_paths: attr_paths.into_boxed_slice(),
        bindings: bindings.into_boxed_slice(),
        shapes: shapes.into_boxed_slice(),
    };
    validate_lowered_ir_artifact(&ir)?;
    Ok(ir)
}

#[cfg(test)]
pub(super) fn lowered_ir_matches(left: &Ir, right: &Ir) -> bool {
    left.root == right.root
        && left.arena.nodes() == right.arena.nodes()
        && left.arena.child_pool() == right.arena.child_pool()
        && left.symbols.symbols() == right.symbols.symbols()
        && left.frames == right.frames
        && left.with_chains == right.with_chains
        && left.attr_paths == right.attr_paths
        && left.bindings == right.bindings
        && left.shapes == right.shapes
}

pub(super) fn encode_symbols(symbols: &SymbolTable) -> Result<Vec<u8>, ParseCacheError> {
    let mut out = Vec::new();
    out.extend_from_slice(SYMBOL_MAGIC);
    write_u32(&mut out, ARTIFACT_VERSION);
    write_len(&mut out, symbols.symbols().len(), "symbol count")?;
    for symbol in symbols.symbols() {
        write_len(&mut out, symbol.len(), "symbol byte length")?;
        out.extend_from_slice(symbol);
    }
    Ok(out)
}

pub(super) fn decode_symbols(bytes: &[u8]) -> Result<SymbolTable, String> {
    let mut reader = BinaryReader::new(bytes);
    reader.expect_magic(SYMBOL_MAGIC)?;
    let version = reader.read_u32()?;
    if version != ARTIFACT_VERSION {
        return Err(format!("unsupported symbols artifact version {version}"));
    }
    let count = reader.read_len("symbol count")?;
    let mut symbols = SymbolTable::new();
    for _ in 0..count {
        let len = reader.read_len("symbol byte length")?;
        let bytes = reader.read_bytes(len)?;
        let expected = u32::try_from(symbols.len())
            .map_err(|_| "symbol table length exceeds u32".to_owned())?;
        let symbol = symbols
            .intern(bytes)
            .map_err(|error| format!("invalid symbol table: {error}"))?;
        if symbol.as_u32() != expected {
            return Err("duplicate symbol in serialized symbol table".to_owned());
        }
    }
    reader.expect_eof()?;
    Ok(symbols)
}
