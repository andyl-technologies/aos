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
//! ```
//!
//! The per-node `facts.bin` flag byte packs the boolean fact bits: bit 0 is
//! the `tryEval` barrier and bit 1 the eager-assembly license (written by
//! analysis version 3 producers; older sidecars only ever wrote bit 0).
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
    Ok(out)
}

/// Bit 0 of the per-node flag byte: `tryEval` barrier.
const FACT_FLAG_TRY_EVAL_BARRIER: u8 = 1 << 0;

/// Bit 1 of the per-node flag byte: eager-assembly license.
const FACT_FLAG_ASSEMBLY_EAGER: u8 = 1 << 1;

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
    if flags & !(FACT_FLAG_TRY_EVAL_BARRIER | FACT_FLAG_ASSEMBLY_EAGER) != 0 {
        return Err(format!("invalid node fact flag byte {flags}"));
    }
    Ok(flags)
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
