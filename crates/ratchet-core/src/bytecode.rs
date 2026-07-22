//! Compact production-baseline bytecode artifacts and verification.
//!
//! The bytecode tier lowers the scope-resolved [`crate::Ir`] into immutable,
//! fixed-stride instructions. The safe tree-walk evaluator remains the semantic
//! oracle; this module owns only the language-agnostic artifact, compiler, and
//! structural verifier. Runtime execution lives above `ratchet-core` so it can
//! use the selected value ABI and dialect helpers without introducing those
//! dependencies here.
//!
//! The initial BC-0 format admits scalar literals and lexical loads:
//!
//! ```text
//! entry(ir=4, registers=1):
//!     load_int r0, 42
//!     return r0
//! ```
//!
//! Unsupported IR nodes have no entry yet. This makes partial rollout explicit:
//! an executor selects bytecode only when [`BytecodeModule::entry`] returns an
//! entry before any effect has executed.

use std::fmt::Write as _;

use thiserror::Error;

use crate::{Ir, IrData, IrId, IrKind};

/// The bytecode compiler and serialized format version.
///
/// Increment this whenever instruction meaning, entry layout, or verification
/// changes incompatibly with a persisted artifact.
pub const BYTECODE_COMPILER_VERSION: u32 = 1;

/// A bytecode instruction offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BytecodePc(u32);

impl BytecodePc {
    /// Creates a program counter from its fixed-stride instruction offset.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the fixed-stride instruction offset.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the instruction offset as a slice index.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A frame-local bytecode value register.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BytecodeRegister(u16);

impl BytecodeRegister {
    /// Creates a register from its frame-local index.
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Returns the frame-local register index.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
    /// Returns the register index as a slice index.
    const fn index(self) -> usize {
        self.0 as usize
    }
}

/// One fixed-stride production-baseline bytecode instruction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BytecodeInstruction {
    /// Loads an integer literal into a register.
    LoadInt {
        /// Destination register.
        dst: BytecodeRegister,
        /// Literal value.
        value: i64,
    },
    /// Loads a floating-point literal into a register.
    LoadFloat {
        /// Destination register.
        dst: BytecodeRegister,
        /// Literal value.
        value: f64,
    },
    /// Loads a boolean literal into a register.
    LoadBool {
        /// Destination register.
        dst: BytecodeRegister,
        /// Literal value.
        value: bool,
    },
    /// Loads the null value into a register.
    LoadNull {
        /// Destination register.
        dst: BytecodeRegister,
    },
    /// Loads a slot from the current lexical frame.
    LoadLocal {
        /// Destination register.
        dst: BytecodeRegister,
        /// Current-frame slot.
        slot: u32,
    },
    /// Loads a slot from a lexical parent frame.
    LoadUpvalue {
        /// Destination register.
        dst: BytecodeRegister,
        /// Number of parent frames to traverse.
        depth: u32,
        /// Target-frame slot.
        slot: u32,
    },
    /// Returns a register from the current entry.
    Return {
        /// Result register.
        src: BytecodeRegister,
    },
}

impl BytecodeInstruction {
    fn register(self) -> BytecodeRegister {
        match self {
            Self::LoadInt { dst, .. }
            | Self::LoadFloat { dst, .. }
            | Self::LoadBool { dst, .. }
            | Self::LoadNull { dst }
            | Self::LoadLocal { dst, .. }
            | Self::LoadUpvalue { dst, .. } => dst,
            Self::Return { src } => src,
        }
    }
}

/// The entry metadata for one admitted IR expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BytecodeEntry {
    /// First instruction executed for the expression.
    pub pc: BytecodePc,
    /// Number of value registers required by the entry.
    pub register_count: u16,
    /// Number of instructions owned by the entry.
    pub instruction_count: u32,
}

/// An immutable bytecode artifact compiled from one lowered IR module.
#[derive(Clone, Debug, PartialEq)]
pub struct BytecodeModule {
    version: u32,
    code: Box<[BytecodeInstruction]>,
    entries: Box<[Option<BytecodeEntry>]>,
}

impl BytecodeModule {
    /// Compiles every currently admitted expression in `ir`.
    ///
    /// Unsupported expressions deliberately receive no bytecode entry. A later
    /// executor must choose the tree-walk oracle before evaluating such an
    /// expression; it must never begin executing an entry and then replay an
    /// effect through the fallback.
    ///
    /// # Errors
    ///
    /// Returns [`BytecodeCompileError`] if the instruction stream cannot be
    /// addressed by [`BytecodePc`].
    pub fn compile(ir: &Ir) -> Result<Self, BytecodeCompileError> {
        let mut code = Vec::new();
        let mut entries = vec![None; ir.arena.nodes().len()];
        for (index, node) in ir.arena.nodes().iter().enumerate() {
            if !node.effect.is_speculable() {
                continue;
            }
            let dst = BytecodeRegister::new(0);
            let instruction = match (node.kind, node.data) {
                (IrKind::Int, IrData::Int(value)) => BytecodeInstruction::LoadInt { dst, value },
                (IrKind::Float, IrData::Float(value)) => {
                    BytecodeInstruction::LoadFloat { dst, value }
                }
                (IrKind::Bool, IrData::Bool(value)) => {
                    BytecodeInstruction::LoadBool { dst, value }
                }
                (IrKind::Null, IrData::None) => BytecodeInstruction::LoadNull { dst },
                (IrKind::LocalVar, IrData::Local { slot }) => {
                    BytecodeInstruction::LoadLocal { dst, slot }
                }
                (IrKind::UpvalVar, IrData::Upval { depth, slot }) => {
                    BytecodeInstruction::LoadUpvalue { dst, depth, slot }
                }
                _ => continue,
            };
            let raw_pc = u32::try_from(code.len())
                .map_err(|_| BytecodeCompileError::TooManyInstructions)?;
            raw_pc
                .checked_add(2)
                .ok_or(BytecodeCompileError::TooManyInstructions)?;
            code.push(instruction);
            code.push(BytecodeInstruction::Return { src: dst });
            entries[index] = Some(BytecodeEntry {
                pc: BytecodePc::new(raw_pc),
                register_count: 1,
                instruction_count: 2,
            });
        }
        let module = Self {
            version: BYTECODE_COMPILER_VERSION,
            code: code.into_boxed_slice(),
            entries: entries.into_boxed_slice(),
        };
        module.verify().map_err(BytecodeCompileError::Verification)?;
        Ok(module)
    }

    /// Returns the bytecode format/compiler version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the instruction stream in program-counter order.
    pub fn code(&self) -> &[BytecodeInstruction] {
        &self.code
    }

    /// Returns the admitted entry for `id`, or `None` when tree walk is required.
    pub fn entry(&self, id: IrId) -> Option<BytecodeEntry> {
        self.entries.get(id.index()).copied().flatten()
    }

    /// Returns the entry table in IR allocation order.
    pub fn entries(&self) -> &[Option<BytecodeEntry>] {
        &self.entries
    }

    /// Verifies all structural invariants required by a safe executor.
    ///
    /// # Errors
    ///
    /// Returns [`BytecodeVerifyError`] when the compiler version is unknown, an
    /// entry points outside the instruction stream, a register lies outside its
    /// entry frame, or a currently straight-line entry does not terminate in a
    /// `return` instruction.
    pub fn verify(&self) -> Result<(), BytecodeVerifyError> {
        if self.version != BYTECODE_COMPILER_VERSION {
            return Err(BytecodeVerifyError::UnsupportedVersion {
                found: self.version,
            });
        }
        for (ir_index, entry) in self.entries.iter().enumerate() {
            let Some(entry) = entry else {
                continue;
            };
            if entry.register_count == 0 {
                return Err(BytecodeVerifyError::ZeroRegisters { ir_index });
            }
            let first = entry.pc.index();
            let instruction_count = usize::try_from(entry.instruction_count).map_err(|_| {
                BytecodeVerifyError::InvalidEntry {
                    ir_index,
                    pc: entry.pc,
                }
            })?;
            let Some(end) = first.checked_add(instruction_count) else {
                return Err(BytecodeVerifyError::InvalidEntry {
                    ir_index,
                    pc: entry.pc,
                });
            };
            let Some(body) = self.code.get(first..end) else {
                return Err(BytecodeVerifyError::InvalidEntry {
                    ir_index,
                    pc: entry.pc,
                });
            };
            let mut terminated = false;
            for (offset, instruction) in body.iter().copied().enumerate() {
                if instruction.register().index() >= usize::from(entry.register_count) {
                    return Err(BytecodeVerifyError::RegisterOutOfBounds {
                        pc: BytecodePc::new(
                            u32::try_from(first + offset).unwrap_or(u32::MAX),
                        ),
                        register: instruction.register(),
                        register_count: entry.register_count,
                    });
                }
                if matches!(instruction, BytecodeInstruction::Return { .. }) {
                    terminated = true;
                    break;
                }
            }
            if !terminated {
                return Err(BytecodeVerifyError::UnterminatedEntry {
                    ir_index,
                    pc: entry.pc,
                });
            }
        }
        Ok(())
    }

    /// Renders a deterministic human-readable artifact for golden tests.
    pub fn render(&self) -> String {
        let mut rendered = format!("bytecode-v{}\n", self.version);
        for (ir_index, entry) in self.entries.iter().enumerate() {
            if let Some(entry) = entry {
                let _ = writeln!(
                    rendered,
                    "entry ir={ir_index} pc={} registers={} instructions={}",
                    entry.pc.as_u32(),
                    entry.register_count,
                    entry.instruction_count
                );
            }
        }
        for (pc, instruction) in self.code.iter().enumerate() {
            let _ = writeln!(rendered, "  {pc:04} {instruction:?}");
        }
        rendered
    }
}

/// A failure while compiling lowered IR to bytecode.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BytecodeCompileError {
    /// The fixed-width program counter cannot address another instruction.
    #[error("bytecode instruction stream exceeds u32 addressability")]
    TooManyInstructions,
    /// The compiler produced an artifact rejected by its verifier.
    #[error("compiled bytecode failed verification: {0}")]
    Verification(BytecodeVerifyError),
}

/// A structural bytecode verification failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BytecodeVerifyError {
    /// The artifact uses an incompatible compiler/format version.
    #[error("unsupported bytecode version {found}")]
    UnsupportedVersion {
        /// Version stored in the artifact.
        found: u32,
    },
    /// An entry allocates no value registers.
    #[error("bytecode entry for IR node {ir_index} declares zero registers")]
    ZeroRegisters {
        /// IR arena index owning the entry.
        ir_index: usize,
    },
    /// An entry starts outside the instruction stream.
    #[error("bytecode entry for IR node {ir_index} points to invalid pc {pc:?}")]
    InvalidEntry {
        /// IR arena index owning the entry.
        ir_index: usize,
        /// Invalid program counter.
        pc: BytecodePc,
    },
    /// An instruction references a register outside its entry frame.
    #[error(
        "bytecode instruction {pc:?} references register {register:?}, but the entry has {register_count} registers"
    )]
    RegisterOutOfBounds {
        /// Program counter of the invalid instruction.
        pc: BytecodePc,
        /// Invalid register.
        register: BytecodeRegister,
        /// Register count declared by the entry.
        register_count: u16,
    },
    /// A straight-line entry reaches the end of the stream without returning.
    #[error("bytecode entry for IR node {ir_index} at {pc:?} is unterminated")]
    UnterminatedEntry {
        /// IR arena index owning the entry.
        ir_index: usize,
        /// First instruction of the entry.
        pc: BytecodePc,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EffectClass, IrArena, IrFacts, IrNode};
    use crate::syntax::{Span, SymbolTable};

    fn ir_with_nodes(nodes: Vec<IrNode>) -> Ir {
        let node_count = nodes.len();
        Ir {
            root: IrId::new(0),
            arena: IrArena::from_raw_parts(nodes, Vec::new()),
            facts: IrFacts::conservative(node_count),
            symbols: SymbolTable::new(),
            frames: Box::new([]),
            with_chains: Box::new([]),
            attr_paths: Box::new([]),
            bindings: Box::new([]),
            shapes: Box::new([]),
        }
    }

    #[test]
    fn compiler_emits_deterministic_scalar_entries_and_explicit_declines() {
        let ir = ir_with_nodes(vec![
            IrNode::new(
                IrKind::Int,
                Span::new(0, 2),
                EffectClass::pure(),
                IrData::Int(42),
            ),
            IrNode::new(
                IrKind::Bool,
                Span::new(3, 7),
                EffectClass::pure(),
                IrData::Bool(true),
            ),
            IrNode::new(
                IrKind::Apply,
                Span::new(8, 12),
                EffectClass::pure(),
                IrData::Pair {
                    first: IrId::new(0),
                    second: IrId::new(1),
                },
            ),
            IrNode::new(
                IrKind::Int,
                Span::new(13, 14),
                EffectClass::new(1, false),
                IrData::Int(7),
            ),
        ]);

        let module = BytecodeModule::compile(&ir).expect("scalar bytecode compiles");
        assert_eq!(module.entry(IrId::new(0)).map(|entry| entry.pc), Some(BytecodePc::new(0)));
        assert_eq!(module.entry(IrId::new(1)).map(|entry| entry.pc), Some(BytecodePc::new(2)));
        assert_eq!(module.entry(IrId::new(2)), None, "unsupported apply declines before execution");
        assert_eq!(
            module.entry(IrId::new(3)),
            None,
            "effectful entries decline before execution"
        );
        assert_eq!(BytecodeModule::compile(&ir).expect("repeat compile").render(), module.render());
        assert!(module.render().contains("LoadInt"));
        assert!(module.render().contains("LoadBool"));
    }

    #[test]
    fn verifier_rejects_out_of_bounds_registers() {
        let module = BytecodeModule {
            version: BYTECODE_COMPILER_VERSION,
            code: vec![
                BytecodeInstruction::LoadNull {
                    dst: BytecodeRegister::new(1),
                },
                BytecodeInstruction::Return {
                    src: BytecodeRegister::new(0),
                },
            ]
            .into_boxed_slice(),
            entries: vec![Some(BytecodeEntry {
                pc: BytecodePc::new(0),
                register_count: 1,
                instruction_count: 2,
            })]
            .into_boxed_slice(),
        };

        assert!(matches!(
            module.verify(),
            Err(BytecodeVerifyError::RegisterOutOfBounds {
                register: BytecodeRegister(1),
                ..
            })
        ));
    }

    #[test]
    fn verifier_rejects_unterminated_entries() {
        let module = BytecodeModule {
            version: BYTECODE_COMPILER_VERSION,
            code: vec![BytecodeInstruction::LoadNull {
                dst: BytecodeRegister::new(0),
            }]
            .into_boxed_slice(),
            entries: vec![Some(BytecodeEntry {
                pc: BytecodePc::new(0),
                register_count: 1,
                instruction_count: 1,
            })]
            .into_boxed_slice(),
        };

        assert!(matches!(
            module.verify(),
            Err(BytecodeVerifyError::UnterminatedEntry { .. })
        ));
    }
}
