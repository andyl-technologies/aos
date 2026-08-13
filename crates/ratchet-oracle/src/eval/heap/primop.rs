//! Constructors and accessors for [`EvalPrimOpArg`] and [`EvalPrimOp`] builtin records.

use super::*;

impl EvalPrimOpArg {
    /// Creates a captured builtin argument record.
    pub const fn new(id: IrId, span: Span, value: Value) -> Self {
        Self::new_in_module(EvalModuleId::ROOT, id, span, value)
    }

    /// Creates a captured builtin argument record in a specific IR module.
    pub const fn new_in_module(module: EvalModuleId, id: IrId, span: Span, value: Value) -> Self {
        Self {
            module,
            id,
            span,
            value,
        }
    }

    /// Returns the module that owns the IR node that produced the argument.
    pub const fn module(&self) -> EvalModuleId {
        self.module
    }

    /// Returns the IR node that produced the argument.
    pub const fn id(&self) -> IrId {
        self.id
    }

    /// Returns the source span associated with the argument.
    pub const fn span(&self) -> Span {
        self.span
    }

    /// Returns the lazy argument value.
    pub const fn value(&self) -> Value {
        self.value
    }
}

impl EvalPrimOp {
    /// Returns whether two payload snapshots contain the same builtin state.
    pub(crate) fn raw_eq(&self, other: &Self) -> bool {
        self.builtin == other.builtin
            && self.symbol == other.symbol
            && self.args.len() == other.args.len()
            && self.args.iter().zip(&other.args).all(|(left, right)| {
                left.module == right.module
                    && left.id == right.id
                    && left.span == right.span
                    && left.value.raw_eq(right.value)
            })
    }

    /// Creates an unapplied first-class builtin record for `symbol`.
    pub const fn new(symbol: Symbol) -> Self {
        Self {
            builtin: None,
            symbol,
            args: Vec::new(),
        }
    }

    /// Creates a partially applied builtin record with captured arguments.
    pub fn with_args(symbol: Symbol, args: Vec<EvalPrimOpArg>) -> Self {
        Self {
            builtin: None,
            symbol,
            args,
        }
    }

    /// Creates an unapplied first-class builtin with its registry declaration.
    pub(crate) const fn registered(symbol: Symbol, builtin: Builtin) -> Self {
        Self {
            builtin: Some(builtin.kind()),
            symbol,
            args: Vec::new(),
        }
    }

    /// Creates a partially applied builtin with its registry declaration.
    pub(crate) fn registered_with_args(
        symbol: Symbol,
        builtin: Builtin,
        args: Vec<EvalPrimOpArg>,
    ) -> Self {
        Self {
            builtin: Some(builtin.kind()),
            symbol,
            args,
        }
    }

    /// Returns the registry declaration selected for this builtin.
    pub(crate) const fn builtin(&self) -> Option<Builtin> {
        match self.builtin {
            Some(kind) => Some(Builtin::from_kind(kind)),
            None => None,
        }
    }

    /// Returns the builtin symbol.
    pub const fn symbol(&self) -> Symbol {
        self.symbol
    }

    /// Returns captured lazy arguments in application order.
    pub fn args(&self) -> &[EvalPrimOpArg] {
        &self.args
    }
}
