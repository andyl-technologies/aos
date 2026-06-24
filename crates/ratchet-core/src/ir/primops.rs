//! Static builtin and direct primitive-operation reference detection.
//!
//! These helpers inspect resolved AST nodes to recognize unshadowed `builtins`
//! references that lower to direct [`IrKind::PrimOp`] nodes instead of ordinary
//! applications. Dialects may map a direct builtin to a dialect-owned operation
//! carried by the same generic primop escape hatch.

use super::*;

impl IrLowerer {
    pub(super) fn builtin_dialect_op_ref(
        &self,
        id: NodeId,
    ) -> Result<Option<(Symbol, IrDialectOp)>, IrError> {
        let Some(symbol) = self.direct_builtin_ref_symbol(id)? else {
            return Ok(None);
        };
        let Some(direct) = self.direct_builtin(symbol) else {
            return Ok(None);
        };
        let op = (self.options.builtin_dialect_op())(self.resolved.symbols.resolve(symbol), direct);
        Ok(op.map(|op| (symbol, op)))
    }

    pub(super) fn strict_unary_primop_ref(
        &self,
        id: NodeId,
    ) -> Result<Option<(Symbol, EffectClass)>, IrError> {
        let Some(symbol) = self.direct_builtin_ref_symbol(id)? else {
            return Ok(None);
        };
        if self.node(id)?.kind == NodeKind::GlobalVar
            && !matches!(
                self.resolved.symbols.resolve(symbol),
                Some(b"import" | b"isNull")
            )
        {
            return Ok(None);
        }
        let Some(BuiltinDirect::StrictUnary { effect }) = self.direct_builtin(symbol) else {
            return Ok(None);
        };
        Ok(Some((symbol, self.effect_class(symbol, effect))))
    }

    pub(super) fn lazy_unary_primop_ref(
        &self,
        id: NodeId,
    ) -> Result<Option<(Symbol, EffectClass)>, IrError> {
        let Some(symbol) = self.direct_builtin_ref_symbol(id)? else {
            return Ok(None);
        };
        if self.node(id)?.kind == NodeKind::GlobalVar {
            return Ok(None);
        }
        let Some(BuiltinDirect::LazyUnary { effect }) = self.direct_builtin(symbol) else {
            return Ok(None);
        };
        Ok(Some((symbol, self.effect_class(symbol, effect))))
    }

    pub(super) fn strict_binary_primop_ref(
        &self,
        id: NodeId,
    ) -> Result<Option<(Symbol, EffectClass, NodeId)>, IrError> {
        let node = self.node(id)?;
        if node.kind != NodeKind::Apply {
            return Ok(None);
        }
        let NodeData::Pair {
            first: function,
            second: first_argument,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "application pair"));
        };
        if self.node(function)?.kind == NodeKind::GlobalVar {
            return Ok(None);
        }
        let Some(symbol) = self.direct_builtin_ref_symbol(function)? else {
            return Ok(None);
        };
        let effect = match self.direct_builtin(symbol) {
            Some(BuiltinDirect::StrictBinary { effect } | BuiltinDirect::Sort { effect }) => effect,
            _ => return Ok(None),
        };
        Ok(Some((
            symbol,
            self.effect_class(symbol, effect),
            first_argument,
        )))
    }

    pub(super) fn strict_lazy_binary_primop_ref(
        &self,
        id: NodeId,
    ) -> Result<Option<(Symbol, EffectClass, NodeId)>, IrError> {
        let node = self.node(id)?;
        if node.kind != NodeKind::Apply {
            return Ok(None);
        }
        let NodeData::Pair {
            first: function,
            second: first_argument,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "application pair"));
        };
        if self.node(function)?.kind == NodeKind::GlobalVar {
            return Ok(None);
        }
        let Some(symbol) = self.direct_builtin_ref_symbol(function)? else {
            return Ok(None);
        };
        let Some(BuiltinDirect::StrictLazyBinary { effect }) = self.direct_builtin(symbol) else {
            return Ok(None);
        };
        Ok(Some((
            symbol,
            self.effect_class(symbol, effect),
            first_argument,
        )))
    }

    pub(super) fn lazy_strict_binary_primop_ref(
        &self,
        id: NodeId,
    ) -> Result<Option<(Symbol, EffectClass, NodeId)>, IrError> {
        let node = self.node(id)?;
        if node.kind != NodeKind::Apply {
            return Ok(None);
        }
        let NodeData::Pair {
            first: function,
            second: first_argument,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "application pair"));
        };
        if self.node(function)?.kind == NodeKind::GlobalVar {
            return Ok(None);
        }
        let Some(symbol) = self.direct_builtin_ref_symbol(function)? else {
            return Ok(None);
        };
        let Some(BuiltinDirect::LazyStrictBinary { effect }) = self.direct_builtin(symbol) else {
            return Ok(None);
        };
        Ok(Some((
            symbol,
            self.effect_class(symbol, effect),
            first_argument,
        )))
    }

    pub(super) fn strict_ternary_primop_ref(
        &self,
        id: NodeId,
    ) -> Result<Option<(Symbol, EffectClass, NodeId, NodeId)>, IrError> {
        let node = self.node(id)?;
        if node.kind != NodeKind::Apply {
            return Ok(None);
        }
        let NodeData::Pair {
            first: function,
            second: second_argument,
        } = node.data
        else {
            return Err(self.invalid_shape(node, "application pair"));
        };
        let function = self.node(function)?;
        if function.kind != NodeKind::Apply {
            return Ok(None);
        }
        let NodeData::Pair {
            first: function,
            second: first_argument,
        } = function.data
        else {
            return Err(self.invalid_shape(function, "application pair"));
        };
        if self.node(function)?.kind == NodeKind::GlobalVar {
            return Ok(None);
        }
        let Some(symbol) = self.direct_builtin_ref_symbol(function)? else {
            return Ok(None);
        };
        let Some(BuiltinDirect::StrictTernary { effect }) = self.direct_builtin(symbol) else {
            return Ok(None);
        };
        Ok(Some((
            symbol,
            self.effect_class(symbol, effect),
            first_argument,
            second_argument,
        )))
    }

    pub(super) fn direct_builtin_ref_symbol(&self, id: NodeId) -> Result<Option<Symbol>, IrError> {
        if self.options.dynamic_builtin_scope() {
            return Ok(None);
        }
        let node = self.node(id)?;
        match node.kind {
            NodeKind::GlobalVar => {
                let NodeData::Symbol(symbol) = node.data else {
                    return Err(self.invalid_shape(node, "global symbol payload"));
                };
                Ok(Some(symbol))
            }
            NodeKind::Select => {
                let NodeData::Select {
                    receiver,
                    path,
                    default,
                } = node.data
                else {
                    return Err(self.invalid_shape(node, "select payload"));
                };
                if default.is_some() {
                    return Ok(None);
                }
                let receiver = self.node(receiver)?;
                if receiver.kind != NodeKind::GlobalVar
                    || !self.symbol_payload_is(receiver, b"builtins")
                {
                    return Ok(None);
                }
                let segments = self.child_ids(path)?;
                let Some(segment) = segments.first().copied() else {
                    return Ok(None);
                };
                if segments.len() != 1 {
                    return Ok(None);
                }
                let segment = self.node(segment)?;
                if !matches!(segment.kind, NodeKind::Ident | NodeKind::Str) {
                    return Ok(None);
                }
                let NodeData::Symbol(symbol) = segment.data else {
                    return Err(self.invalid_shape(segment, "attribute symbol payload"));
                };
                Ok(Some(symbol))
            }
            _ => Ok(None),
        }
    }

    pub(super) fn symbol_payload_is(&self, node: Node, expected: &[u8]) -> bool {
        let NodeData::Symbol(symbol) = node.data else {
            return false;
        };
        self.symbol_is(symbol, expected)
    }

    pub(super) fn symbol_is(&self, symbol: Symbol, expected: &[u8]) -> bool {
        self.resolved.symbols.resolve(symbol) == Some(expected)
    }

    pub(super) fn direct_builtin(&self, symbol: Symbol) -> Option<BuiltinDirect> {
        self.resolved
            .symbols
            .resolve(symbol)
            .and_then(direct_builtin)
    }

    pub(super) fn effect_class(&self, symbol: Symbol, effect: BuiltinEffect) -> EffectClass {
        let name = self.resolved.symbols.resolve(symbol);
        (self.options.builtin_effect_of())(name, effect)
    }
}
