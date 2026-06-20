//! Declaration macros that publish each builtin marker type as both an entry
//! in the ordered `BUILTINS` registry and the generated exact-name lookup.
//!
//! These macros are `#[macro_use]`-imported so the `define_builtins!`
//! invocation in `declarations` can expand against them.

macro_rules! builtin_registry {
    (
        $(
            $ty:ident,
        )*
    ) => {
        pub(crate) const BUILTIN_DECLARATIONS: &[Builtin] = &[
            $(
                <$ty as BuiltinDefinition>::DECLARATION,
            )*
        ];
        pub(crate) const BUILTIN_LOOKUP_LEN: usize = BUILTIN_DECLARATIONS.len();
        pub(crate) type BuiltinLookup = BuiltinLookupTable<BUILTIN_LOOKUP_LEN>;
        pub(crate) const BUILTIN_LOOKUP: BuiltinLookup = BuiltinLookupTable::build(BUILTIN_DECLARATIONS);

        /// Builtin declarations recognized by the resolver and evaluator.
        pub(crate) const BUILTINS: BuiltinRegistry =
            BuiltinRegistry::new(BUILTIN_DECLARATIONS, &BUILTIN_LOOKUP);
    };
}

macro_rules! define_builtins {
    (
        $(
            pub(crate) struct $ty:ident;
            impl BuiltinDefinition for $impl_ty:ident {
                $($body:item)*
            }
        )*
    ) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub(crate) enum BuiltinKind {
            $(
                $ty,
            )*
        }

        $(
            pub(crate) struct $ty;
            impl BuiltinDefinition for $impl_ty {
                const KIND: BuiltinKind = BuiltinKind::$ty;
                $($body)*
            }
        )*

        impl Builtin {
            /// Returns whether this builtin is visible in the current evaluator options.
            pub(crate) fn is_available<E>(self, eval: &E) -> bool
            where
                E: BuiltinExecutor,
            {
                match self.kind {
                    $(
                        BuiltinKind::$ty => <$ty as BuiltinDefinition>::is_available(eval),
                    )*
                }
            }

            /// Selects this builtin as an attribute or top-level global value.
            ///
            /// # Errors
            ///
            /// Returns an evaluator error when selecting the builtin requires unsupported
            /// ambient state or heap allocation fails.
            pub(crate) fn select<E>(
                self,
                eval: &mut E,
                id: IrId,
                span: Span,
                symbol: Symbol,
            ) -> Result<E::Value, E::Error>
            where
                E: BuiltinExecutor,
            {
                match self.kind {
                    $(
                        BuiltinKind::$ty => <$ty as BuiltinDefinition>::select(
                            eval,
                            id,
                            span,
                            symbol,
                        ),
                    )*
                }
            }

            /// Applies this builtin at a direct lowered IR call site.
            ///
            /// # Errors
            ///
            /// Returns an evaluator error when arity validation fails, argument forcing
            /// fails, or the builtin implementation reports a runtime diagnostic.
            pub(crate) fn apply_direct<E>(
                self,
                eval: &mut E,
                call: BuiltinCall,
                node: &IrNode,
                args: &[IrId],
            ) -> Result<E::Value, E::Error>
            where
                E: BuiltinExecutor,
            {
                match self.kind {
                    $(
                        BuiltinKind::$ty => <$ty as BuiltinDefinition>::apply_direct(
                            eval,
                            call,
                            node,
                            args,
                        ),
                    )*
                }
            }

            /// Applies this builtin after it has been selected as a first-class value.
            ///
            /// # Errors
            ///
            /// Returns an evaluator error when arity validation fails, argument forcing
            /// fails, or the builtin implementation reports a runtime diagnostic.
            pub(crate) fn apply<E>(
                self,
                eval: &mut E,
                call: BuiltinCall,
                args: &[EvalPrimOpArg],
            ) -> Result<E::Value, E::Error>
            where
                E: BuiltinExecutor,
            {
                match self.kind {
                    $(
                        BuiltinKind::$ty => <$ty as BuiltinDefinition>::apply(
                            eval,
                            call,
                            args,
                        ),
                    )*
                }
            }
        }

        builtin_registry! {
            $(
                $ty,
            )*
        }
    };
}

macro_rules! builtin_docs {
    ($summary:literal) => {
        &BuiltinDocs { summary: $summary }
    };
}
