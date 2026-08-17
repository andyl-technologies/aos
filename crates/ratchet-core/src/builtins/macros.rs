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
        pub const BUILTIN_DECLARATIONS: &[Builtin] = &[
            $(
                <$ty as BuiltinDefinition>::DECLARATION,
            )*
        ];
        pub const BUILTIN_LOOKUP_LEN: usize = BUILTIN_DECLARATIONS.len();
        pub type BuiltinLookup = BuiltinLookupTable<BUILTIN_LOOKUP_LEN>;
        pub const BUILTIN_LOOKUP: BuiltinLookup = BuiltinLookupTable::build(BUILTIN_DECLARATIONS);

        /// Builtin declarations recognized by the resolver and evaluator.
        pub const BUILTINS: BuiltinRegistry =
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
        pub enum BuiltinKind {
            $(
                $ty,
            )*
        }

        $(
            pub struct $ty;
            impl BuiltinDefinition for $impl_ty {
                const KIND: BuiltinKind = BuiltinKind::$ty;
                $($body)*
            }
        )*

        impl Builtin {
            /// Reconstructs the declaration for a builtin kind.
            ///
            /// Every field of a [`Builtin`] is a compile-time constant of its
            /// [`BuiltinKind`], so this is the exact inverse of [`Builtin::kind`]:
            /// `Builtin::from_kind(b.kind()) == b` for every declaration. Resolution
            /// caches that store only the kind use this to recover the full record.
            pub const fn from_kind(kind: BuiltinKind) -> Self {
                match kind {
                    $(
                        BuiltinKind::$ty => <$ty as BuiltinDefinition>::DECLARATION,
                    )*
                }
            }

            /// Returns whether this builtin is visible in the current evaluator options.
            pub fn is_available<E>(self, eval: &E) -> bool
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
            pub fn select<E>(
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
            pub fn apply_direct<E>(
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
            pub fn apply<E>(
                self,
                eval: &mut E,
                call: BuiltinCall,
                args: &[E::Arg],
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
