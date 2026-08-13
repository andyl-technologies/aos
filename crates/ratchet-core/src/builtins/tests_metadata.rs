//! Tests for builtin declaration metadata: arity, availability, native
//! fallback policy, executor dispatch, and custom declaration overrides.

use super::*;

#[test]
fn builtin_declarations_record_direct_arity_by_direct_lowering() {
    assert_eq!(
        BuiltinDirect::DerivationStrict.arity(),
        1,
        "derivationStrict consumes one argument"
    );
    assert_eq!(
        BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Pure,
        }
        .arity(),
        1
    );
    assert_eq!(
        BuiltinDirect::LazyUnary {
            effect: BuiltinEffect::Pure,
        }
        .arity(),
        1
    );
    assert_eq!(
        BuiltinDirect::StrictBinary {
            effect: BuiltinEffect::Pure,
        }
        .arity(),
        2
    );
    assert_eq!(
        BuiltinDirect::StrictLazyBinary {
            effect: BuiltinEffect::Pure,
        }
        .arity(),
        2
    );
    assert_eq!(
        BuiltinDirect::LazyStrictBinary {
            effect: BuiltinEffect::Pure,
        }
        .arity(),
        2
    );
    assert_eq!(
        BuiltinDirect::Sort {
            effect: BuiltinEffect::Pure,
        }
        .arity(),
        2
    );
    assert_eq!(
        BuiltinDirect::StrictTernary {
            effect: BuiltinEffect::Pure,
        }
        .arity(),
        3
    );

    for builtin in BUILTINS.iter().copied() {
        if let Some(direct) = builtin.direct() {
            assert_eq!(
                builtin.first_class_arity(),
                Some(direct.arity()),
                "{} direct and first-class arity should match until a builtin explicitly needs different call surfaces",
                String::from_utf8_lossy(builtin.name()),
            );
        }
    }
}

#[test]
fn builtin_declarations_record_contextual_availability() {
    assert_eq!(
        BUILTINS.lookup(b"length").unwrap().availability(),
        BuiltinAvailability::Always
    );
    assert_eq!(
        BUILTINS.lookup(b"currentSystem").unwrap().availability(),
        BuiltinAvailability::ImpureCurrentSystem
    );
    assert_eq!(
        BUILTINS.lookup(b"currentTime").unwrap().availability(),
        BuiltinAvailability::ImpureCurrentTime
    );
}

#[test]
fn builtin_declarations_record_native_fallback_policy() {
    for name in [
        b"derivation".as_slice(),
        b"derivationStrict".as_slice(),
        b"fetchMercurial".as_slice(),
        b"fetchTree".as_slice(),
        b"fetchurl".as_slice(),
        b"getEnv".as_slice(),
        b"hashFile".as_slice(),
        b"readFile".as_slice(),
        b"trace".as_slice(),
    ] {
        assert!(
            BUILTINS
                .lookup(name)
                .unwrap()
                .native_cli_fallback_feature()
                .is_some(),
            "{} should require CLI fallback",
            String::from_utf8_lossy(name),
        );
    }

    for name in [
        b"length".as_slice(),
        b"lessThan".as_slice(),
        b"nixVersion".as_slice(),
        b"langVersion".as_slice(),
        b"parseFlakeRef".as_slice(),
        b"flakeRefToString".as_slice(),
    ] {
        assert!(
            !BUILTINS
                .lookup(name)
                .unwrap()
                .native_cli_fallback_feature()
                .is_some(),
            "{} should stay native-evaluable",
            String::from_utf8_lossy(name),
        );
    }

    for name in [b"getFlake".as_slice()] {
        assert_eq!(
            BUILTINS.lookup(name).unwrap().native_cli_fallback_feature(),
            Some("flakes"),
            "{} should report flakes as the fallback feature",
            String::from_utf8_lossy(name),
        );
    }

    assert_eq!(
        BUILTINS
            .lookup(b"fetchurl")
            .unwrap()
            .native_cli_fallback_feature(),
        Some("CLI-sensitive builtin evaluation")
    );
    assert_eq!(
        BUILTINS
            .lookup(b"length")
            .unwrap()
            .native_cli_fallback_feature(),
        None
    );
}

#[test]
fn builtin_accessors_return_stored_declaration_metadata() {
    for builtin in BUILTINS.iter() {
        assert_eq!(builtin.direct(), builtin.direct, "{builtin:?}");
        assert_eq!(
            builtin.first_class_arity(),
            builtin.first_class_arity,
            "{builtin:?}",
        );
        assert_eq!(builtin.availability(), builtin.availability, "{builtin:?}");
        assert_eq!(
            builtin.native_cli_fallback_feature(),
            builtin
                .native_cli_fallback_feature
                .map(NativeCliFallbackFeature::label),
            "{builtin:?}",
        );
    }
}

static OVERRIDE_PROBE_DOCS: BuiltinDocs = BuiltinDocs {
    summary: "Exercises test-only declaration metadata overrides.",
};

struct OverrideProbeBuiltin;

impl BuiltinDefinition for OverrideProbeBuiltin {
    const KIND: BuiltinKind = BuiltinKind::LengthBuiltin;
    const NAME: &'static [u8] = b"overrideProbe";
    const EXECUTION: BuiltinExecution = BuiltinExecution::strict_unary(StrictUnaryPrimOp::Length);
    const DIRECT: Option<BuiltinDirect> = Some(BuiltinDirect::LazyUnary {
        effect: BuiltinEffect::Effectful,
    });
    const FIRST_CLASS_ARITY: Option<usize> = Some(3);
    const AVAILABILITY: BuiltinAvailability = BuiltinAvailability::ImpureCurrentSystem;
    const NAME_SCOPE: BuiltinNameScope = BuiltinNameScope::UnshadowableGlobal;
    const NATIVE_CLI_FALLBACK_FEATURE: Option<NativeCliFallbackFeature> =
        Some(NativeCliFallbackFeature::Flakes);
    const DOCS: &'static BuiltinDocs = &OVERRIDE_PROBE_DOCS;
}

#[test]
fn builtin_definition_overrides_are_stored_on_declaration() {
    let builtin = OverrideProbeBuiltin::DECLARATION;

    assert_eq!(
        builtin.execution(),
        BuiltinExecution::strict_unary(StrictUnaryPrimOp::Length)
    );
    assert_eq!(
        builtin.direct(),
        Some(BuiltinDirect::LazyUnary {
            effect: BuiltinEffect::Effectful,
        })
    );
    assert_ne!(builtin.direct(), builtin.execution().direct());
    assert_eq!(builtin.first_class_arity(), Some(3));
    assert_eq!(builtin.direct().map(BuiltinDirect::arity), Some(1));
    assert_ne!(
        builtin.direct().map(BuiltinDirect::arity),
        builtin.first_class_arity()
    );
    assert_ne!(
        builtin.first_class_arity(),
        builtin.execution().first_class_arity()
    );
    assert_eq!(
        builtin.availability(),
        BuiltinAvailability::ImpureCurrentSystem
    );
    assert_eq!(builtin.name_scope(), BuiltinNameScope::UnshadowableGlobal);
    assert_eq!(builtin.native_cli_fallback_feature(), Some("flakes"));
    assert_eq!(
        builtin.docs().summary(),
        "Exercises test-only declaration metadata overrides."
    );
}

#[derive(Default)]
struct RecordingExecutor {
    calls: Vec<(&'static str, Builtin)>,
}

impl BuiltinExecutor for RecordingExecutor {
    type Value = &'static str;
    type Error = &'static str;
    type Arg = ();

    fn builtin_is_available(&self, builtin: Builtin) -> bool {
        builtin.name() == b"length"
    }

    fn select_builtin(
        &mut self,
        builtin: Builtin,
        _id: IrId,
        _span: Span,
        _symbol: Symbol,
    ) -> Result<Self::Value, Self::Error> {
        self.calls.push(("select", builtin));
        Ok("selected")
    }

    fn apply_builtin_direct(
        &mut self,
        builtin: Builtin,
        _call: BuiltinCall,
        _node: &IrNode,
        _args: &[IrId],
    ) -> Result<Self::Value, Self::Error> {
        self.calls.push(("direct", builtin));
        Ok("direct")
    }

    fn apply_builtin(
        &mut self,
        builtin: Builtin,
        _call: BuiltinCall,
        _args: &[Self::Arg],
    ) -> Result<Self::Value, Self::Error> {
        self.calls.push(("apply", builtin));
        Ok("applied")
    }
}

#[test]
fn generated_builtin_dispatch_reaches_generic_executor_with_selected_declaration() {
    use crate::{EffectClass, IrData, IrKind};

    let length = BUILTINS
        .lookup(b"length")
        .expect("length builtin is registered");
    let fetchurl = BUILTINS
        .lookup(b"fetchurl")
        .expect("fetchurl builtin is registered");
    let mut executor = RecordingExecutor::default();

    assert!(length.is_available(&executor));
    assert!(!fetchurl.is_available(&executor));

    let id = IrId::new(7);
    let span = Span::new(11, 17);
    let symbol = Symbol::new(3);
    let call = BuiltinCall::new(id, span, symbol);
    let node = IrNode::new(IrKind::Null, span, EffectClass::pure(), IrData::None);

    assert_eq!(
        length.select(&mut executor, id, span, symbol),
        Ok("selected")
    );
    assert_eq!(
        length.apply_direct(&mut executor, call, &node, &[]),
        Ok("direct"),
    );
    assert_eq!(length.apply(&mut executor, call, &[]), Ok("applied"));
    assert_eq!(
        executor.calls,
        vec![("select", length), ("direct", length), ("apply", length),],
    );
}

#[test]
fn custom_builtin_declaration_stays_attached_to_definition() {
    let fetchurl = BUILTINS
        .lookup(b"fetchurl")
        .expect("fetchurl builtin is registered");

    assert_eq!(fetchurl.execution(), BuiltinExecution::Fetchurl);
    assert_eq!(
        fetchurl.direct(),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(fetchurl.first_class_arity(), Some(1));
    assert_eq!(
        fetchurl.native_cli_fallback_feature(),
        Some("CLI-sensitive builtin evaluation")
    );
    assert_eq!(
        fetchurl.docs().summary(),
        "Fetches a URL as a fixed-output store path."
    );

    let fetch_git = BUILTINS
        .lookup(b"fetchGit")
        .expect("fetchGit builtin is registered");

    assert_eq!(fetch_git.execution(), BuiltinExecution::FetchGit);
    assert_eq!(
        fetch_git.direct(),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(fetch_git.first_class_arity(), Some(1));
    assert_eq!(
        fetch_git.native_cli_fallback_feature(),
        Some("CLI-sensitive builtin evaluation")
    );
    assert_eq!(
        fetch_git.docs().summary(),
        "Fetches a pinned Git repository as a recursive fixed-output store path."
    );

    let fetch_tarball = BUILTINS
        .lookup(b"fetchTarball")
        .expect("fetchTarball builtin is registered");

    assert_eq!(fetch_tarball.execution(), BuiltinExecution::FetchTarball);
    assert_eq!(
        fetch_tarball.direct(),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(fetch_tarball.first_class_arity(), Some(1));
    assert_eq!(
        fetch_tarball.native_cli_fallback_feature(),
        Some("CLI-sensitive builtin evaluation")
    );
    assert_eq!(
        fetch_tarball.docs().summary(),
        "Fetches and unpacks a tarball as a recursive fixed-output store path."
    );

    let fetch_tree = BUILTINS
        .lookup(b"fetchTree")
        .expect("fetchTree builtin is registered");

    assert_eq!(fetch_tree.execution(), BuiltinExecution::FetchTree);
    assert_eq!(
        fetch_tree.direct(),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(fetch_tree.first_class_arity(), Some(1));
    assert_eq!(
        fetch_tree.native_cli_fallback_feature(),
        Some("CLI-sensitive builtin evaluation")
    );
    assert_eq!(
        fetch_tree.docs().summary(),
        "Fetches supported typed tree inputs as fixed-output store paths."
    );

    let get_flake = BUILTINS
        .lookup(b"getFlake")
        .expect("getFlake builtin is registered");
    assert_eq!(get_flake.execution(), BuiltinExecution::GetFlake);
    assert_eq!(
        get_flake.direct(),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Effectful
        })
    );
    assert_eq!(get_flake.first_class_arity(), Some(1));
    assert_eq!(get_flake.native_cli_fallback_feature(), Some("flakes"));
    assert_eq!(
        get_flake.docs().summary(),
        "Fetches and evaluates a flake reference when flakes are enabled."
    );

    let parse_flake_ref = BUILTINS
        .lookup(b"parseFlakeRef")
        .expect("parseFlakeRef builtin is registered");
    assert_eq!(parse_flake_ref.execution(), BuiltinExecution::ParseFlakeRef);
    assert_eq!(
        parse_flake_ref.direct(),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(parse_flake_ref.first_class_arity(), Some(1));
    assert_eq!(parse_flake_ref.native_cli_fallback_feature(), None);
    assert_eq!(
        parse_flake_ref.docs().summary(),
        "Parses flake-reference URL syntax into attrs."
    );

    let flake_ref_to_string = BUILTINS
        .lookup(b"flakeRefToString")
        .expect("flakeRefToString builtin is registered");
    assert_eq!(
        flake_ref_to_string.execution(),
        BuiltinExecution::FlakeRefToString
    );
    assert_eq!(
        flake_ref_to_string.direct(),
        Some(BuiltinDirect::StrictUnary {
            effect: BuiltinEffect::Pure
        })
    );
    assert_eq!(flake_ref_to_string.first_class_arity(), Some(1));
    assert_eq!(flake_ref_to_string.native_cli_fallback_feature(), None);
    assert_eq!(
        flake_ref_to_string.docs().summary(),
        "Converts flake-reference attrs to URL syntax."
    );
}

#[test]
fn custom_builtin_docs_stay_attached_to_declaration() {
    assert_eq!(
        BUILTINS.lookup(b"appendContext").unwrap().docs().summary(),
        "Returns a string with reflected string context appended."
    );
    assert_eq!(
        BUILTINS
            .lookup(b"addErrorContext")
            .unwrap()
            .docs()
            .summary(),
        "Adds a diagnostic context message to errors from an expression."
    );
    assert_eq!(
        BUILTINS.lookup(b"currentSystem").unwrap().docs().summary(),
        "Returns the configured target system when available."
    );
    assert_eq!(
        BUILTINS.lookup(b"genericClosure").unwrap().docs().summary(),
        "Computes the transitive closure of keyed attribute sets."
    );
    assert_eq!(
        BUILTINS.lookup(b"hashFile").unwrap().docs().summary(),
        "Returns the hex digest of a file's contents."
    );
    assert_eq!(
        BUILTINS.lookup(b"getEnv").unwrap().docs().summary(),
        "Returns a configured environment variable or an empty string."
    );
    assert_eq!(
        BUILTINS.lookup(b"fetchurl").unwrap().docs().summary(),
        "Fetches a URL as a fixed-output store path."
    );
    assert_eq!(
        BUILTINS.lookup(b"fetchTarball").unwrap().docs().summary(),
        "Fetches and unpacks a tarball as a recursive fixed-output store path."
    );
    assert_eq!(
        BUILTINS.lookup(b"fetchTree").unwrap().docs().summary(),
        "Fetches supported typed tree inputs as fixed-output store paths."
    );
    assert_eq!(
        BUILTINS.lookup(b"langVersion").unwrap().docs().summary(),
        "Returns the pinned Nix language version."
    );
    assert_eq!(
        BUILTINS.lookup(b"nixVersion").unwrap().docs().summary(),
        "Returns the pinned C++ Nix version string."
    );
    assert_eq!(
        BUILTINS.lookup(b"nixPath").unwrap().docs().summary(),
        "Returns the configured Nix search path entries."
    );
    assert_eq!(
        BUILTINS.lookup(b"pathExists").unwrap().docs().summary(),
        "Returns whether a path exists at evaluation time."
    );
    assert_eq!(
        BUILTINS.lookup(b"placeholder").unwrap().docs().summary(),
        "Returns the Nix placeholder string for a derivation output."
    );
    assert_eq!(
        BUILTINS.lookup(b"readDir").unwrap().docs().summary(),
        "Returns an attribute set describing a directory's entries."
    );
    assert_eq!(
        BUILTINS.lookup(b"readFile").unwrap().docs().summary(),
        "Returns the contents of a file as a string."
    );
    assert_eq!(
        BUILTINS.lookup(b"readFileType").unwrap().docs().summary(),
        "Returns the filesystem type of a path."
    );
    assert_eq!(
        BUILTINS.lookup(b"storeDir").unwrap().docs().summary(),
        "Returns the configured Nix store directory."
    );
    assert_eq!(
        BUILTINS.lookup(b"storePath").unwrap().docs().summary(),
        "Returns a store path as a context-carrying string."
    );
    assert_eq!(
        BUILTINS.lookup(b"toPath").unwrap().docs().summary(),
        "Coerces an absolute path-like value to a normalized string."
    );
    assert_eq!(
        BUILTINS.lookup(b"tryEval").unwrap().docs().summary(),
        "Evaluates an expression to WHNF and reports catchable failures."
    );
    assert_eq!(
        BUILTINS.lookup(b"trace").unwrap().docs().summary(),
        "Prints a value to stderr and returns the second argument."
    );
    assert_eq!(
        BUILTINS.lookup(b"traceVerbose").unwrap().docs().summary(),
        "Conditionally prints a value to stderr and returns the second argument."
    );
    assert_eq!(
        BUILTINS.lookup(b"warn").unwrap().docs().summary(),
        "Prints a warning to stderr and returns the second argument."
    );
}

#[test]
fn builtin_declarations_all_have_explicit_docs() {
    for builtin in BUILTINS.iter() {
        let summary = builtin.docs().summary();
        assert!(
            !summary.is_empty(),
            "{} should have builtin docs",
            String::from_utf8_lossy(builtin.name())
        );
        assert!(
            !summary.contains("not been imported"),
            "{} should not use placeholder builtin docs",
            String::from_utf8_lossy(builtin.name())
        );
        assert!(
            summary.ends_with('.'),
            "{} docs should be a complete sentence",
            String::from_utf8_lossy(builtin.name())
        );
    }
}
