//! Tree-walk evaluator tests: derivation 2.

use super::*;
use crate::cache::{CutoffDecision, EarlyCutoff, ValueHash};

#[test]
fn derivation_strict_supports_ignore_nulls() {
    let source = r#"let
             default = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             };
             withNull = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               foo = null;
             };
             ignored = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               foo = null;
               __ignoreNulls = true;
             };
             explicitFalse = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               foo = null;
               __ignoreNulls = false;
             };
             capital = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               A = null;
               __ignoreNulls = true;
             };
             argsNull = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               args = null;
               __ignoreNulls = true;
             };
             structuredFalse = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               __structuredAttrs = false;
               foo = null;
               __ignoreNulls = true;
             };
             unsupportedNulls = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               outputHash = null;
               outputHashAlgo = null;
               outputHashMode = null;
               __contentAddressed = null;
               allowedReferences = null;
               disallowedReferences = null;
               allowedRequisites = null;
               disallowedRequisites = null;
               exportReferencesGraph = null;
               __ignoreNulls = true;
             };
           in {
             argsNull = argsNull.drvPath;
             capital = capital.drvPath;
             default = default.drvPath;
             explicitFalse = explicitFalse.drvPath;
             ignored = ignored.drvPath;
             structuredFalse = structuredFalse.drvPath;
             unsupportedNulls = unsupportedNulls.drvPath;
             withNull = withNull.drvPath;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"argsNull":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","capital":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","default":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","explicitFalse":"/nix/store/gbihbhvs2za69fzg3gl91x0f7zcq1ii9-x.drv","ignored":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","structuredFalse":"/nix/store/ch3c4m4ba4r554gq3z26r8v9h80sp119-x.drv","unsupportedNulls":"/nix/store/bw7h8n8czwb6f7gvjl1cpb3al60lfzqy-x.drv","withNull":"/nix/store/gbihbhvs2za69fzg3gl91x0f7zcq1ii9-x.drv"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_preserves_non_utf8_environment_values() {
    let source = b"let d = derivationStrict {\n  name = \"x\";\n  system = \"x86_64-linux\";\n  builder = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder\";\n  raw = \"raw-\xff-byte\";\n}; in d.drvPath";
    let outcome = eval_whnf_owned(&lower_bytes(source)).expect("raw env bytes evaluate");
    let aterm = outcome
        .derivations()
        .iter()
        .find_map(EvalDerivation::aterm_bytes)
        .expect("static derivation has ATerm bytes");

    assert!(
        aterm
            .windows(b"raw-\xff-byte".len())
            .any(|window| window == b"raw-\xff-byte"),
        "{aterm:?}"
    );
}

#[test]
fn derivation_strict_aterm_value_hash_precursor_tracks_recorded_drv_bytes() {
    fn recorded_aterm(source: &str) -> Vec<u8> {
        let outcome = eval_whnf_owned(&lower(source)).expect("derivation evaluates");
        outcome
            .derivations()
            .iter()
            .find_map(EvalDerivation::aterm_bytes)
            .expect("static derivation has ATerm bytes")
            .to_vec()
    }

    let first_source = r#"let d = derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        env = "same";
    }; in d.drvPath"#;
    let changed_source = r#"let d = derivationStrict {
        name = "x";
        system = "x86_64-linux";
        builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
        env = "changed";
    }; in d.drvPath"#;

    let first_aterm = recorded_aterm(first_source);
    let same_aterm = recorded_aterm(first_source);
    let changed_aterm = recorded_aterm(changed_source);
    let first_hash = ValueHash::from_derivation_aterm_bytes(&first_aterm);
    let same_hash = ValueHash::from_derivation_aterm_bytes(&same_aterm);
    let changed_hash = ValueHash::from_derivation_aterm_bytes(&changed_aterm);

    assert_eq!(first_hash, same_hash);
    assert_ne!(first_hash, changed_hash);
    assert_eq!(
        EarlyCutoff::decide(Some(first_hash), same_hash),
        CutoffDecision::CutOff
    );
    assert_eq!(
        EarlyCutoff::decide(Some(first_hash), changed_hash),
        CutoffDecision::Propagate
    );
}
