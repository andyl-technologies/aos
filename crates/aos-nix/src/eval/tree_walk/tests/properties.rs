//! Tree-walk evaluator tests: property checks for high-risk semantic invariants.

use super::*;
use proptest::prelude::*;

const GENERATED_DERIVATION_CONTROL_KEYS: &[&str] = &[
    "__contentAddressed",
    "__impure",
    "__ignoreNulls",
    "__structuredAttrs",
    "args",
    "builder",
    "name",
    "out",
    "outputHash",
    "outputHashAlgo",
    "outputHashMode",
    "outputs",
    "system",
];

fn attr_name_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![b'a'..=b'z', b'A'..=b'Z', b'0'..=b'9', Just(b'_')],
        1..8,
    )
    .prop_filter("attribute names must not start with a digit", |bytes| {
        bytes
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    })
    .prop_map(|bytes| String::from_utf8(bytes).expect("generated attr names are ASCII"))
}

fn plain_string_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            b'a'..=b'z',
            b'A'..=b'Z',
            b'0'..=b'9',
            Just(b' '),
            Just(b'_'),
            Just(b'-')
        ],
        0..12,
    )
    .prop_map(|bytes| String::from_utf8(bytes).expect("generated strings are ASCII"))
}

fn small_int_strategy() -> impl Strategy<Value = i64> {
    0_i64..=10_000_i64
}

fn small_int_list_strategy() -> impl Strategy<Value = Vec<i64>> {
    prop::collection::vec(small_int_strategy(), 0..8)
}

fn attr_map_strategy() -> impl Strategy<Value = BTreeMap<String, i64>> {
    prop::collection::btree_map(attr_name_strategy(), small_int_strategy(), 0..8)
}

fn derivation_env_strategy() -> impl Strategy<Value = BTreeMap<String, String>> {
    prop::collection::btree_map(attr_name_strategy(), plain_string_strategy(), 0..8).prop_filter(
        "generated derivation env keys must not override mandatory derivation fields",
        |attrs| {
            !attrs
                .keys()
                .any(|key| GENERATED_DERIVATION_CONTROL_KEYS.contains(&key.as_str()))
        },
    )
}

fn nix_list(values: &[i64]) -> String {
    let body = values
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    format!("[ {body} ]")
}

fn nix_attrset(attrs: &BTreeMap<String, i64>) -> String {
    let body = attrs
        .iter()
        .map(|(name, value)| format!("{} = {value};", nix_string_literal(name)))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{{ {body} }}")
}

fn nix_string_attrset(attrs: &BTreeMap<String, String>) -> String {
    let body = attrs
        .iter()
        .map(|(name, value)| {
            format!(
                "{} = {};",
                nix_string_literal(name),
                nix_string_literal(value)
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!("{{ {body} }}")
}

fn derivation_env_source(env: &BTreeMap<String, String>) -> String {
    format!(
        "derivationStrict ({{ name = \"prop\"; system = \"x86_64-linux\"; builder = \":\"; }} // {})",
        nix_string_attrset(env)
    )
}

fn hash_pair_source(text: &str) -> String {
    let literal = nix_string_literal(text);
    format!(
        "let x = {literal}; in [ (builtins.hashString \"sha256\" x) (builtins.hashString \"sha256\" x) ]",
    )
}

fn context_free_source(left: &str, right: &str) -> String {
    format!(
        "let left = {}; right = {}; in [ \
         (builtins.hasContext left) \
         (builtins.hasContext (left + right)) \
         (builtins.hasContext \"${{left}}${{right}}\") \
         (builtins.hasContext (builtins.substring 0 3 left)) \
         ]",
        nix_string_literal(left),
        nix_string_literal(right),
    )
}

fn contextful_string(text: &str, path: &str) -> String {
    format!(
        "builtins.appendContext {} {{ {} = {{ path = true; }}; }}",
        nix_string_literal(text),
        nix_string_literal(path),
    )
}

fn context_propagation_source(left: &str, right: &str) -> String {
    let left_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-left";
    let right_path = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-right";
    let source_path = "/nix/store/cccccccccccccccccccccccccccccccc-source";
    let used_path = "/nix/store/dddddddddddddddddddddddddddddddd-used";
    format!(
        "let \
         left = {}; \
         right = {}; \
         source = {}; \
         used = {}; \
         in {{ \
         concat = builtins.getContext (left + right); \
         interpolation = builtins.getContext \"${{left}}${{right}}\"; \
         substring = builtins.getContext (builtins.substring 0 1 left); \
         replace = builtins.getContext (builtins.replaceStrings [ \"a\" \"z\" ] [ used right ] source); \
         updateLhs = builtins.getContext (({{ k = left; }} // {{ other = right; }}).k); \
         updateRhs = builtins.getContext (({{ k = left; }} // {{ k = right; }}).k); \
         listFirst = builtins.getContext (builtins.elemAt ([ left ] ++ [ right ]) 0); \
         listSecond = builtins.getContext (builtins.elemAt ([ left ] ++ [ right ]) 1); \
         }}",
        contextful_string(left, left_path),
        contextful_string(right, right_path),
        contextful_string("abcabc", source_path),
        contextful_string("X", used_path),
    )
}

fn context_keys(
    report: &BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    field: &str,
) -> BTreeSet<String> {
    report
        .get(field)
        .unwrap_or_else(|| panic!("context report contains {field}"))
        .keys()
        .cloned()
        .collect()
}

fn first_derivation_aterm(source: &str) -> Vec<u8> {
    let outcome = eval_whnf_owned(&lower(source)).expect("derivation source evaluates");
    outcome
        .derivations()
        .first()
        .and_then(EvalDerivation::aterm_bytes)
        .expect("evaluating derivationStrict records ATerm bytes")
        .to_vec()
}

fn first_derivation_environment_keys(source: &str) -> Vec<String> {
    let aterm = first_derivation_aterm(source);
    nix_compat::derivation::Derivation::from_aterm_bytes(&aterm)
        .expect("recorded derivation ATerm parses");
    let final_list = aterm
        .iter()
        .rposition(|byte| *byte == b'[')
        .expect("derivation ATerm contains an environment list");
    let mut index = final_list + 1;
    let mut keys = Vec::new();

    while index < aterm.len() {
        match aterm[index] {
            b']' => return keys,
            b',' => index += 1,
            b'(' => {
                index += 1;
                keys.push(parse_unescaped_aterm_string(&aterm, &mut index));
                assert_eq!(aterm[index], b',', "environment entry has key/value comma");
                index += 1;
                skip_aterm_string(&aterm, &mut index);
                assert_eq!(aterm[index], b')', "environment entry closes");
                index += 1;
            }
            byte => panic!("unexpected byte in derivation environment ATerm: {byte:?}"),
        }
    }

    panic!("unterminated derivation environment ATerm")
}

fn parse_unescaped_aterm_string(aterm: &[u8], index: &mut usize) -> String {
    assert_eq!(aterm[*index], b'"', "ATerm string opens");
    *index += 1;
    let start = *index;
    while *index < aterm.len() && aterm[*index] != b'"' {
        assert_ne!(
            aterm[*index], b'\\',
            "generated environment keys are unescaped"
        );
        *index += 1;
    }
    let bytes = &aterm[start..*index];
    assert_eq!(aterm[*index], b'"', "ATerm string closes");
    *index += 1;
    String::from_utf8(bytes.to_vec()).expect("generated ATerm string is UTF-8")
}

fn skip_aterm_string(aterm: &[u8], index: &mut usize) {
    assert_eq!(aterm[*index], b'"', "ATerm string opens");
    *index += 1;
    while *index < aterm.len() {
        match aterm[*index] {
            b'\\' => *index += 2,
            b'"' => {
                *index += 1;
                return;
            }
            _ => *index += 1,
        }
    }

    panic!("unterminated ATerm string")
}

proptest! {
    #[test]
    fn attr_names_are_sorted_by_generated_key_order(attrs in attr_map_strategy()) {
        let source = format!("builtins.attrNames {}", nix_attrset(&attrs));
        let actual: Vec<String> = serde_json::from_slice(&eval_json_bytes(&source))
            .expect("attrNames JSON decodes");
        let expected = attrs.keys().cloned().collect::<Vec<_>>();

        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn attr_update_is_rhs_biased(lhs in attr_map_strategy(), rhs in attr_map_strategy()) {
        let source = format!("({} // {})", nix_attrset(&lhs), nix_attrset(&rhs));
        let actual: BTreeMap<String, i64> = serde_json::from_slice(&eval_json_bytes(&source))
            .expect("updated attrset JSON decodes");
        let mut expected = lhs;
        expected.extend(rhs);

        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn list_concat_preserves_element_order(
        left in small_int_list_strategy(),
        middle in small_int_list_strategy(),
        right in small_int_list_strategy(),
    ) {
        let source = format!("{} ++ {} ++ {}", nix_list(&left), nix_list(&middle), nix_list(&right));
        let actual: Vec<i64> = serde_json::from_slice(&eval_json_bytes(&source))
            .expect("concatenated list JSON decodes");
        let expected = left
            .into_iter()
            .chain(middle)
            .chain(right)
            .collect::<Vec<_>>();

        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn hash_string_sha256_is_deterministic(text in plain_string_strategy()) {
        let source = hash_pair_source(&text);
        let actual: Vec<String> = serde_json::from_slice(&eval_json_bytes(&source))
            .expect("hash JSON decodes");

        prop_assert_eq!(actual.len(), 2);
        prop_assert_eq!(&actual[0], &actual[1]);
    }

    #[test]
    fn context_free_string_operations_stay_context_free(
        left in plain_string_strategy(),
        right in plain_string_strategy(),
    ) {
        let source = context_free_source(&left, &right);
        let actual: Vec<bool> = serde_json::from_slice(&eval_json_bytes(&source))
            .expect("context JSON decodes");

        prop_assert_eq!(actual, vec![false, false, false, false]);
    }

    #[test]
    fn contextful_operations_preserve_expected_contexts(
        left in plain_string_strategy(),
        right in plain_string_strategy(),
    ) {
        let source = context_propagation_source(&left, &right);
        let actual: BTreeMap<String, BTreeMap<String, serde_json::Value>> =
            serde_json::from_slice(&eval_json_bytes(&source)).expect("context JSON decodes");
        let left_context =
            BTreeSet::from(["/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-left".to_owned()]);
        let right_context =
            BTreeSet::from(["/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-right".to_owned()]);
        let source_path = "/nix/store/cccccccccccccccccccccccccccccccc-source".to_owned();
        let used = "/nix/store/dddddddddddddddddddddddddddddddd-used".to_owned();
        let union = left_context
            .union(&right_context)
            .cloned()
            .collect::<BTreeSet<_>>();
        let replace = BTreeSet::from([source_path, used]);

        prop_assert_eq!(context_keys(&actual, "concat"), union.clone());
        prop_assert_eq!(context_keys(&actual, "interpolation"), union);
        prop_assert_eq!(context_keys(&actual, "substring"), left_context.clone());
        prop_assert_eq!(context_keys(&actual, "replace"), replace);
        prop_assert_eq!(context_keys(&actual, "updateLhs"), left_context.clone());
        prop_assert_eq!(context_keys(&actual, "updateRhs"), right_context.clone());
        prop_assert_eq!(context_keys(&actual, "listFirst"), left_context);
        prop_assert_eq!(context_keys(&actual, "listSecond"), right_context);
    }

    #[test]
    fn derivation_environment_keys_remain_sorted(env in derivation_env_strategy()) {
        let actual = first_derivation_environment_keys(&derivation_env_source(&env));
        let expected = env
            .keys()
            .cloned()
            .chain(["builder", "name", "out", "system"].into_iter().map(String::from))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn derivation_aterm_bytes_are_deterministic(env in derivation_env_strategy()) {
        let source = derivation_env_source(&env);

        prop_assert_eq!(first_derivation_aterm(&source), first_derivation_aterm(&source));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn generated_core_json_expressions_match_configured_cpp_nix(
        attrs in attr_map_strategy(),
        left in small_int_list_strategy(),
        right in small_int_list_strategy(),
        text in plain_string_strategy(),
        context_left in plain_string_strategy(),
        context_right in plain_string_strategy(),
        contextful_left in plain_string_strategy(),
        contextful_right in plain_string_strategy(),
        env in derivation_env_strategy(),
    ) {
        let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
            return Ok(());
        };
        assert_pinned_cpp_nix_oracle(&oracle);
        let source = format!(
            "{{ \
             names = builtins.attrNames {}; \
             values = {} ++ {}; \
             hashes = {}; \
             context = {}; \
             contextful = {}; \
             drv = {}; \
             }}",
            nix_attrset(&attrs),
            nix_list(&left),
            nix_list(&right),
            hash_pair_source(&text),
            context_free_source(&context_left, &context_right),
            context_propagation_source(&contextful_left, &contextful_right),
            derivation_env_source(&env),
        );

        prop_assert_eq!(eval_json_bytes(&source), cpp_nix_eval_json(&oracle, &source));
    }
}
