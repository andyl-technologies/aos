//! Flag parsing and postprocess support for upstream `lang.sh` cases.

use super::support::*;

#[test]
fn lang_sh_noop_eval_flags_are_supported() {
    let lang_dir = fixture_lang_dir();
    let strict_eval_flags = ["--eval", "--strict"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let eval_fail_no_trace_flags = ["--eval", "--strict", "--no-show-trace"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let trace_only_flags = ["--no-show-trace"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    assert!(lang_case_options(LangCategory::EvalOkay, &strict_eval_flags, &lang_dir).is_ok());
    assert!(
        lang_case_options(LangCategory::EvalFail, &eval_fail_no_trace_flags, &lang_dir).is_ok()
    );
    assert_eq!(
        lang_case_options(LangCategory::EvalFail, &trace_only_flags, &lang_dir),
        Err("case carries unsupported flags: --no-show-trace".to_owned())
    );
    assert_eq!(
        lang_case_options(LangCategory::ParseOkay, &strict_eval_flags, &lang_dir),
        Err("case carries unsupported flags: --eval --strict".to_owned())
    );
}

#[test]
fn lang_sh_max_call_depth_flag_configures_eval() {
    let lang_dir = fixture_lang_dir();
    let max_call_depth_flags = ["--max-call-depth", "3"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let max_call_depth_with_trace_flags = ["--max-call-depth", "3", "--no-show-trace"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let max_call_depth_with_eval_flags = ["--max-call-depth", "3", "--eval", "--strict"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let options = lang_case_options(LangCategory::EvalFail, &max_call_depth_flags, &lang_dir)
        .expect("max-call-depth flag should be supported");
    assert_eq!(options.max_call_depth(), 3);
    assert_eq!(
        lang_case_options(
            LangCategory::EvalFail,
            &max_call_depth_with_trace_flags,
            &lang_dir
        ),
        Err("case carries unsupported flags: --max-call-depth 3 --no-show-trace".to_owned())
    );
    assert_eq!(
        lang_case_options(
            LangCategory::EvalFail,
            &max_call_depth_with_eval_flags,
            &lang_dir
        ),
        Err("case carries unsupported flags: --max-call-depth 3 --eval --strict".to_owned())
    );
}

#[test]
fn recursive_lambda_eval_fail_preserves_the_default_max_call_depth() {
    let lang_dir = fixture_lang_dir();
    let default_max_call_depth = base_eval_options(&lang_dir)
        .expect("base options configure")
        .max_call_depth();
    let case = LangCase {
        name: "eval-fail-infinite-recursion-lambda".to_owned(),
        category: LangCategory::EvalFail,
        source: lang_dir.join("eval-fail-infinite-recursion-lambda.nix"),
        expected: Some(lang_dir.join("eval-fail-infinite-recursion-lambda.err.exp")),
        expected_xml: None,
        postprocess: None,
        flags: Vec::new(),
        disabled: false,
    };

    let config =
        lang_case_config_for_case(&case, &lang_dir).expect("recursive lambda case configures");
    assert_eq!(config.options.max_call_depth(), default_max_call_depth);
}

#[test]
fn lang_sh_search_path_flags_configure_eval_okay() {
    let lang_dir = fixture_lang_dir();
    let search_path_flags = ["-I", "lang/dir1", "-I", "lang/dir2", "-I", "dir5=lang/dir3"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let options = lang_case_options(LangCategory::EvalOkay, &search_path_flags, &lang_dir)
        .expect("search-path flags should be supported");
    assert_eq!(
        options.search_path_base(),
        path_bytes(&lang_dir.parent().unwrap())
    );
    assert_eq!(options.nix_path().len(), 5);
    assert_eq!(
        options.corepkgs_path(),
        Some(path_bytes(&fixture_corepkgs_dir()).as_slice())
    );
}

#[test]
fn lang_sh_experimental_feature_flags_configure_eval_okay() {
    let lang_dir = fixture_lang_dir();
    let timestamp_flags = ["--extra-experimental-features", "parse-toml-timestamps"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unsupported_feature_flags = ["--extra-experimental-features", "flakes"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let missing_feature_flags = ["--extra-experimental-features"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let options = lang_case_options(LangCategory::EvalOkay, &timestamp_flags, &lang_dir)
        .expect("parse-toml-timestamps should be supported");
    assert!(options.parse_toml_timestamps());
    assert_eq!(options.nix_path().len(), 2);
    assert_eq!(
        lang_case_options(
            LangCategory::EvalOkay,
            &unsupported_feature_flags,
            &lang_dir
        ),
        Err("case carries unsupported flags: --extra-experimental-features flakes".to_owned())
    );
    assert_eq!(
        lang_case_options(LangCategory::EvalOkay, &missing_feature_flags, &lang_dir),
        Err("case carries unsupported flags: --extra-experimental-features".to_owned())
    );
    assert_eq!(
        lang_case_options(LangCategory::ParseOkay, &timestamp_flags, &lang_dir),
        Err(
            "case carries unsupported flags: --extra-experimental-features parse-toml-timestamps"
                .to_owned()
        )
    );
}

#[test]
fn lang_sh_autoarg_flags_configure_eval_okay() {
    let lang_dir = fixture_lang_dir();
    let autoarg_flags = [
        "--arg",
        "lib",
        "import(lang/lib.nix)",
        "--argstr",
        "xyzzy",
        "xyzzy!",
        "-A",
        "result",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    let unsupported_autoarg_flags = ["--arg", "lib", "builtins"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unsupported_name_flags = ["--argstr", "bad-name", "value"]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let unsupported_attr_flags = ["-A", "\"quoted.attr\""]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

    let config = lang_case_config(LangCategory::EvalOkay, &autoarg_flags, &lang_dir)
        .expect("autoarg flags should be supported");
    assert_eq!(config.auto_args.len(), 2);
    assert_eq!(config.attr_path, vec![b"result".to_vec()]);
    assert_eq!(config.options.nix_path().len(), 2);

    assert_eq!(
        wrap_eval_okay_source(
            b"{ lib, xyzzy }: { result = xyzzy; }",
            &lang_dir,
            &config,
            &autoarg_flags
        )
        .expect("autoarg source should wrap"),
        format!(
            "(({{ lib, xyzzy }}: {{ result = xyzzy; }}) {{ lib = import {}/lib.nix; xyzzy = \"xyzzy!\"; }}).\"result\"",
            lang_dir.display()
        )
    );
    assert_eq!(
        nix_string_literal(b"${oops}", &autoarg_flags).expect("string literal should escape"),
        "\"\\${oops}\""
    );
    assert_eq!(
        lang_case_config(
            LangCategory::EvalOkay,
            &unsupported_autoarg_flags,
            &lang_dir
        ),
        Err("case carries unsupported flags: --arg lib builtins".to_owned())
    );
    assert_eq!(
        lang_case_config(LangCategory::EvalOkay, &unsupported_name_flags, &lang_dir),
        Err("case carries unsupported flags: --argstr bad-name value".to_owned())
    );
    assert_eq!(
        lang_case_config(LangCategory::EvalOkay, &unsupported_attr_flags, &lang_dir),
        Err("case carries unsupported flags: -A \"quoted.attr\"".to_owned())
    );
}

#[test]
fn lang_sh_digit_normalizer_postprocess_is_supported() -> Result<()> {
    let lang_dir = fixture_lang_dir();
    let case = discover_lang_cases(&lang_dir)?
        .into_iter()
        .find(|case| case.name == "eval-okay-postprocess")
        .expect("postprocess fixture exists");
    assert_eq!(
        lang_case_postprocess(&case),
        Ok(Some(LangPostprocess {
            target: LangOutput::Out
        }))
    );
    let err_script = format!("{}\n", digit_normalizer_postprocess_lines("err").join("\n"));
    assert_eq!(
        parse_lang_postprocess(&err_script),
        Ok(LangPostprocess {
            target: LangOutput::Err
        })
    );

    let mut output = b"       9| value 1234\n".to_vec();
    let postprocess = lang_case_postprocess(&case).map_err(anyhow::Error::msg)?;
    apply_lang_postprocess(&mut output, LangOutput::Out, postprocess);
    assert_eq!(output, b"<number>| value <number>\n");
    assert_eq!(parse_lang_postprocess("echo unsupported"), Err(()));

    Ok(())
}
