//! Tree-walk evaluator tests for derivation validation and content-addressing behavior.

use super::*;

#[test]
fn derivation_strict_rejects_non_utf8_structural_fields() {
    for source in [
            b"derivationStrict {\n  name = \"x\";\n  system = \"x86_64-linux\";\n  builder = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-\xff-builder\";\n}"
                .as_slice(),
            b"derivationStrict {\n  name = \"x\";\n  system = \"x86_64-\xff-linux\";\n  builder = \"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder\";\n}"
                .as_slice(),
        ] {
            let error = eval_whnf_owned(&lower_bytes(source))
                .expect_err("structural derivation fields must stay UTF-8");
            assert!(
                matches!(
                    error.kind(),
                    TreeWalkErrorKind::DerivationStringUtf8 {
                        field: "environment value",
                        ..
                    }
                ),
                "{source:?}: {error:?}"
            );
        }
}

#[test]
fn derivation_strict_ignore_nulls_type_checks_flag_only() {
    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 __ignoreNulls = 1;
               }"#,
    ))
    .expect_err("ignoreNulls must be a bool");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = null;
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 __ignoreNulls = true;
               }"#,
    ))
    .expect_err("ignoreNulls does not skip the mandatory name attr");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = builtins.appendContext "x" {
                   "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                 };
                 system = "x86_64-linux";
                 builder = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-builder";
               }"#,
    ))
    .expect_err("derivation names cannot carry string context");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "derivationStrict",
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 __structuredAttrs = null;
                 __ignoreNulls = true;
               }"#,
    ))
    .expect_err("ignoreNulls does not skip structuredAttrs type checking");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "bool",
            actual: ValueTag::Null,
            ..
        }
    ));
}

#[test]
fn derivation_strict_rejects_invalid_derivation_names_before_later_attrs() {
    let long_name = "a".repeat(DERIVATION_NAME_MAX_LEN + 1);
    let cases = [
        ("", "name must not be empty"),
        ("bad/name", "contains illegal character '/'"),
        ("~jiggle~", "contains illegal character '~'"),
        (".", "name '.' is not valid"),
        (
            ".-component",
            "first dash-separated component must not be '.'",
        ),
        ("..", "name '..' is not valid"),
        (
            "..-component",
            "first dash-separated component must not be '..'",
        ),
        (long_name.as_str(), "must be no longer than 211 characters"),
    ];
    for (name, reason) in cases {
        let source = format!(
            r#"derivationStrict {{
                     name = {name:?};
                     system = builtins.throw "late";
                     builder = builtins.throw "late";
                   }}"#
        );
        let error = eval_whnf_owned(&lower(&source))
            .expect_err("invalid derivation name must be rejected before later attrs");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::DerivationStrict {
                    message,
                    ..
                } if message.contains("invalid derivation name")
                    && message.contains(reason)
            ),
            "{name:?}: {error:?}"
        );
    }

    let error = eval_whnf_owned(&lower(
        r#"derivationStrict {
                 name = builtins.fromJSON "\"cafe\\u0301\"";
                 system = builtins.throw "late";
                 builder = builtins.throw "late";
               }"#,
    ))
    .expect_err("non-ASCII derivation name must be rejected before later attrs");
    assert!(
        matches!(
            error.kind(),
            TreeWalkErrorKind::DerivationStrict {
                message,
                ..
            } if message.contains("invalid derivation name")
                && message.contains("contains illegal character '\u{301}'")
        ),
        "{error:?}"
    );
}

#[test]
fn derivation_strict_rejects_supported_names_ending_in_drv() {
    for source in [
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 __contentAddressed = true;
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 __impure = true;
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 outputs = "bad/name";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 __structuredAttrs = true;
                 outputs = [ "bad/name" ];
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 outputHash = "not-a-hash";
                 outputHashAlgo = "sha256";
                 outputHashMode = "recursive";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 outputHash = "";
               }"#,
        r#"derivationStrict {
                 name = "bad.drv";
                 system = ":";
                 builder = ":";
                 __contentAddressed = true;
                 __impure = true;
               }"#,
    ] {
        let error = eval_whnf_owned(&lower(source))
            .expect_err("supported derivation forms reject names ending in .drv");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::DerivationStrict {
                    message,
                    ..
                } if message.contains("end in '.drv'")
            ),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn derivation_strict_ignore_nulls_does_not_skip_args_elements() {
    let source = r#"let
             d = derivationStrict {
               name = "x";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               foo = null;
               __ignoreNulls = true;
               args = [ null ];
             };
           in {
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/4ljrbgdg50gl74wbgr53yvv23ap9bfrz-x.drv","out":"/nix/store/j6kab8pd56kjnp4z2zsvwcsdm7fmn37f-x"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_fixed_output_derivations() {
    let source = r#"let
             mk = attrs: derivationStrict ({
               name = "foo";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
             } // attrs);
             flat = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "sha256";
               outputHashMode = "flat";
             };
             recursive = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
             omittedMode = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "sha256";
             };
             omittedAlgo = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashMode = "recursive";
             };
             raw = mk {
               outputHash = "4374173a8cbe88de152b609f96f46e958bcf65762017474eec5a05ec2bd61530";
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
             emptyAlgo = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "";
               outputHashMode = "recursive";
             };
             bogusAlgo = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "bogus";
               outputHashMode = "recursive";
             };
             dashAlgo = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "sha-256";
               outputHashMode = "recursive";
             };
             upperAlgo = mk {
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
               outputHashAlgo = "SHA256";
               outputHashMode = "recursive";
             };
             emptyHash = mk {
               outputHash = "";
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
           in {
             bogusAlgo = bogusAlgo.out;
             bogusAlgoDrv = bogusAlgo.drvPath;
             dashAlgo = dashAlgo.out;
             dashAlgoDrv = dashAlgo.drvPath;
             drvFlat = flat.drvPath;
             drvRecursive = recursive.drvPath;
             emptyAlgo = emptyAlgo.out;
             emptyAlgoDrv = emptyAlgo.drvPath;
             emptyHash = emptyHash.out;
             emptyHashDrv = emptyHash.drvPath;
             flat = flat.out;
             omittedAlgo = omittedAlgo.out;
             omittedMode = omittedMode.out;
             raw = raw.out;
             recursive = recursive.out;
             upperAlgo = upperAlgo.out;
             upperAlgoDrv = upperAlgo.drvPath;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"bogusAlgo":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","bogusAlgoDrv":"/nix/store/2y7fz2ii2r75dvrxsqc2z3px3v159lzq-foo.drv","dashAlgo":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","dashAlgoDrv":"/nix/store/lbpn865wvns79mxjz1nf532s61rxvpv3-foo.drv","drvFlat":"/nix/store/jl08sl0js08lghpzy0vr5lz64wyf4vny-foo.drv","drvRecursive":"/nix/store/yxkyw9zabh90wi2ak4j2f43xx44j35k6-foo.drv","emptyAlgo":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","emptyAlgoDrv":"/nix/store/18fky491dplc3n09l99491ji924jv02j-foo.drv","emptyHash":"/nix/store/1dcapabdb1anckxk8md1m0dpqx5jmm73-foo","emptyHashDrv":"/nix/store/35lwba14kzq02b5mvk01v2rh042rdagf-foo.drv","flat":"/nix/store/q4pkwkxdib797fhk22p0k3g1q32jmxvf-foo","omittedAlgo":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","omittedMode":"/nix/store/q4pkwkxdib797fhk22p0k3g1q32jmxvf-foo","raw":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","recursive":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","upperAlgo":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","upperAlgoDrv":"/nix/store/3jp0xvy6sw6wfz1p2i3ja8swb2bjaaak-foo.drv"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_recursive_sha1_fixed_output_derivations() {
    let bar = r#"derivationStrict {
             name = "bar";
             system = ":";
             builder = ":";
             outputHash = "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33";
             outputHashAlgo = "sha1";
             outputHashMode = "recursive";
           }"#;
    let source = format!("let d = {bar}; in {{ drvPath = d.drvPath; out = d.out; }}");

    assert_eq!(
            eval_json_bytes(&source),
            br#"{"drvPath":"/nix/store/ss2p4wmxijn652haqyd7dckxwl4c7hxx-bar.drv","out":"/nix/store/mp57d33657rf34lzvlbpfa1gjfv5gmpg-bar"}"#.to_vec()
        );

    let outcome = eval_whnf_owned(&lower(&format!("let d = {bar}; in d.drvPath")))
        .expect("recursive SHA-1 fixed-output derivation evaluates");
    let recorded = outcome
        .derivations()
        .iter()
        .find(|drv| drv.absolute_path() == "/nix/store/ss2p4wmxijn652haqyd7dckxwl4c7hxx-bar.drv")
        .expect("recursive SHA-1 fixed-output derivation records ATerm bytes");

    assert_eq!(
            recorded.aterm_bytes(),
            Some(
                br#"Derive([("out","/nix/store/mp57d33657rf34lzvlbpfa1gjfv5gmpg-bar","r:sha1","0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33")],[],[],":",":",[],[("builder",":"),("name","bar"),("out","/nix/store/mp57d33657rf34lzvlbpfa1gjfv5gmpg-bar"),("outputHash","0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"),("outputHashAlgo","sha1"),("outputHashMode","recursive"),("system",":")])"#.as_slice()
            )
        );

    let downstream = format!(
        r#"let
                 bar = {bar};
                 foo = derivationStrict {{
                   name = "foo";
                   system = ":";
                   builder = ":";
                   bar = bar.out;
                 }};
               in {{ drvPath = foo.drvPath; out = foo.out; }}"#
    );
    assert_eq!(
            eval_json_bytes(&downstream),
            br#"{"drvPath":"/nix/store/ch49594n9avinrf8ip0aslidkc4lxkqv-foo.drv","out":"/nix/store/fhaj6gmwns62s6ypkcldbaj2ybvkhx3p-foo"}"#.to_vec()
        );

    let downstream_drv_path = format!(
        r#"let
                 bar = {bar};
                 foo = derivationStrict {{
                   name = "foo";
                   system = ":";
                   builder = ":";
                   bar = bar.out;
                 }};
               in foo.drvPath"#
    );
    let outcome = eval_whnf_owned(&lower(&downstream_drv_path))
        .expect("downstream derivation depending on SHA-1 FOD evaluates");
    let downstream_recorded = outcome
        .derivations()
        .iter()
        .find(|drv| drv.absolute_path() == "/nix/store/ch49594n9avinrf8ip0aslidkc4lxkqv-foo.drv")
        .expect("downstream derivation records ATerm bytes");

    assert_eq!(
            downstream_recorded.aterm_bytes(),
            Some(
                br#"Derive([("out","/nix/store/fhaj6gmwns62s6ypkcldbaj2ybvkhx3p-foo","","")],[("/nix/store/ss2p4wmxijn652haqyd7dckxwl4c7hxx-bar.drv",["out"])],[],":",":",[],[("bar","/nix/store/mp57d33657rf34lzvlbpfa1gjfv5gmpg-bar"),("builder",":"),("name","foo"),("out","/nix/store/fhaj6gmwns62s6ypkcldbaj2ybvkhx3p-foo"),("system",":")])"#.as_slice()
            )
        );
}

#[test]
fn derivation_strict_supports_disabled_content_addressed_marker() {
    let source = r#"let
             d = derivationStrict {
               name = "foo";
               system = "x86_64-linux";
               builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               __contentAddressed = false;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
           in {
             drvPath = d.drvPath;
             names = builtins.attrNames d;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"drvPath":"/nix/store/y73d5vkljj9wx7hxjpfswzv5m2cgz6xw-foo.drv","names":["drvPath","out"],"out":"/nix/store/i4v7l2ia22fdp6d1nfy4w836zbg3h6hv-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_disabled_impure_marker() {
    let source = r#"let
             explicitFalse = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __impure = false;
             };
             structuredFalse = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __impure = false;
             };
             ignoredNull = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __structuredAttrs = true;
               __impure = null;
               __ignoreNulls = true;
             };
           in {
             explicitFalseDrv = explicitFalse.drvPath;
             explicitFalseOut = explicitFalse.out;
             ignoredNullDrv = ignoredNull.drvPath;
             ignoredNullOut = ignoredNull.out;
             structuredFalseDrv = structuredFalse.drvPath;
             structuredFalseOut = structuredFalse.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"explicitFalseDrv":"/nix/store/byy6hf9vzifjqikj1wxh1dlz1k2mm55y-foo.drv","explicitFalseOut":"/nix/store/zyxk99gi89lp0n4acr3ingrdp8pwjqcp-foo","ignoredNullDrv":"/nix/store/qsg1hv3lkdblqrzknfz5hrwa2ylhqi7d-foo.drv","ignoredNullOut":"/nix/store/m1839r6ds9nkq40ndigls6fgmi6h4j6x-foo","structuredFalseDrv":"/nix/store/q0bwyr5jasf511qq3jzz93s31782kw17-foo.drv","structuredFalseOut":"/nix/store/9jld8vmqis8rk1n1vgcncxznx3s3v8yr-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_supports_floating_content_addressed_derivations() {
    let source = r#"let
             recursive = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
             flat = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "flat";
             };
             defaulted = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
             };
             multi = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               outputs = [ "out" "dev" ];
             };
           in {
             defaultDrv = defaulted.drvPath;
             defaultOut = defaulted.out;
             flatDrv = flat.drvPath;
             flatOut = flat.out;
             multiDev = multi.dev;
             multiDrv = multi.drvPath;
             multiNames = builtins.attrNames multi;
             multiOut = multi.out;
             recursiveCtx = builtins.getContext recursive.out;
             recursiveDrv = recursive.drvPath;
             recursiveDrvCtx = builtins.getContext recursive.drvPath;
             recursiveNames = builtins.attrNames recursive;
             recursiveOut = recursive.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"defaultDrv":"/nix/store/asqvh5kd8syak2nap6qfby2kzhad93ln-foo.drv","defaultOut":"/0va4qp2ahx6mzdj5jv1rmd902hpfaiqqqiacifnckwnv2ab0356k","flatDrv":"/nix/store/h45pc0783njkplw61p57klqwk4rq88wd-foo.drv","flatOut":"/0dy829a8ha7khjxzv6pc5fv0xfsgby2mdgqavyj8cnr610fgi1sm","multiDev":"/1zcx5za1flqh9fnmak474592n4lr9b55ign6qry5ycc0n0j9rzgv","multiDrv":"/nix/store/mj5lbvmrbi0wak4g3scs801dbh5rvd5k-foo.drv","multiNames":["dev","drvPath","out"],"multiOut":"/0qwqpv6x549qb5amk1slwbswzjh03n435ddw392rs6n5h2wbglr4","recursiveCtx":{"/nix/store/5d4gn8jbm861c1pcharmm24yzacv5x4h-foo.drv":{"outputs":["out"]}},"recursiveDrv":"/nix/store/5d4gn8jbm861c1pcharmm24yzacv5x4h-foo.drv","recursiveDrvCtx":{"/nix/store/5d4gn8jbm861c1pcharmm24yzacv5x4h-foo.drv":{"allOutputs":true}},"recursiveNames":["drvPath","out"],"recursiveOut":"/1h9lmzdzqh6czk0m08hbfk343704ykhfwfwz3160xnamfgggfjws"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_floating_ca_matches_cpp_nix_hash_algo_and_mode_parsing() {
    let source = r#"let
             bogus = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "bogus";
               outputHashMode = "recursive";
             };
             empty = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "";
               outputHashMode = "recursive";
             };
             nar = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "nar";
             };
             upper = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "SHA256";
               outputHashMode = "recursive";
             };
           in {
             bogusDrv = bogus.drvPath;
             bogusOut = bogus.out;
             emptyDrv = empty.drvPath;
             emptyOut = empty.out;
             narDrv = nar.drvPath;
             narOut = nar.out;
             upperDrv = upper.drvPath;
             upperOut = upper.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"bogusDrv":"/nix/store/sfvbsz4716wchmgqccrbgyx82bwwp0bl-foo.drv","bogusOut":"/1qxz9i2h42krf58nihzbybdd0i4nfskc85ywjvg1z3k7slnl1a4p","emptyDrv":"/nix/store/9g7if9vq9c7zfigby235xgcla16n3s5h-foo.drv","emptyOut":"/0khcai9n321warx3azdv4c16573x8pnc05pndwikd8rbzkrwbqh6","narDrv":"/nix/store/6w7snr1mlr3kq48cq8lj22vqc7fjw19h-foo.drv","narOut":"/137j0hqh4klrf447lfyfzjv4x37fbzwz5kv1drk36jg225dc539k","upperDrv":"/nix/store/05p9rdwygprb3xw84ybssjh06m1yziry-foo.drv","upperOut":"/0ky0f7m9zhjvl1s8fc60mvaayb9rf1f7l73acq5293n9r3lz3780"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_content_addressed_marker_preserves_fixed_output_derivation() {
    let source = r#"let
             recursive = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
             };
             nar = derivationStrict {
               name = "foo";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "nar";
               outputHash = "sha256-Q3QXOoy+iN4VK2CflvRulYvPZXYgF0dO7FoF7CvWFTA=";
             };
           in {
             narDrv = nar.drvPath;
             narOut = nar.out;
             recursiveDrv = recursive.drvPath;
             recursiveOut = recursive.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"narDrv":"/nix/store/g72ixp5q1kzsm4nk85fazw8x5zdw92dx-foo.drv","narOut":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo","recursiveDrv":"/nix/store/3yx7944f4sjjnh56pynw9i73mbmavwb9-foo.drv","recursiveOut":"/nix/store/17wgs52s7kcamcyin4ja58njkf91ipq8-foo"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_content_addressed_derivations_defer_downstream_outputs() {
    let source = r#"let
             base = derivationStrict {
               name = "base";
               system = ":";
               builder = ":";
               __contentAddressed = true;
               outputHashAlgo = "sha256";
               outputHashMode = "recursive";
             };
             d = derivationStrict {
               name = "user";
               system = ":";
               builder = ":";
               input = base.out;
             };
           in {
             baseDrv = base.drvPath;
             baseOut = base.out;
             ctx = builtins.getContext d.out;
             drvPath = d.drvPath;
             out = d.out;
           }"#;

    assert_eq!(
            eval_json_bytes(source),
            br#"{"baseDrv":"/nix/store/sycp28psd9pmlky6a4jpcb5lijdfjw6g-base.drv","baseOut":"/12b6k9m59nmk4z3mpbpi60a9626jbcihnxmydd980k8jvgwsb8ry","ctx":{"/nix/store/l6n89w9r2i5pn8p9asx7zkxpbqwwgi2y-user.drv":{"outputs":["out"]}},"drvPath":"/nix/store/l6n89w9r2i5pn8p9asx7zkxpbqwwgi2y-user.drv","out":"/0dgqgrnsrgzgjvxqfag1i449qjkl8fixagz9dlj6arf2py6m7mz5"}"#.to_vec()
        );
}

#[test]
fn derivation_strict_deferred_derivation_paths_sort_and_dedupe_references() {
    let ir = lower("null");
    let mut eval = TreeWalk::new(&ir);
    let id = IrId::new(0);
    let span = Span::new(0, 0);
    let output = FloatingCaOutput {
        method: FloatingCaMethod::Recursive,
        hash_algo: nix_compat::nixhash::HashAlgo::Sha256,
    };
    let low_drv = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-low.drv",
    )
    .expect("low drv store path parses");
    let high_drv = nix_compat::store_path::StorePath::<String>::from_bytes(
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-high.drv",
    )
    .expect("high drv store path parses");
    let mut derivation = nix_compat::derivation::Derivation::default();
    derivation
        .outputs
        .insert("out".to_owned(), nix_compat::derivation::Output::default());
    derivation.input_sources.insert(high_drv.clone());
    derivation
        .input_derivations
        .insert(low_drv.clone(), BTreeSet::from(["out".to_owned()]));
    derivation
        .input_derivations
        .insert(high_drv.clone(), BTreeSet::from(["out".to_owned()]));
    let references = BTreeSet::from([low_drv.to_absolute_path(), high_drv.to_absolute_path()]);

    let static_aterm = eval.derivation_aterm_bytes(&derivation);
    let expected =
        nix_compat::store_path::build_text_path("mixed.drv", &static_aterm, references.clone())
            .expect("expected ordinary path builds");
    let actual = eval
        .calculate_derivation_path(id, span, "mixed", &derivation)
        .expect("ordinary path builds");
    assert_eq!(actual, expected);

    let floating_aterm = eval.floating_ca_derivation_aterm_bytes(&derivation, output, None);
    let expected =
        nix_compat::store_path::build_text_path("mixed.drv", &floating_aterm, references.clone())
            .expect("expected floating path builds");
    let actual = eval
        .calculate_derivation_path_from_aterm(id, span, "mixed", &derivation, &floating_aterm)
        .expect("floating path builds");
    assert_eq!(actual, expected);

    let impure_aterm = eval.impure_derivation_aterm_bytes(&derivation, output, None);
    let expected = nix_compat::store_path::build_text_path("mixed.drv", &impure_aterm, references)
        .expect("expected impure path builds");
    let actual = eval
        .calculate_derivation_path_from_aterm(id, span, "mixed", &derivation, &impure_aterm)
        .expect("impure path builds");
    assert_eq!(actual, expected);
}

#[test]
fn derivation_strict_deferred_forms_use_configured_store_dir() {
    let store_dir = unique_temp_dir("derivation-strict-deferred-store");
    let store_root = path_source(&store_dir);
    let store_prefix = format!("{store_root}/");
    let src_path = format!("{store_root}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src");
    let options = TreeWalkOptions::with_store_dir(store_root.as_bytes().to_vec())
        .expect("temporary store root configures");
    let src_path_literal = nix_string_literal(&src_path);
    let source = format!(
        r#"let
                 opaque = builtins.appendContext "src" {{
                   {src_path_literal} = {{ path = true; }};
                 }};
                 floating = derivationStrict {{
                   name = "floating";
                   system = ":";
                   builder = ":";
                   __contentAddressed = true;
                   outputHashAlgo = "sha256";
                   outputHashMode = "recursive";
                   input = opaque;
                 }};
                 impure = derivationStrict {{
                   name = "impure";
                   system = ":";
                   builder = ":";
                   __impure = true;
                   input = opaque;
                 }};
                 downstream = derivationStrict {{
                   name = "user";
                   system = ":";
                   builder = ":";
                   input = floating.out;
                 }};
               in {{
                 downstreamCtx = builtins.getContext downstream.out;
                 downstreamDrv = downstream.drvPath;
                 floatingDrv = floating.drvPath;
                 impureDrv = impure.drvPath;
               }}"#
    );
    let outcome =
        eval_whnf_owned_with_options(&lower(&format!("builtins.toJSON ({source})")), options)
            .expect("custom-store deferred derivations evaluate");
    let json = outcome
        .heap()
        .get_string(outcome.value())
        .expect("result is JSON string")
        .bytes()
        .to_vec();
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("custom-store result JSON parses");
    let floating_drv = value["floatingDrv"]
        .as_str()
        .expect("floating drv path is a string");
    let impure_drv = value["impureDrv"]
        .as_str()
        .expect("impure drv path is a string");
    let downstream_drv = value["downstreamDrv"]
        .as_str()
        .expect("downstream drv path is a string");

    for drv_path in [floating_drv, impure_drv, downstream_drv] {
        assert!(drv_path.starts_with(&store_prefix), "{drv_path}");
        assert!(drv_path.ends_with(".drv"), "{drv_path}");
        assert!(!drv_path.starts_with("/nix/store/"), "{drv_path}");
    }
    assert_eq!(
        value["downstreamCtx"][downstream_drv],
        serde_json::json!({ "outputs": ["out"] })
    );

    let floating_aterm = outcome
        .derivations()
        .iter()
        .find(|derivation| derivation.absolute_path() == floating_drv)
        .and_then(EvalDerivation::aterm_bytes)
        .expect("floating derivation has a materialized ATerm");
    let floating_aterm = std::str::from_utf8(floating_aterm).expect("floating ATerm is UTF-8");
    assert!(floating_aterm.contains(&src_path), "{floating_aterm}");
    assert!(!floating_aterm.contains("/nix/store"), "{floating_aterm}");

    let impure_aterm = outcome
        .derivations()
        .iter()
        .find(|derivation| derivation.absolute_path() == impure_drv)
        .and_then(EvalDerivation::aterm_bytes)
        .expect("impure derivation has a materialized ATerm");
    let impure_aterm = std::str::from_utf8(impure_aterm).expect("impure ATerm is UTF-8");
    assert!(impure_aterm.contains(&src_path), "{impure_aterm}");
    assert!(!impure_aterm.contains("/nix/store"), "{impure_aterm}");

    let downstream_aterm = outcome
        .derivations()
        .iter()
        .find(|derivation| derivation.absolute_path() == downstream_drv)
        .and_then(EvalDerivation::aterm_bytes)
        .expect("downstream derivation has a materialized ATerm");
    let downstream_aterm =
        std::str::from_utf8(downstream_aterm).expect("downstream ATerm is UTF-8");
    assert!(
        downstream_aterm.contains(floating_drv),
        "{downstream_aterm}"
    );
    assert!(
        !downstream_aterm.contains("/nix/store"),
        "{downstream_aterm}"
    );

    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}
