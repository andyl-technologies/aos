//! Tree-walk test support: C++ Nix string/derivation oracle helpers.

use super::super::*;
use super::*;

pub(crate) fn assert_cpp_nix_string_context_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.getContext (builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
            })"#,
        r#"builtins.getContext (builtins.appendContext "x" {
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = {
                    path = true;
                    allOutputs = true;
                    outputs = [ "out" "dev" "" "out" ];
                };
            })"#,
        r#"builtins.hasContext (builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
            })"#,
        r#"builtins.getContext (builtins.appendContext
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                })
                {
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other" = { path = true; };
                    "/nix/store/cccccccccccccccccccccccccccccccc-empty" = {
                        path = false;
                        allOutputs = false;
                        outputs = [];
                    };
                })"#,
        r#"builtins.getContext (builtins.appendContext
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = { outputs = [ "out" ]; };
                })
                {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = {
                        path = true;
                        allOutputs = true;
                        outputs = [ "dev" ];
                    };
                })"#,
        r#"builtins.getContext (builtins.unsafeDiscardStringContext
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                }))"#,
        r#"builtins.getContext (builtins.unsafeDiscardOutputDependency
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = { allOutputs = true; };
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-out.drv" = { outputs = [ "out" ]; };
                    "/nix/store/cccccccccccccccccccccccccccccccc-src" = { path = true; };
                }))"#,
        r#"builtins.getContext (builtins.addDrvOutputDependencies
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = { path = true; };
                }))"#,
        r#"builtins.getContext (builtins.addDrvOutputDependencies
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = { allOutputs = true; };
                }))"#,
        r#"let append = builtins.appendContext "x"; in
               builtins.getContext (append {
                 "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
               })"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        "builtins.appendContext 1 {}",
        r#"builtins.appendContext { outPath = "abc"; } {}"#,
        r#"builtins.appendContext "x" 1"#,
        r#"builtins.appendContext "x" { "not-a-store-path" = { path = true; }; }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = 1;
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = 1; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-." = { path = true; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-.." = { path = true; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { allOutputs = true; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { outputs = [ "out" ]; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = { outputs = [ 1 ]; };
            }"#,
        r#"builtins.appendContext "x" {
                "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-drv.drv" = {
                    outputs = [
                      (builtins.appendContext "out" {
                        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                      })
                    ];
                };
            }"#,
        r#"builtins.addDrvOutputDependencies "x""#,
        r#"builtins.addDrvOutputDependencies
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; };
                })"#,
        r#"builtins.addDrvOutputDependencies
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-drv.drv" = { outputs = [ "out" ]; };
                })"#,
        r#"builtins.addDrvOutputDependencies
                (builtins.appendContext "x" {
                    "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a.drv" = { path = true; };
                    "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b.drv" = { path = true; };
                })"#,
        r#"builtins.unsafeDiscardOutputDependency 1"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }
}

pub(crate) fn assert_cpp_nix_string_coercion_contexts_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                 b = withCtx "b" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
               in builtins.getContext (builtins.toString [ a 1 b ])"#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                 b = withCtx "b" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
               in builtins.getContext "${a}${b}""#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                 b = withCtx "b" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
               in builtins.getContext (a + b)"#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                 b = withCtx "b" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b";
                 sep = withCtx ":" "/nix/store/cccccccccccccccccccccccccccccccc-sep";
               in builtins.getContext (builtins.concatStringsSep sep [ a b ])"#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 a = withCtx "a" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a";
                 sep = withCtx ":" "/nix/store/cccccccccccccccccccccccccccccccc-sep";
               in {
                 single = builtins.getContext (builtins.concatStringsSep sep [ a ]);
                 empty = builtins.getContext (builtins.concatStringsSep sep []);
               }"#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 source = withCtx "x" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
                 used = withCtx "X" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-used";
                 unused = withCtx "Z" "/nix/store/cccccccccccccccccccccccccccccccc-unused";
                 pattern = withCtx "x" "/nix/store/dddddddddddddddddddddddddddddddd-pattern";
               in {
                 used = builtins.getContext
                   (builtins.replaceStrings [ "x" "z" ] [ used unused ] source);
                 unused = builtins.getContext
                   (builtins.replaceStrings [ "y" ] [ used ] source);
                 patternContext = builtins.getContext
                   (builtins.replaceStrings [ pattern ] [ used ] source);
               }"#,
        r#"let
                 withCtx = text: path: builtins.appendContext text {
                   ${path} = { path = true; };
                 };
                 hook = withCtx "hook" "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hook";
                 out = withCtx "out" "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-out";
               in {
                 toStringHook = builtins.getContext
                   (builtins.toString { __toString = self: hook; });
                 toStringOut = builtins.getContext
                   (builtins.toString { outPath = out; });
                 interpolationHook = builtins.getContext
                   "${{ __toString = self: hook; }}";
                 interpolationOut = builtins.getContext
                   "${{ outPath = out; }}";
               }"#,
        r#"let
                 strict = derivationStrict {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
                 drv = {
                   type = "derivation";
                   name = "x";
                   drvPath = strict.drvPath;
                   outPath = strict.out;
                 };
               in builtins.getContext (builtins.toString drv)"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }
}

pub(crate) fn assert_cpp_nix_derivation_wrapper_matches_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    for source in [
        r#"let
                 d = derivation {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in {
                 allLen = builtins.length d.all;
                 allOutputNames = builtins.map (x: x.outputName) d.all;
                 attrNames = builtins.attrNames d;
                 drvAttrs = builtins.attrNames d.drvAttrs;
                 drvPath = d.drvPath;
                 functionArgs = builtins.functionArgs derivation;
                 isFunction = builtins.isFunction builtins.derivation;
                 kind = d.type;
                 outNames = builtins.attrNames d.out;
                 outputName = d.outputName;
                 pathOut = d.outPath;
                 rendered = "${d}";
                 renderedContext = builtins.getContext "${d}";
                 type = builtins.typeOf derivation;
               }"#,
        r#"let
                 d = builtins.derivation {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                   outputs = [ "out" "dev" ];
                 };
               in {
                 allLen = builtins.length d.all;
                 allOutputNames = builtins.map (x: x.outputName) d.all;
                 devNested = d.dev.out.dev.dev.outPath;
                 devOutPath = d.dev.outPath;
                 drvAttrs = builtins.attrNames d.drvAttrs;
                 names = builtins.attrNames d;
                 outNested = d.out.dev.out.outPath;
                 pathOut = d.outPath;
                 outputs = d.outputs;
               }"#,
        r#"let
                 d = derivation {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                   outputs = [ "dev" ];
                 };
               in {
                 allLen = builtins.length d.all;
                 hasDev = builtins.hasAttr "dev" d;
                 hasOut = builtins.hasAttr "out" d;
                 names = builtins.attrNames d;
                 outputName = d.outputName;
                 pathOut = d.outPath;
               }"#,
        r#"let
                 f = builtins.derivation;
                 d = f {
                   name = "x";
                   system = "x86_64-linux";
                   builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 };
               in d.outPath"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, source);
    }

    for source in [
        r#"derivation {
                 name = "x";
                 system = "x86_64-linux";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
                 outputs = "out dev";
               }"#,
        r#"derivation {
                 name = "x";
                 builder = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-builder";
               }.drvPath"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }
}

pub(crate) fn assert_cpp_nix_to_string_builtin_matches_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);

    let (dir, path) = temp_file_with_bytes("cpp-nix-to-string-path", b"abc");
    let path = path_source(&path);

    for source in [
        r#"builtins.toString "x""#.to_owned(),
        "builtins.toString 1".to_owned(),
        "builtins.toString (-2)".to_owned(),
        "builtins.toString 9223372036854775807".to_owned(),
        "builtins.toString (-9223372036854775807 - 1)".to_owned(),
        "builtins.toString 1.0".to_owned(),
        "builtins.toString 1.25".to_owned(),
        "builtins.toString 1.23456789".to_owned(),
        "builtins.toString (-0.0)".to_owned(),
        "builtins.toString 0.00001".to_owned(),
        "builtins.toString 0.0000001".to_owned(),
        "builtins.toString 1000000.0".to_owned(),
        "builtins.toString ((1.0e308 * 1.0e308) - (1.0e308 * 1.0e308))".to_owned(),
        "builtins.toString (1.0e308 * 1.0e308)".to_owned(),
        "builtins.toString (builtins.sub 0.0 (1.0e308 * 1.0e308))".to_owned(),
        "builtins.toString true".to_owned(),
        "builtins.toString false".to_owned(),
        "builtins.toString null".to_owned(),
        format!("builtins.toString {path}"),
        "builtins.toString [ 1 \"x\" true false null ]".to_owned(),
        "builtins.toString [ \"x\" [] \"y\" ]".to_owned(),
        "builtins.toString [ [ \"a\" \"b\" ] [ \"c\" \"\" ] [ \"\" \"d\" ] ]".to_owned(),
        "builtins.toString { __toString = self: 1; outPath = 1 / 0; }".to_owned(),
        r#"builtins.toString { __toString = self: [ "a" "b" ]; }"#.to_owned(),
        r#"builtins.toString { outPath = [ "a" "b" ]; }"#.to_owned(),
        r#"let f = builtins.toString; in f [ "a" "b" ]"#.to_owned(),
    ] {
        assert_cpp_nix_json_matches_tree_walk(oracle, &source);
    }

    for source in [
        "builtins.toString [ \"a\" (1 / 0) ]",
        "builtins.toString (x: x)",
        r#"builtins.toString { __toString = "bad"; outPath = "fallback"; }"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(oracle, source);
    }

    fs::remove_dir_all(dir).expect("temp directory removes");
}

pub(crate) fn assert_cpp_nix_string_path_builtins_match_tree_walk(oracle: &str) {
    assert_pinned_cpp_nix_oracle(oracle);
    for source in [
        r#"builtins.substring 1 3 "abcdef""#,
        r#"builtins.substring 1 2 { outPath = "abcd"; }"#,
        r#"let slice = builtins.substring 1; take2 = slice 2; in take2 "abcd""#,
        r#"builtins.stringLength "a\n""#,
        r#"builtins.stringLength { __toString = self: self.name; name = "custom"; }"#,
        r#"builtins.replaceStrings [ "a" "bc" ] [ "x" "Y" ] "abcabc""#,
        r#"builtins.replaceStrings [ "" ] [ "x" ] "ab""#,
        r#"builtins.replaceStrings [ "a" "ab" ] [ "X" "Y" ] "ababa""#,
        r#"builtins.replaceStrings [ "ab" "a" ] [ "Y" "X" ] "ababa""#,
        r#"let replace = builtins.replaceStrings [ "a" ]; swap = replace [ "b" ]; in swap "a""#,
        r#"builtins.concatStringsSep ":" [ "a" { outPath = "b"; } { __toString = self: "c"; } ]"#,
        r#"let join = builtins.concatStringsSep ","; in join [ "a" "b" ]"#,
        r#"builtins.match "a(.)c" "abc""#,
        r#"builtins.match "a(.)" "abc""#,
        r#"builtins.match "abc" "abc""#,
        r#"builtins.match "a|aa" "aa""#,
        r#"builtins.match "(a|aa)" "aa""#,
        r#"builtins.match "(a)?b" "b""#,
        r#"builtins.match "(a*)" """#,
        r#"builtins.match "a{2,3}" "aaa""#,
        r#"let m = builtins.match "a(.)c"; in m "abc""#,
        r#"builtins.split "-" "a-b-c""#,
        r#"builtins.split "(-)" "a-b-c""#,
        r#"builtins.split "(a)?b" "b-ab""#,
        r#"builtins.split "a*" "baac""#,
        r#"builtins.split "(a*)" "baac""#,
        r#"builtins.split "a?" "bc""#,
        r#"builtins.split "^" "abc""#,
        r#"builtins.split "$" "abc""#,
        r#"builtins.split "^|$" "abc""#,
        r#"builtins.split "^|$" "a""#,
        r#"builtins.split "a*$" "baac""#,
        r#"builtins.length (builtins.split "." "éx")"#,
        r#"builtins.stringLength (builtins.elemAt (builtins.elemAt (builtins.split "(.)" "éx") 1) 0)"#,
        r#"let split = builtins.split "-"; in split "a-b""#,
        r#"builtins.splitVersion "1.0pre2""#,
        r#"builtins.splitVersion "foo-1.2_bar""#,
        r#"builtins.splitVersion "1+2~pre""#,
        r#"builtins.compareVersions "1.0pre2" "1.0pre10""#,
        r#"builtins.compareVersions "1a" "1.0""#,
        r#"builtins.compareVersions "1.0" "1.0.0""#,
        r#"let cmp = builtins.compareVersions "1.2"; in cmp "1.10""#,
        r#"builtins.parseDrvName "foo-1.2""#,
        r#"builtins.parseDrvName "foo--1""#,
        r#"builtins.parseDrvName "foo-.1""#,
        r#"builtins.parseDrvName "foo-_1""#,
        r#"builtins.parseDrvName "foo-A-1""#,
        r#"builtins.parseDrvName "foo-""#,
        r#"builtins.parseDrvName "-1""#,
        r#"builtins.baseNameOf "/a/b/""#,
        r#"builtins.dirOf "/a/b/""#,
        r#"builtins.baseNameOf "a//""#,
        r#"builtins.dirOf "a//""#,
        r#"builtins.baseNameOf "//a""#,
        r#"builtins.dirOf "//a""#,
        r#"builtins.dirOf { __toString = self: "/a/b"; }"#,
        r#"builtins.toPath "/tmp/../var/./tmp//""#,
        r#"let toPath = builtins.toPath; in toPath "/tmp/foo//bar""#,
        r#"builtins.typeOf (builtins.toPath "/tmp")"#,
        r#"builtins.toPath { __toString = self: "/tmp/from-to-string"; }"#,
    ] {
        assert_cpp_nix_json_matches_tree_walk(&oracle, source);
    }

    for source in [
        r#"builtins.match "" """#,
        r#"builtins.match "[" "x""#,
        r#"builtins.match "()" """#,
        r#"builtins.match "(?:a)" "a""#,
        r#"builtins.match "\\d" "1""#,
        r#"builtins.match "a|" "a""#,
        r#"builtins.match "(|a)" "a""#,
        r#"builtins.match "\\x61" "a""#,
        r#"builtins.match "\\n" "n""#,
        r#"builtins.match "a*?" "aaa""#,
        r#"builtins.match "a{1,2}?" "aa""#,
        r#"builtins.split "" "abc""#,
        r#"builtins.split "[" "x""#,
        r#"builtins.split "()" """#,
        r#"builtins.split "(?:a)" "a""#,
        r#"builtins.split "\\d" "1""#,
        r#"builtins.split "a|" "a""#,
        r#"builtins.split "(|a)" "a""#,
        r#"builtins.split "\\x61" "a""#,
        r#"builtins.split "\\n" "n""#,
        r#"builtins.split "a*?" "aaa""#,
        r#"builtins.split "a{1,2}?" "aa""#,
        r#"builtins.parseDrvName (builtins.appendContext "foo-1" { "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-src" = { path = true; }; })"#,
        r#"builtins.toPath "relative/path""#,
        r#"builtins.toPath 1"#,
    ] {
        assert_cpp_nix_and_tree_walk_reject_expression(&oracle, source);
    }
}
