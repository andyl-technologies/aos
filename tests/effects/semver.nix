##! Rust semver 1.0.28 parity for bounded build-time seed selection.
let
  semver = import ../../lib/packages/semver.nix;
  check = requirement: accepted: rejected:
    builtins.all (version:
      if semver.matches requirement version
      then true
      else throw "SemVer '${requirement}' rejected '${version}'.")
    accepted
    && builtins.all (version:
      if !(semver.matches requirement version)
      then true
      else throw "SemVer '${requirement}' accepted '${version}'.")
    rejected;
  invalid = parser: values:
    builtins.all (value:
      !(builtins.tryEval (builtins.deepSeq (parser value) true)).success)
    values;
  repeat = count: value: builtins.concatStringsSep "" (builtins.genList (_: value) count);
  maximum = "18446744073709551615";
  overflow = "18446744073709551616";
  manyComparators = count: builtins.concatStringsSep "," (builtins.genList (_: "=1.2.3") count);
in {
  caret_preserves_leftmost_nonzero_component =
    check "1" ["1.0.0" "1.9.9"] ["0.9.9" "2.0.0"]
    && check "^1.2" ["1.2.0" "1.9.9"] ["1.1.9" "2.0.0"]
    && check "^1.2.3" ["1.2.3" "1.2.4" "1.9.0"] ["1.2.2" "2.0.0"]
    && check "^0" ["0.0.0" "0.9.9"] ["1.0.0"]
    && check "^0.0" ["0.0.0" "0.0.9"] ["0.1.0"]
    && check "^0.1" ["0.1.0" "0.1.9"] ["0.0.9" "0.2.0"]
    && check "^0.1.2" ["0.1.2" "0.1.9"] ["0.1.1" "0.2.0"]
    && check "^0.0.2" ["0.0.2"] ["0.0.1" "0.0.3" "0.1.0"];

  tilde_keeps_selected_minor =
    check "~1" ["1.0.0" "1.9.9"] ["0.9.9" "2.0.0"]
    && check "~1.2" ["1.2.0" "1.2.9"] ["1.1.9" "1.3.0"]
    && check "~1.2.3" ["1.2.3" "1.2.9"] ["1.2.2" "1.3.0"]
    && check "~0.0.2" ["0.0.2" "0.0.9"] ["0.0.1" "0.1.0"];

  partial_comparators_use_rust_semantics =
    check "=1" ["1.0.0" "1.9.9"] ["0.9.9" "2.0.0"]
    && check "=1.2" ["1.2.0" "1.2.9"] ["1.1.9" "1.3.0"]
    && check ">1" ["2.0.0"] ["1.0.0" "1.9.9"]
    && check ">=1" ["1.0.0" "1.9.9" "2.0.0"] ["0.9.9"]
    && check "<1" ["0.9.9"] ["1.0.0" "1.9.9"]
    && check "<=1" ["0.9.9" "1.9.9"] ["2.0.0"]
    && check ">1.2" ["1.3.0" "2.0.0"] ["1.2.0" "1.2.9"]
    && check ">=1.2" ["1.2.0" "1.2.9" "2.0.0"] ["1.1.9"]
    && check "<1.2" ["1.1.9" "0.9.9"] ["1.2.0" "1.2.9"]
    && check "<=1.2" ["1.1.9" "1.2.9"] ["1.3.0"]
    && check " >= 1.2.3 , < 2 " ["1.2.3" "1.9.9"] ["1.2.2" "2.0.0"];

  wildcards_keep_explicit_operators =
    builtins.all (range: check range ["0.0.0" "1.2.3" "9.9.9"] ["1.2.3-alpha"]) ["*" "x" "X" " * "]
    && builtins.all (range: check range ["1.0.0" "1.9.9"] ["0.9.9" "2.0.0" "1.2.3-alpha"]) ["1.*" "1.x" "1.X" "1.*.*" "1.x.X"]
    && builtins.all (range: check range ["1.2.0" "1.2.9"] ["1.1.9" "1.3.0"]) ["1.2.*" "1.2.x" "1.2.X"]
    && check ">1.*" ["2.0.0"] ["1.9.9"]
    && check "<=1.2.*" ["1.2.9" "1.1.9"] ["1.3.0"]
    && check "~1.*" ["1.9.9"] ["2.0.0"]
    && check "^0.*" ["0.9.9"] ["1.0.0"]
    && check "^0.0.*" ["0.0.9"] ["0.1.0"];

  prereleases_require_same_base_opt_in =
    check ">=1.2.3" ["1.2.3" "1.2.4"] ["1.2.3-alpha" "1.2.4-alpha"]
    && check ">=1.2.3-alpha, <2" ["1.2.3-alpha" "1.2.3-beta" "1.2.3" "1.9.9"] ["1.2.4-alpha" "2.0.0"]
    && check "~1.2.3-beta.2" ["1.2.3-beta.2" "1.2.3-beta.10" "1.2.3" "1.2.4"] ["1.2.3-beta.1" "1.2.4-beta.2" "1.3.0"]
    && check "^0.0.2-alpha" ["0.0.2-alpha" "0.0.2-beta" "0.0.2"] ["0.0.3" "0.0.3-alpha"]
    && check ">=1.2.3-9" ["1.2.3-10" "1.2.3-alpha"] ["1.2.3-8"]
    && check ">=1.2.3-alpha" ["1.2.3-alpha.1" "1.2.3-beta"] ["1.2.3-1"]
    && check "<1.2.3-alpha.1" ["1.2.3-alpha" "1.2.2"] ["1.2.3-alpha.2" "1.2.2-alpha"]
    && check "=1.2.3-01a" ["1.2.3-01a"] ["1.2.3-1a"]
    && check ">=1.2.3-${repeat 70 "9"}" ["1.2.3-${repeat 71 "1"}" "1.2.3-a"] ["1.2.3-${repeat 69 "9"}"];

  build_metadata_does_not_affect_matching =
    check "=1.2.3+build.01" ["1.2.3" "1.2.3+other.02"] ["1.2.4"]
    && check "^1.2.3-alpha+build" ["1.2.3-alpha+other" "1.2.3" "1.2.4+build"] ["1.2.4-alpha+build"];

  unsigned_64_bounds_do_not_overflow_nix =
    check "^${maximum}.0.0" ["${maximum}.0.0" "${maximum}.1.0"] ["18446744073709551614.9.9"]
    && check ">${maximum}" [] ["${maximum}.9.9"]
    && check ">=0.${maximum}.0" ["0.${maximum}.0" "1.0.0"] ["0.18446744073709551614.9"]
    && check "=0.0.${maximum}" ["0.0.${maximum}"] ["0.0.18446744073709551614"]
    && (semver.parseVersion "${maximum}.${maximum}.${maximum}").patch == maximum;

  malformed_ranges_and_versions_are_rejected =
    invalid semver.parseVersion [
      ""
      "1"
      "1.2"
      "1.2.3.4"
      "v1.2.3"
      "01.2.3"
      "1.02.3"
      "1.2.03"
      "-1.2.3"
      "1.2.3-"
      "1.2.3+"
      "1.2.3-01"
      "1.2.3-a..b"
      "1.2.3+a..b"
      "1.2.3-a_b"
      "1.2.3+a_b"
      "1.2.3-é"
      " 1.2.3"
      "1.2.3 "
      "${overflow}.0.0"
      "0.${overflow}.0"
      "0.0.${overflow}"
    ]
    && invalid semver.parseRequirement [
      ""
      " "
      "1.2.3,"
      ",1.2.3"
      "1.2.3,,2"
      "1.2.3 2"
      "1 - 2"
      "1 || 2"
      "*,1"
      "1,*"
      "=*"
      "^x"
      "~X"
      "*.*"
      "1.*.2"
      "1.2.*.*"
      "01"
      "1.02"
      "1.2.03"
      "1.2-alpha"
      "1.2+build"
      "1.2.3-01"
      "1.2.3-a..b"
      "1.2.3+a..b"
      "1.2.3-"
      "1.2.3+"
      ">==1"
      ">= >=1"
      "\t1.2.3"
      "1.2.3\n"
      "1.2.3,\r2"
      "1.2.3,\t2"
      "${overflow}"
      "1.${overflow}"
    ];

  limits_distinguish_exact_versions_from_whole_ranges =
    (semver.parseVersion "1.2.3+${repeat 122 "a"}").major
    == "1"
    && invalid semver.parseVersion ["1.2.3+${repeat 123 "a"}"]
    && check "=1.2.3+${repeat 4089 "a"}" ["1.2.3"] ["1.2.4"]
    && check "^1.2.3-${repeat 160 "a"}" ["1.2.3" "1.2.4"] ["1.2.2"]
    && invalid semver.parseRequirement ["=1.2.3+${repeat 4090 "a"}" (manyComparators 33)]
    && check (manyComparators 32) ["1.2.3"] ["1.2.4"];
}
